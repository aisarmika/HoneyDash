from __future__ import annotations

"""
Enrichment worker: GeoIP via ip-api.com + VirusTotal (optional).

Flow:
  1. src_ip is put on enrichment_queue after an event is persisted.
  2. enrichment_worker dequeues IPs one at a time.
  3. Cache check: if ip_enrichments row exists with status='complete' and
     enriched_at within cache window, skip.
  4. GeoIP lookup (ip-api.com, free, no key needed).
  5. VirusTotal lookup (optional, rate-limited to 15 s/call on free tier).
  6. Broadcast enrichment_update to all WebSocket clients.
"""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Set

import httpx
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..config import settings
from ..database import AsyncSessionLocal
from ..models import IPEnrichment

enrichment_queue: asyncio.Queue = asyncio.Queue()
enrichment_in_flight: Set[str] = set()

_last_vt_call: float = 0.0


async def enqueue(ip: str):
    if ip in enrichment_in_flight:
        return
    enrichment_in_flight.add(ip)
    await enrichment_queue.put(ip)


async def _fetch_geoip(client: httpx.AsyncClient, ip: str) -> dict | None:
    fields = "status,country,countryCode,city,regionName,lat,lon,isp,query"
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            return data
    except Exception as exc:
        print(f"[enrichment] GeoIP error for {ip}: {exc}")
    return None


async def _fetch_virustotal(client: httpx.AsyncClient, ip: str) -> dict | None:
    global _last_vt_call
    if not settings.virustotal_api_key:
        return None

    elapsed = time.monotonic() - _last_vt_call
    if elapsed < settings.vt_rate_limit_seconds:
        await asyncio.sleep(settings.vt_rate_limit_seconds - elapsed)

    for attempt in range(3):
        try:
            _last_vt_call = time.monotonic()
            r = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=15,
            )
            if r.status_code == 429:
                await asyncio.sleep(60)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            print(f"[enrichment] VT error for {ip} (attempt {attempt+1}): {exc}")
            await asyncio.sleep(2 ** attempt)
    return None


def _compute_severity_from_vt(vt_malicious: int | None) -> str | None:
    if vt_malicious is None:
        return None
    if vt_malicious >= 3:
        return "high"
    if vt_malicious >= 1:
        return "medium"
    return None


async def _enrich_ip(ip: str):
    cache_cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.enrichment_cache_hours)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IPEnrichment).where(IPEnrichment.ip_address == ip)
        )
        row = result.scalar_one_or_none()

        if (
            row
            and row.enrichment_status == "complete"
            and row.enriched_at
            and row.enriched_at.replace(tzinfo=timezone.utc) > cache_cutoff
        ):
            return  # cache hit

    geo_data = None
    vt_data = None

    async with httpx.AsyncClient() as client:
        # Add small delay to respect ip-api.com 45 req/min limit
        await asyncio.sleep(1.5)
        geo_data = await _fetch_geoip(client, ip)

        if geo_data:
            async with AsyncSessionLocal() as db:
                stmt = pg_insert(IPEnrichment).values(
                    ip_address=ip,
                    country=geo_data.get("country"),
                    country_code=geo_data.get("countryCode"),
                    city=geo_data.get("city"),
                    region=geo_data.get("regionName"),
                    latitude=geo_data.get("lat"),
                    longitude=geo_data.get("lon"),
                    isp=geo_data.get("isp"),
                    enrichment_status="geoip_done",
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["ip_address"],
                    set_={
                        "country": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "city": geo_data.get("city"),
                        "region": geo_data.get("regionName"),
                        "latitude": geo_data.get("lat"),
                        "longitude": geo_data.get("lon"),
                        "isp": geo_data.get("isp"),
                        "enrichment_status": "geoip_done",
                    },
                )
                await db.execute(stmt)
                await db.commit()

        vt_data = await _fetch_virustotal(client, ip)

    vt_malicious = vt_suspicious = vt_harmless = vt_total = vt_reputation = None
    if vt_data:
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_malicious = stats.get("malicious")
        vt_suspicious = stats.get("suspicious")
        vt_harmless = stats.get("harmless", 0) + stats.get("undetected", 0)
        vt_total = sum(stats.values()) if stats else None
        vt_reputation = vt_data.get("data", {}).get("attributes", {}).get("reputation")

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        stmt = pg_insert(IPEnrichment).values(
            ip_address=ip,
            country=geo_data.get("country") if geo_data else None,
            country_code=geo_data.get("countryCode") if geo_data else None,
            city=geo_data.get("city") if geo_data else None,
            region=geo_data.get("regionName") if geo_data else None,
            latitude=geo_data.get("lat") if geo_data else None,
            longitude=geo_data.get("lon") if geo_data else None,
            isp=geo_data.get("isp") if geo_data else None,
            vt_malicious=vt_malicious,
            vt_suspicious=vt_suspicious,
            vt_harmless=vt_harmless,
            vt_total=vt_total,
            vt_reputation=vt_reputation,
            enrichment_status="complete" if (geo_data or vt_data) else "failed",
            enriched_at=now,
        )
        update_vals = {
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "vt_harmless": vt_harmless,
            "vt_total": vt_total,
            "vt_reputation": vt_reputation,
            "enrichment_status": "complete" if (geo_data or vt_data) else "failed",
            "enriched_at": now,
        }
        if geo_data:
            update_vals.update({
                "country": geo_data.get("country"),
                "country_code": geo_data.get("countryCode"),
                "city": geo_data.get("city"),
                "region": geo_data.get("regionName"),
                "latitude": geo_data.get("lat"),
                "longitude": geo_data.get("lon"),
                "isp": geo_data.get("isp"),
            })
        stmt = stmt.on_conflict_do_update(index_elements=["ip_address"], set_=update_vals)
        await db.execute(stmt)
        await db.commit()

    # Broadcast enrichment update to all WebSocket clients
    from .broadcaster import manager
    payload = {
        "src_ip": ip,
        "country": geo_data.get("country") if geo_data else None,
        "country_code": geo_data.get("countryCode") if geo_data else None,
        "city": geo_data.get("city") if geo_data else None,
        "region": geo_data.get("regionName") if geo_data else None,
        "lat": geo_data.get("lat") if geo_data else None,
        "lng": geo_data.get("lon") if geo_data else None,
        "isp": geo_data.get("isp") if geo_data else None,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total,
        "vt_reputation": vt_reputation,
    }
    await manager.broadcast({"type": "enrichment_update", "data": payload})


async def start_enrichment_worker():
    """Long-running background task that processes IPs from enrichment_queue."""
    print("[enrichment] worker started")
    while True:
        ip = await enrichment_queue.get()
        try:
            await _enrich_ip(ip)
        except Exception as exc:
            print(f"[enrichment] unhandled error for {ip}: {exc}")
        finally:
            enrichment_in_flight.discard(ip)
            enrichment_queue.task_done()
