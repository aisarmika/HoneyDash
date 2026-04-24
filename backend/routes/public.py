"""
Public Viewer endpoints — HD_UC_02

No authentication required. All data is anonymised:
  - No source IPs, usernames, passwords, or command payloads
  - Country-level geo data only
  - Aggregate counts only for sensitive fields
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Event, IPEnrichment, Session

router = APIRouter()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.get("/stats")
async def public_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate stats — no IPs, no sensitive fields."""
    cutoff = _now_utc() - timedelta(hours=24)

    total = await db.scalar(
        select(func.count(Event.id)).where(Event.timestamp >= cutoff)
    )
    unique_sources = await db.scalar(
        select(func.count(func.distinct(Event.src_ip))).where(Event.timestamp >= cutoff)
    )
    high_sev = await db.scalar(
        select(func.count(Event.id)).where(
            Event.timestamp >= cutoff, Event.severity == "high"
        )
    )
    total_sessions = await db.scalar(select(func.count(Session.id)))
    countries = await db.scalar(
        select(func.count(func.distinct(IPEnrichment.country))).where(
            IPEnrichment.country.isnot(None)
        )
    )
    anomalies = await db.scalar(
        select(func.count(Session.id)).where(Session.is_anomaly == True)  # noqa: E712
    )

    return {
        "total_attacks_24h": total or 0,
        "unique_sources_24h": unique_sources or 0,
        "high_severity_24h": high_sev or 0,
        "total_sessions": total_sessions or 0,
        "countries_seen": countries or 0,
        "ml_anomalies": anomalies or 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/timeline")
async def public_timeline(
    range: str = Query("7d", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
):
    now = _now_utc()

    if range == "24h":
        cutoff = now - timedelta(hours=24)
        result = await db.execute(
            text(
                """
                SELECT EXTRACT(HOUR FROM timestamp)::int AS hr, COUNT(*) AS cnt
                FROM events
                WHERE timestamp >= :cutoff
                GROUP BY hr ORDER BY hr
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        slots = {f"{h:02d}:00": 0 for h in range(0, 24, 2)}
        for row in rows:
            bucket = f"{(row.hr // 2) * 2:02d}:00"
            slots[bucket] = slots.get(bucket, 0) + row.cnt
        labels, data = list(slots.keys()), list(slots.values())

    elif range == "7d":
        cutoff = now - timedelta(days=7)
        result = await db.execute(
            text(
                """
                SELECT TO_CHAR(DATE(timestamp), 'Dy') AS day_name,
                       DATE(timestamp) AS day_date, COUNT(*) AS cnt
                FROM events WHERE timestamp >= :cutoff
                GROUP BY day_date, day_name ORDER BY day_date
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        day_order = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        slots = {d: 0 for d in day_order}
        for row in rows:
            key = row.day_name[:3]
            if key in slots:
                slots[key] += row.cnt
        labels, data = list(slots.keys()), list(slots.values())

    else:  # 30d
        cutoff = now - timedelta(days=30)
        result = await db.execute(
            text(
                """
                SELECT FLOOR(EXTRACT(EPOCH FROM (timestamp - :cutoff)) / 604800)::int AS week_num,
                       COUNT(*) AS cnt
                FROM events WHERE timestamp >= :cutoff
                GROUP BY week_num ORDER BY week_num
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        slots = {"Week 1": 0, "Week 2": 0, "Week 3": 0, "Week 4": 0}
        for row in rows:
            week = min(int(row.week_num) + 1, 4)
            slots[f"Week {week}"] += row.cnt
        labels, data = list(slots.keys()), list(slots.values())

    return {"range": range, "labels": labels, "data": data}


@router.get("/attack-types")
async def public_attack_types(db: AsyncSession = Depends(get_db)):
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        select(Event.attack_type, func.count(Event.id).label("cnt"))
        .where(Event.timestamp >= cutoff, Event.attack_type.isnot(None))
        .group_by(Event.attack_type)
        .order_by(func.count(Event.id).desc())
        .limit(5)
    )
    rows = result.fetchall()
    return {"labels": [r.attack_type for r in rows], "data": [r.cnt for r in rows]}


@router.get("/map")
async def public_map(db: AsyncSession = Depends(get_db)):
    """Country-level markers only — no IPs."""
    result = await db.execute(
        select(
            IPEnrichment.country,
            IPEnrichment.country_code,
            IPEnrichment.latitude,
            IPEnrichment.longitude,
            func.count(Session.id).label("cnt"),
        )
        .join(Session, Session.src_ip == IPEnrichment.ip_address)
        .where(
            IPEnrichment.latitude.isnot(None),
            IPEnrichment.longitude.isnot(None),
        )
        .group_by(
            IPEnrichment.country,
            IPEnrichment.country_code,
            IPEnrichment.latitude,
            IPEnrichment.longitude,
        )
        .order_by(func.count(Session.id).desc())
        .limit(100)
    )
    rows = result.fetchall()
    return {
        "markers": [
            {
                "country": r.country,
                "country_code": r.country_code,
                "lat": r.latitude,
                "lng": r.longitude,
                "count": r.cnt,
            }
            for r in rows
        ]
    }


@router.get("/hourly")
async def public_hourly(db: AsyncSession = Depends(get_db)):
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        text(
            """
            SELECT EXTRACT(HOUR FROM timestamp)::int AS hr, COUNT(*) AS cnt
            FROM events WHERE timestamp >= :cutoff
            GROUP BY hr ORDER BY hr
            """
        ),
        {"cutoff": cutoff},
    )
    rows = result.fetchall()
    buckets = [0] * 24
    for row in rows:
        buckets[row.hr] = row.cnt
    return {"data": buckets}


@router.get("/recent-activity")
async def public_recent_activity(db: AsyncSession = Depends(get_db)):
    """
    Most recent 20 events — anonymised.
    Returns: timestamp, attack_type, severity, country, city.
    IPs, usernames, passwords, and command payloads are NEVER returned.
    """
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        select(
            Event.timestamp,
            Event.attack_type,
            Event.severity,
            Event.dst_port,
            IPEnrichment.country,
            IPEnrichment.city,
            IPEnrichment.country_code,
        )
        .outerjoin(IPEnrichment, IPEnrichment.ip_address == Event.src_ip)
        .where(Event.timestamp >= cutoff)
        .order_by(Event.timestamp.desc())
        .limit(20)
    )
    rows = result.fetchall()
    return {
        "items": [
            {
                "timestamp": r.timestamp.isoformat() + "Z" if r.timestamp else None,
                "attack_type": r.attack_type or "Unknown",
                "severity": r.severity or "low",
                "dst_port": r.dst_port,
                "country": r.country or "Unknown",
                "city": r.city,
                "country_code": r.country_code or "",
            }
            for r in rows
        ]
    }
