from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Event, IPEnrichment

router = APIRouter()


def _event_to_dict(ev: Event, enrich: IPEnrichment | None) -> dict:
    return {
        "id": ev.id,
        "event_id": ev.event_id,
        "session_id": ev.session_id,
        "src_ip": ev.src_ip,
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "timestamp": ev.timestamp.isoformat() + "Z" if ev.timestamp else None,
        "username": ev.username,
        "password": ev.password,
        "command_input": ev.command_input,
        "download_url": ev.download_url,
        "severity": ev.severity,
        "attack_type": ev.attack_type,
        "country": enrich.country if enrich else None,
        "country_code": enrich.country_code if enrich else None,
        "city": enrich.city if enrich else None,
        "lat": enrich.latitude if enrich else None,
        "lng": enrich.longitude if enrich else None,
        "isp": enrich.isp if enrich else None,
        "vt_malicious": enrich.vt_malicious if enrich else None,
        "vt_total": enrich.vt_total if enrich else None,
    }


@router.get("")
async def list_events(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: str = Query(""),
    src_ip: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    q = select(Event, IPEnrichment).outerjoin(
        IPEnrichment, IPEnrichment.ip_address == Event.src_ip
    )
    if severity:
        q = q.where(Event.severity == severity)
    if src_ip:
        q = q.where(Event.src_ip == src_ip)

    total = await db.scalar(
        select(func.count(Event.id)).where(
            *(([Event.severity == severity] if severity else []) +
              ([Event.src_ip == src_ip] if src_ip else []))
        )
    )

    q = q.order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    rows = result.fetchall()

    items = [_event_to_dict(ev, enrich) for ev, enrich in rows]
    return {"total": total or 0, "limit": limit, "offset": offset, "items": items}


@router.get("/{event_id}")
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(
        select(Event, IPEnrichment)
        .outerjoin(IPEnrichment, IPEnrichment.ip_address == Event.src_ip)
        .where(Event.id == event_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    ev, enrich = row
    data = _event_to_dict(ev, enrich)
    data["raw_json"] = ev.raw_json
    return data
