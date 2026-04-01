from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..auth import get_current_user
from ..database import get_db
from ..models import Event, IPEnrichment, Session

router = APIRouter()


def _duration_display(secs: float | None) -> str:
    if secs is None:
        return "-"
    mins = int(secs // 60)
    s = int(secs % 60)
    if mins > 0:
        return f"{mins} min {s} sec"
    return f"{s} sec"


def _session_to_dict(sess: Session, enrich: IPEnrichment | None) -> dict:
    return {
        "id": sess.id,
        "session_id": sess.session_id,
        "src_ip": sess.src_ip,
        "src_port": sess.src_port,
        "dst_port": sess.dst_port,
        "start_time": sess.start_time.isoformat() + "Z" if sess.start_time else None,
        "end_time": sess.end_time.isoformat() + "Z" if sess.end_time else None,
        "duration_secs": sess.duration_secs,
        "duration_display": _duration_display(sess.duration_secs),
        "login_attempts": sess.login_attempts,
        "login_success": sess.login_success,
        "commands_run": sess.commands_run,
        "files_downloaded": sess.files_downloaded,
        "severity": sess.severity,
        "attack_type": sess.attack_type,
        "sensor": sess.sensor,
        "country": enrich.country if enrich else None,
        "country_code": enrich.country_code if enrich else None,
        "city": enrich.city if enrich else None,
        "region": enrich.region if enrich else None,
        "lat": enrich.latitude if enrich else None,
        "lng": enrich.longitude if enrich else None,
        "isp": enrich.isp if enrich else None,
        "vt_malicious": enrich.vt_malicious if enrich else None,
        "vt_total": enrich.vt_total if enrich else None,
        "vt_reputation": enrich.vt_reputation if enrich else None,
        "enrichment_status": enrich.enrichment_status if enrich else "pending",
    }


@router.get("")
async def list_sessions(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: str = Query(""),
    attack_type: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    q = select(Session, IPEnrichment).outerjoin(
        IPEnrichment, IPEnrichment.ip_address == Session.src_ip
    )
    filters = []
    if severity:
        filters.append(Session.severity == severity)
    if attack_type:
        filters.append(Session.attack_type == attack_type)
    if filters:
        q = q.where(*filters)

    total = await db.scalar(
        select(func.count(Session.id)).where(*filters) if filters
        else select(func.count(Session.id))
    )

    q = q.order_by(Session.start_time.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    rows = result.fetchall()

    items = [_session_to_dict(sess, enrich) for sess, enrich in rows]
    return {"total": total or 0, "limit": limit, "offset": offset, "items": items}


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(
        select(Session, IPEnrichment)
        .outerjoin(IPEnrichment, IPEnrichment.ip_address == Session.src_ip)
        .where(Session.session_id == session_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    sess, enrich = row

    events_result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.timestamp)
    )
    events = events_result.scalars().all()

    event_list = [
        {
            "id": ev.id,
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.isoformat() + "Z" if ev.timestamp else None,
            "username": ev.username,
            "password": ev.password,
            "command_input": ev.command_input,
            "download_url": ev.download_url,
            "severity": ev.severity,
            "attack_type": ev.attack_type,
        }
        for ev in events
    ]

    return {
        "session": _session_to_dict(sess, enrich),
        "events": event_list,
    }
