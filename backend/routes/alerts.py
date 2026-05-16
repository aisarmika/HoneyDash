from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import AlertInvestigation, Event, IPEnrichment

router = APIRouter()

_TABLE_READY = False


class AlertAction(BaseModel):
    action: str = Field(..., pattern="^(reviewed|false_positive|escalated|open|note)$")
    note: str | None = Field(None, max_length=4000)


async def _ensure_investigation_table(db: AsyncSession) -> None:
    """Create the investigation table if the local server was not restarted cleanly."""
    global _TABLE_READY
    if _TABLE_READY:
        return
    def _create(sync_session):
        AlertInvestigation.__table__.create(bind=sync_session.connection(), checkfirst=True)
    await db.run_sync(_create)
    _TABLE_READY = True


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _case_to_dict(case: AlertInvestigation | None) -> dict:
    return {
        "status": case.status if case else "open",
        "note": case.note if case else None,
        "reviewed_at": case.reviewed_at.isoformat() + "Z" if case and case.reviewed_at else None,
        "false_positive_at": case.false_positive_at.isoformat() + "Z" if case and case.false_positive_at else None,
        "escalated_at": case.escalated_at.isoformat() + "Z" if case and case.escalated_at else None,
        "updated_by": case.updated_by if case else None,
    }


def _alert_to_dict(ev: Event, enrich: IPEnrichment | None, case: AlertInvestigation | None) -> dict:
    return {
        "id": ev.id,
        "event_id": ev.event_id,
        "session_id": ev.session_id,
        "src_ip": ev.src_ip,
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "timestamp": ev.timestamp.isoformat() + "Z" if ev.timestamp else None,
        "sensor": ev.sensor,
        "protocol": ev.protocol,
        "username": ev.username,
        "password": ev.password,
        "command_input": ev.command_input,
        "download_url": ev.download_url,
        "severity": ev.severity,
        "attack_type": ev.attack_type,
        "country": enrich.country if enrich else None,
        "country_code": enrich.country_code if enrich else None,
        "city": enrich.city if enrich else None,
        "isp": enrich.isp if enrich else None,
        "investigation": _case_to_dict(case),
    }


def _filters(severity: str, sensor: str, status: str):
    filters = []
    if severity:
        filters.append(Event.severity == severity)
    else:
        filters.append(Event.severity == "high")
    if sensor:
        filters.append(Event.sensor == sensor)
    if status:
        if status == "open":
            filters.append(or_(AlertInvestigation.status.is_(None), AlertInvestigation.status == "open"))
        else:
            filters.append(AlertInvestigation.status == status)
    return filters


@router.get("")
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: str = Query("high"),
    sensor: str = Query(""),
    status: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    await _ensure_investigation_table(db)
    filters = _filters(severity, sensor, status)
    base = (
        select(Event, IPEnrichment, AlertInvestigation)
        .outerjoin(IPEnrichment, IPEnrichment.ip_address == Event.src_ip)
        .outerjoin(AlertInvestigation, AlertInvestigation.event_id == Event.id)
        .where(and_(*filters))
    )
    total_q = (
        select(func.count(Event.id))
        .outerjoin(AlertInvestigation, AlertInvestigation.event_id == Event.id)
        .where(and_(*filters))
    )
    total = await db.scalar(total_q)
    result = await db.execute(base.order_by(Event.timestamp.desc()).limit(limit).offset(offset))
    rows = result.fetchall()
    return {
        "total": total or 0,
        "limit": limit,
        "offset": offset,
        "items": [_alert_to_dict(ev, enrich, case) for ev, enrich, case in rows],
    }


@router.get("/stats")
async def alert_stats(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    await _ensure_investigation_table(db)
    event_filters = [Event.severity == "high"]
    if sensor:
        event_filters.append(Event.sensor == sensor)
    cutoff = _now_utc() - timedelta(hours=24)
    high_24h = await db.scalar(
        select(func.count(Event.id)).where(*event_filters, Event.timestamp >= cutoff)
    )
    open_count = await db.scalar(
        select(func.count(Event.id))
        .outerjoin(AlertInvestigation, AlertInvestigation.event_id == Event.id)
        .where(*event_filters, or_(AlertInvestigation.status.is_(None), AlertInvestigation.status == "open"))
    )
    reviewed = await db.scalar(
        select(func.count(AlertInvestigation.id))
        .join(Event, Event.id == AlertInvestigation.event_id)
        .where(*event_filters, AlertInvestigation.status == "reviewed")
    )
    false_pos = await db.scalar(
        select(func.count(AlertInvestigation.id))
        .join(Event, Event.id == AlertInvestigation.event_id)
        .where(*event_filters, AlertInvestigation.status == "false_positive")
    )
    escalated = await db.scalar(
        select(func.count(AlertInvestigation.id))
        .join(Event, Event.id == AlertInvestigation.event_id)
        .where(*event_filters, AlertInvestigation.status == "escalated")
    )
    return {
        "high_24h": high_24h or 0,
        "open": open_count or 0,
        "reviewed": reviewed or 0,
        "false_positive": false_pos or 0,
        "escalated": escalated or 0,
    }


@router.post("/{event_id}/action")
async def update_alert_action(
    event_id: int,
    body: AlertAction,
    db: AsyncSession = Depends(get_db),
    user: str = Depends(get_current_user),
):
    await _ensure_investigation_table(db)
    event = await db.scalar(select(Event).where(Event.id == event_id))
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    case = await db.scalar(select(AlertInvestigation).where(AlertInvestigation.event_id == event_id))
    if not case:
        case = AlertInvestigation(event_id=event_id)
        db.add(case)

    now = _now_utc()
    if body.action == "reviewed":
        case.status = "reviewed"
        case.reviewed_at = now
    elif body.action == "false_positive":
        case.status = "false_positive"
        case.false_positive_at = now
    elif body.action == "escalated":
        case.status = "escalated"
        case.escalated_at = now
    elif body.action == "open":
        case.status = "open"
    elif body.action == "note":
        case.status = case.status or "open"

    if body.note is not None:
        case.note = body.note.strip() or None

    case.updated_by = user
    await db.commit()
    await db.refresh(case)
    return {"event_id": event_id, "investigation": _case_to_dict(case)}
