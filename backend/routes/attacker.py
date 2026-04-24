"""Attacker profile: full per-IP aggregation — sessions, events, enrichment, stats."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Event, IPEnrichment, Session

router = APIRouter()


@router.get("/{ip}")
async def get_attacker_profile(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    # ── Enrichment ──────────────────────────────────────────────────────────
    enrich_result = await db.execute(
        select(IPEnrichment).where(IPEnrichment.ip_address == ip)
    )
    enrich = enrich_result.scalar_one_or_none()

    # ── Sessions ────────────────────────────────────────────────────────────
    sessions_result = await db.execute(
        select(Session)
        .where(Session.src_ip == ip)
        .order_by(Session.start_time.desc())
        .limit(50)
    )
    sessions = sessions_result.scalars().all()

    # ── Recent events ────────────────────────────────────────────────────────
    events_result = await db.execute(
        select(Event)
        .where(Event.src_ip == ip)
        .order_by(Event.timestamp.desc())
        .limit(100)
    )
    events = events_result.scalars().all()

    # ── Aggregate stats ──────────────────────────────────────────────────────
    total_sessions = len(sessions)
    total_events   = await db.scalar(
        select(func.count(Event.id)).where(Event.src_ip == ip)
    ) or 0
    first_seen_row = await db.execute(
        select(func.min(Session.start_time)).where(Session.src_ip == ip)
    )
    first_seen = first_seen_row.scalar_one_or_none()
    last_seen_row = await db.execute(
        select(func.max(Session.start_time)).where(Session.src_ip == ip)
    )
    last_seen = last_seen_row.scalar_one_or_none()

    # Attack type distribution
    atk_result = await db.execute(
        select(Session.attack_type, func.count(Session.id).label("cnt"))
        .where(Session.src_ip == ip)
        .group_by(Session.attack_type)
        .order_by(func.count(Session.id).desc())
    )
    attack_dist = [{"attack_type": r.attack_type or "Unknown", "count": r.cnt}
                   for r in atk_result.fetchall()]

    # Max severity
    max_sev = "low"
    for s in sessions:
        if s.severity == "high":
            max_sev = "high"
            break
        if s.severity == "medium":
            max_sev = "medium"

    # Credentials tried
    creds_result = await db.execute(
        select(Event.username, Event.password)
        .where(Event.src_ip == ip, Event.username.isnot(None))
        .distinct()
        .limit(20)
    )
    credentials = [{"username": r.username, "password": r.password} for r in creds_result.fetchall()]

    # Commands run
    cmds_result = await db.execute(
        select(Event.command_input, Event.timestamp)
        .where(Event.src_ip == ip, Event.command_input.isnot(None))
        .order_by(Event.timestamp.desc())
        .limit(30)
    )
    commands = [{"command": r.command_input,
                 "timestamp": r.timestamp.isoformat() + "Z" if r.timestamp else None}
                for r in cmds_result.fetchall()]

    # Downloads
    dl_result = await db.execute(
        select(Event.download_url, Event.timestamp)
        .where(Event.src_ip == ip, Event.download_url.isnot(None))
        .order_by(Event.timestamp.desc())
        .limit(20)
    )
    downloads = [{"url": r.download_url,
                  "timestamp": r.timestamp.isoformat() + "Z" if r.timestamp else None}
                 for r in dl_result.fetchall()]

    return {
        "ip": ip,
        "enrichment": {
            "country": enrich.country if enrich else None,
            "country_code": enrich.country_code if enrich else None,
            "city": enrich.city if enrich else None,
            "region": enrich.region if enrich else None,
            "isp": enrich.isp if enrich else None,
            "latitude": enrich.latitude if enrich else None,
            "longitude": enrich.longitude if enrich else None,
            "vt_malicious": enrich.vt_malicious if enrich else None,
            "vt_suspicious": enrich.vt_suspicious if enrich else None,
            "vt_total": enrich.vt_total if enrich else None,
            "vt_reputation": enrich.vt_reputation if enrich else None,
            "enrichment_status": enrich.enrichment_status if enrich else "pending",
        },
        "stats": {
            "total_sessions": total_sessions,
            "total_events": total_events,
            "first_seen": first_seen.isoformat() + "Z" if first_seen else None,
            "last_seen": last_seen.isoformat() + "Z" if last_seen else None,
            "max_severity": max_sev,
            "login_successes": sum(1 for s in sessions if s.login_success),
            "total_commands": sum(s.commands_run or 0 for s in sessions),
            "total_downloads": sum(s.files_downloaded or 0 for s in sessions),
        },
        "attack_distribution": attack_dist,
        "sessions": [
            {
                "session_id": s.session_id,
                "start_time": s.start_time.isoformat() + "Z" if s.start_time else None,
                "duration_secs": s.duration_secs,
                "attack_type": s.attack_type,
                "severity": s.severity,
                "login_attempts": s.login_attempts,
                "login_success": s.login_success,
                "commands_run": s.commands_run,
                "files_downloaded": s.files_downloaded,
            }
            for s in sessions
        ],
        "credentials": credentials,
        "commands": commands,
        "downloads": downloads,
    }
