from __future__ import annotations

"""
Log collector: tails the Cowrie JSON log file and persists events to the DB.

Startup behaviour:
  - If LOG_CATCHUP_ON_START=true: process entire existing file from the start.
  - Otherwise: seek to end of file (only new events from now on).

Rotation handling:
  - If the file shrinks (rotated), re-open from the beginning of the new file.
"""

import asyncio
import json
import os
import re
from datetime import datetime, timezone

import aiofiles
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from ..config import settings
from ..database import AsyncSessionLocal
from ..models import Event, Session
from .enrichment import enqueue as enrich_enqueue

DANGEROUS_CMDS = re.compile(
    r"\b(wget|curl|chmod|bash|/bin/sh|python|python3|nc|netcat|base64|perl|ruby|php)\b",
    re.IGNORECASE,
)

ATTACK_TYPE_PRIORITY = {
    "Malware Download": 5,
    "Command Execution": 4,
    "SSH Login": 3,
    "SSH Brute Force": 2,
    "SSH Connect": 1,
}

EVENTID_TO_ATTACK_TYPE = {
    "cowrie.session.connect": "SSH Connect",
    "cowrie.login.failed": "SSH Brute Force",
    "cowrie.login.success": "SSH Login",
    "cowrie.command.input": "Command Execution",
    "cowrie.session.file_download": "Malware Download",
    "cowrie.session.closed": None,
}


def _compute_event_severity(data: dict) -> str:
    eid = data.get("eventid", "")
    if eid == "cowrie.login.success":
        return "high"
    if eid == "cowrie.session.file_download":
        return "high"
    if eid == "cowrie.command.input":
        cmd = data.get("input", "")
        if DANGEROUS_CMDS.search(cmd):
            return "high"
        return "medium"
    if eid == "cowrie.login.failed":
        return "low"
    return "low"


def _upgrade_severity(current: str, new: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return new if order.get(new, 0) > order.get(current, 0) else current


def _upgrade_attack_type(current: str | None, new_type: str | None) -> str | None:
    if new_type is None:
        return current
    if current is None:
        return new_type
    if ATTACK_TYPE_PRIORITY.get(new_type, 0) > ATTACK_TYPE_PRIORITY.get(current, 0):
        return new_type
    return current


async def _parse_timestamp(ts_str: str) -> datetime:
    try:
        # Cowrie format: "2024-01-15T10:30:00.000000Z"
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)  # store as naive UTC
    except Exception:
        return datetime.utcnow()


async def process_line(line: str):
    if not line:
        return
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return

    eid = data.get("eventid", "")
    if eid not in EVENTID_TO_ATTACK_TYPE:
        return

    src_ip = data.get("src_ip", "")
    session_id = data.get("session", "")
    timestamp = await _parse_timestamp(data.get("timestamp", ""))
    sensor = data.get("sensor", "")
    attack_type = EVENTID_TO_ATTACK_TYPE[eid]
    severity = _compute_event_severity(data)

    async with AsyncSessionLocal() as db:
        # Upsert session row (create if missing)
        session_stmt = pg_insert(Session).values(
            session_id=session_id,
            src_ip=src_ip,
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port", 22),
            start_time=timestamp,
            sensor=sensor,
            severity=severity,
            attack_type=attack_type,
        )
        session_stmt = session_stmt.on_conflict_do_nothing(index_elements=["session_id"])
        await db.execute(session_stmt)

        # Update session counters and upgrade severity/attack_type
        from sqlalchemy import select
        result = await db.execute(
            select(Session).where(Session.session_id == session_id)
        )
        sess = result.scalar_one_or_none()
        if sess:
            new_severity = _upgrade_severity(sess.severity, severity)
            new_attack_type = _upgrade_attack_type(sess.attack_type, attack_type)

            if eid == "cowrie.login.failed":
                sess.login_attempts = (sess.login_attempts or 0) + 1
                if sess.login_attempts >= 5:
                    new_severity = _upgrade_severity(new_severity, "medium")
            elif eid == "cowrie.login.success":
                sess.login_success = True
                new_severity = "high"
            elif eid == "cowrie.command.input":
                sess.commands_run = (sess.commands_run or 0) + 1
            elif eid == "cowrie.session.file_download":
                sess.files_downloaded = (sess.files_downloaded or 0) + 1
                new_severity = "high"
            elif eid == "cowrie.session.closed":
                sess.end_time = timestamp
                sess.duration_secs = data.get("duration")

            sess.severity = new_severity
            sess.attack_type = new_attack_type
            await db.flush()

        # Insert event (skip on duplicate)
        if eid != "cowrie.session.closed":
            event = Event(
                event_id=eid,
                session_id=session_id,
                src_ip=src_ip,
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port", 22),
                timestamp=timestamp,
                sensor=sensor,
                username=data.get("username"),
                password=data.get("password"),
                command_input=data.get("input"),
                download_url=data.get("url"),
                download_path=data.get("outfile"),
                duration=data.get("duration"),
                raw_json=line,
                severity=severity,
                attack_type=attack_type,
            )
            db.add(event)
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                return
        else:
            await db.commit()
            return

        # Refresh to get the auto-assigned id
        await db.refresh(event)
        event_id_db = event.id

    # Broadcast new event to WebSocket clients
    from .broadcaster import manager
    enrichment = await _get_enrichment_data(src_ip)
    await manager.broadcast({
        "type": "new_event",
        "data": {
            "id": event_id_db,
            "event_id": eid,
            "session_id": session_id,
            "src_ip": src_ip,
            "dst_port": data.get("dst_port", 22),
            "timestamp": timestamp.isoformat() + "Z",
            "username": data.get("username"),
            "password": data.get("password"),
            "command_input": data.get("input"),
            "severity": severity,
            "attack_type": attack_type,
            "country": enrichment.get("country") if enrichment else None,
            "country_code": enrichment.get("country_code") if enrichment else None,
            "city": enrichment.get("city") if enrichment else None,
            "lat": enrichment.get("latitude") if enrichment else None,
            "lng": enrichment.get("longitude") if enrichment else None,
            "vt_malicious": enrichment.get("vt_malicious") if enrichment else None,
        },
    })

    # Queue enrichment (deduped)
    await enrich_enqueue(src_ip)


async def _get_enrichment_data(ip: str) -> dict | None:
    from sqlalchemy import select
    from ..models import IPEnrichment
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IPEnrichment).where(IPEnrichment.ip_address == ip)
        )
        row = result.scalar_one_or_none()
        if row:
            return {
                "country": row.country,
                "country_code": row.country_code,
                "city": row.city,
                "latitude": row.latitude,
                "longitude": row.longitude,
                "vt_malicious": row.vt_malicious,
            }
    return None


async def start_log_collector():
    """Tail the Cowrie JSON log file and process new lines indefinitely."""
    path = settings.cowrie_log_path
    print(f"[collector] watching {path}")

    # Wait for file to exist
    while not os.path.exists(path):
        print(f"[collector] waiting for {path} to appear...")
        await asyncio.sleep(5)

    last_size = os.path.getsize(path)

    async with aiofiles.open(path, mode="r", encoding="utf-8", errors="replace") as f:
        if not settings.log_catchup_on_start:
            await f.seek(0, 2)  # seek to end — only process new events
        else:
            print("[collector] catchup mode: processing existing log from start")

        while True:
            line = await f.readline()
            if line:
                await process_line(line.strip())
            else:
                await asyncio.sleep(0.5)
                # Detect log rotation: file shrunk
                try:
                    current_size = os.path.getsize(path)
                    if current_size < last_size:
                        print("[collector] log rotation detected, re-opening from start")
                        await f.seek(0)
                    last_size = current_size
                except OSError:
                    # File was deleted — wait and re-open
                    await asyncio.sleep(2)
                    while not os.path.exists(path):
                        await asyncio.sleep(2)
                    await f.seek(0)
                    last_size = 0
