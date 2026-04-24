"""
Dionaea multi-protocol honeypot collector.

Polls Dionaea's SQLite database every 10 seconds for new connections,
login attempts, and malware captures.  Normalises them into HoneyDash
Events / Sessions / MalwareSamples and broadcasts via WebSocket.

Dionaea SQLite tables used:
  connections  – every TCP/UDP connection accepted
  logins       – username/password attempts (FTP, MySQL, MSSQL, HTTP Basic)
  downloads    – malware files fetched by attackers
  offers       – URLs offered by attackers for download
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from ..database import AsyncSessionLocal
from ..models import Event, MalwareSample, Session
from .enrichment import enqueue as enrich_enqueue

logger = logging.getLogger(__name__)

# Paths where Dionaea might store its SQLite DB inside the container
DIONAEA_DB_PATHS = [
    "/opt/dionaea/var/lib/dionaea/dionaea.sqlite",   # dinotools/dionaea:latest
    "/var/dionaea/dionaea.sqlite",
    "/var/dionaea/lib/dionaea/dionaea.sqlite",
    "/opt/dionaea/var/dionaea.sqlite",
]

POLL_INTERVAL = 10  # seconds

# Map Dionaea connection_protocol → HoneyDash protocol name
PROTO_MAP: dict[str, str] = {
    "smbd":       "smb",
    "httpd":      "http",
    "mysqld":     "mysql",
    "mssqld":     "mssql",
    "ftpd":       "ftp",
    "telnetd":    "telnet",
    "sipd":       "sip",
    "pptp":       "pptp",
    "memcached":  "memcached",
    "epmapper":   "smb",
    "nfsd":       "nfs",
}

# Map port → protocol (fallback when connection_protocol is blank)
PORT_PROTO: dict[int, str] = {
    21: "ftp",
    23: "telnet",
    80: "http",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    5060: "sip",
    5061: "sip",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
}

# Map protocol → attack type label
ATTACK_TYPE: dict[str, str] = {
    "ssh":           "SSH Connect",
    "ftp":           "FTP Brute Force",
    "telnet":        "Telnet Attack",
    "http":          "HTTP Exploit",
    "https":         "HTTPS Exploit",
    "smb":           "SMB/EternalBlue Exploit",
    "mysql":         "MySQL Brute Force",
    "mssql":         "MSSQL Brute Force",
    "sip":           "SIP Scanning",
    "memcached":     "Memcached Abuse",
    "elasticsearch": "Elasticsearch Probe",
    "pptp":          "PPTP VPN Probe",
}


def _resolve_db() -> str | None:
    for path in DIONAEA_DB_PATHS:
        if os.path.exists(path):
            return path
    return None


def _ts(unix_float: float | None) -> datetime:
    if not unix_float:
        return datetime.utcnow()
    return datetime.fromtimestamp(unix_float, tz=timezone.utc).replace(tzinfo=None)


def _protocol(row_proto: str | None, port: int | None) -> str:
    if row_proto:
        mapped = PROTO_MAP.get(row_proto.lower().strip())
        if mapped:
            return mapped
    if port:
        return PORT_PROTO.get(port, "unknown")
    return "unknown"


def _severity(proto: str, has_login: bool = False) -> str:
    if proto in ("smb", "http", "https"):
        return "high"
    if proto in ("mysql", "mssql", "ftp") and has_login:
        return "medium"
    return "low"


async def _upsert_session(
    src_ip: str,
    session_id: str,
    dst_port: int | None,
    proto: str,
    timestamp: datetime,
    sensor: str,
) -> None:
    attack = ATTACK_TYPE.get(proto, f"{proto.upper()} Probe")
    sev = _severity(proto)
    async with AsyncSessionLocal() as db:
        stmt = pg_insert(Session).values(
            session_id=session_id,
            src_ip=src_ip,
            dst_port=dst_port or 0,
            start_time=timestamp,
            sensor=sensor,
            protocol=proto,
            severity=sev,
            attack_type=attack,
        )
        stmt = stmt.on_conflict_do_nothing(index_elements=["session_id"])
        await db.execute(stmt)
        await db.commit()


async def _insert_event(
    conn_id: int,
    src_ip: str,
    src_port: int | None,
    dst_port: int | None,
    proto: str,
    timestamp: datetime,
    sensor: str,
    username: str | None = None,
    password: str | None = None,
    download_url: str | None = None,
    raw: dict | None = None,
) -> int | None:
    """Insert one Dionaea event into the events table. Returns the new event DB id."""
    session_id = f"dionaea-{conn_id}"
    attack = ATTACK_TYPE.get(proto, f"{proto.upper()} Probe")
    sev = _severity(proto, has_login=bool(username))
    raw_json = json.dumps(raw or {})

    # Map event_id string to something meaningful
    if username:
        eid = f"dionaea.login.{proto}"
    elif download_url:
        eid = "dionaea.download.offer"
    else:
        eid = f"dionaea.connection.{proto}.accept"

    async with AsyncSessionLocal() as db:
        # Make sure session exists first
        await _upsert_session(src_ip, session_id, dst_port, proto, timestamp, sensor)

        # Update session login counter if login event
        if username:
            result = await db.execute(select(Session).where(Session.session_id == session_id))
            sess = result.scalar_one_or_none()
            if sess:
                sess.login_attempts = (sess.login_attempts or 0) + 1
                await db.flush()

        event = Event(
            event_id=eid,
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            timestamp=timestamp,
            sensor=sensor,
            protocol=proto,
            username=username,
            password=password,
            download_url=download_url,
            raw_json=raw_json,
            severity=sev,
            attack_type=attack,
        )
        db.add(event)
        try:
            await db.commit()
            await db.refresh(event)
            return event.id
        except IntegrityError:
            await db.rollback()
            return None


async def _broadcast_event(
    event_db_id: int,
    conn_id: int,
    src_ip: str,
    dst_port: int | None,
    proto: str,
    timestamp: datetime,
    sensor: str,
    username: str | None = None,
    download_url: str | None = None,
    sev: str = "low",
    attack: str = "",
) -> None:
    from .broadcaster import manager
    from ..models import IPEnrichment

    # Quick enrichment cache lookup
    enrich: dict | None = None
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(IPEnrichment).where(IPEnrichment.ip_address == src_ip))
        row = result.scalar_one_or_none()
        if row:
            enrich = {
                "country": row.country, "country_code": row.country_code,
                "city": row.city, "lat": row.latitude, "lng": row.longitude,
            }

    await manager.broadcast({
        "type": "new_event",
        "data": {
            "id": event_db_id,
            "event_id": f"dionaea.connection.{proto}.accept",
            "session_id": f"dionaea-{conn_id}",
            "src_ip": src_ip,
            "dst_port": dst_port,
            "timestamp": timestamp.isoformat() + "Z",
            "username": username,
            "download_url": download_url,
            "severity": sev,
            "attack_type": attack,
            "protocol": proto,
            "sensor": sensor,
            "country": enrich.get("country") if enrich else None,
            "country_code": enrich.get("country_code") if enrich else None,
            "city": enrich.get("city") if enrich else None,
            "lat": enrich.get("lat") if enrich else None,
            "lng": enrich.get("lng") if enrich else None,
        },
    })


async def _upsert_malware(
    sha256: str,
    md5: str | None,
    sha512: str | None,
    file_size: int | None,
    src_ip: str | None,
    download_url: str | None,
    proto: str,
    sensor: str,
    timestamp: datetime,
) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(MalwareSample).where(MalwareSample.sha256 == sha256)
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.download_count = (existing.download_count or 1) + 1
            existing.last_seen = timestamp
            await db.commit()
        else:
            sample = MalwareSample(
                sha256=sha256,
                md5=md5,
                sha512=sha512,
                file_size=file_size,
                first_seen=timestamp,
                last_seen=timestamp,
                src_ip=src_ip,
                download_url=download_url,
                protocol=proto,
                sensor=sensor,
            )
            db.add(sample)
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()

    # Broadcast malware alert
    from .broadcaster import manager
    await manager.broadcast({
        "type": "new_malware",
        "data": {
            "sha256": sha256,
            "md5": md5,
            "src_ip": src_ip,
            "download_url": download_url,
            "protocol": proto,
            "sensor": sensor,
            "timestamp": timestamp.isoformat() + "Z",
        },
    })


async def start_dionaea_collector() -> None:
    """
    Background task: polls Dionaea's SQLite every POLL_INTERVAL seconds.
    Tracks the highest processed connection/download IDs so we never
    re-process old rows on restart.
    """
    logger.info("[dionaea] collector starting …")
    sensor = "dionaea-01"
    last_conn_id = 0
    last_dl_id = 0

    while True:
        db_path = _resolve_db()
        if not db_path:
            logger.debug("[dionaea] SQLite not found yet, waiting …")
            await asyncio.sleep(30)
            continue

        try:
            import aiosqlite  # noqa: PLC0415

            async with aiosqlite.connect(db_path) as db:
                db.row_factory = aiosqlite.Row
                # Enable WAL so Dionaea writes don't block our reads
                await db.execute("PRAGMA journal_mode=WAL")

                # ── Process new connections ───────────────────────────────────
                # logins FK is `connection` (not login_connection)
                async with db.execute(
                    """
                    SELECT c.connection, c.connection_transport,
                           c.connection_protocol, c.connection_timestamp,
                           c.local_port, c.remote_host, c.remote_port,
                           l.login_username, l.login_password
                    FROM connections c
                    LEFT JOIN logins l ON l.connection = c.connection
                    WHERE c.connection > ?
                    ORDER BY c.connection
                    """,
                    (last_conn_id,),
                ) as cur:
                    conn_rows = await cur.fetchall()

                seen_conn_ids: set[int] = set()
                for row in conn_rows:
                    cid = row["connection"]
                    if cid in seen_conn_ids:
                        continue
                    seen_conn_ids.add(cid)
                    last_conn_id = max(last_conn_id, cid)

                    src_ip = row["remote_host"] or ""
                    src_port = row["remote_port"]
                    dst_port = row["local_port"]
                    ts = _ts(row["connection_timestamp"])
                    raw_proto = row["connection_protocol"]
                    proto = _protocol(raw_proto, dst_port)
                    username = row["login_username"]
                    password = row["login_password"]
                    sev = _severity(proto, has_login=bool(username))
                    attack = ATTACK_TYPE.get(proto, f"{proto.upper()} Probe")

                    event_id = await _insert_event(
                        conn_id=cid,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        timestamp=ts,
                        sensor=sensor,
                        username=username,
                        password=password,
                        raw={
                            "connection_id": cid,
                            "protocol": raw_proto,
                            "transport": row["connection_transport"],
                        },
                    )

                    if event_id:
                        await _broadcast_event(
                            event_db_id=event_id,
                            conn_id=cid,
                            src_ip=src_ip,
                            dst_port=dst_port,
                            proto=proto,
                            timestamp=ts,
                            sensor=sensor,
                            username=username,
                            sev=sev,
                            attack=attack,
                        )
                        if src_ip:
                            await enrich_enqueue(src_ip)

                # ── Process new malware downloads ─────────────────────────────
                # Downloads schema: download(PK), connection(FK), download_url,
                #                   download_md5_hash  (no sha512 / size columns)
                async with db.execute(
                    """
                    SELECT d.download, d.connection,
                           d.download_url, d.download_md5_hash,
                           c.connection_timestamp, c.remote_host,
                           c.local_port, c.connection_protocol
                    FROM downloads d
                    JOIN connections c ON c.connection = d.connection
                    WHERE d.download > ?
                    ORDER BY d.download
                    """,
                    (last_dl_id,),
                ) as cur:
                    dl_rows = await cur.fetchall()

                for row in dl_rows:
                    last_dl_id = max(last_dl_id, row["download"])
                    md5 = row["download_md5_hash"] or ""
                    if not md5:
                        continue

                    ts = _ts(row["connection_timestamp"])
                    dst_port = row["local_port"]
                    proto = _protocol(row["connection_protocol"], dst_port)
                    # Use md5 as the sha256 stand-in (Dionaea only stores MD5)
                    pseudo_sha256 = f"md5:{md5}"

                    await _upsert_malware(
                        sha256=pseudo_sha256[:64],
                        md5=md5,
                        sha512=None,
                        file_size=None,
                        src_ip=row["remote_host"],
                        download_url=row["download_url"],
                        proto=proto,
                        sensor=sensor,
                        timestamp=ts,
                    )
                    logger.info(
                        "[dionaea] malware captured: md5=%s from %s via %s",
                        md5,
                        row["remote_host"],
                        proto,
                    )

        except ImportError:
            logger.warning("[dionaea] aiosqlite not installed — Dionaea collector disabled")
            return
        except Exception as exc:
            logger.error("[dionaea] collector error: %s", exc)

        await asyncio.sleep(POLL_INTERVAL)
