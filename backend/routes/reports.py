"""HD_UC_10 — Reports: aggregated analytics endpoints + CSV export."""
import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Event, IPEnrichment, Session

router = APIRouter()


def _since(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)


def _all_days(since: datetime, days: int) -> list[str]:
    """Return every calendar date from `since` up to today as 'YYYY-MM-DD' strings."""
    result = []
    for i in range(days):
        d = since.date() + timedelta(days=i)
        result.append(str(d))
    result.append(str(datetime.utcnow().date()))
    return sorted(set(result))


def _sensor_clause_ev(sensor: str) -> str:
    """SQL fragment for event-level sensor filtering (raw text queries)."""
    return "AND ev.sensor = :sensor" if sensor else ""


def _sensor_clause(sensor: str, alias: str = "events") -> str:
    """SQL fragment for sensor filtering (raw text queries, configurable alias)."""
    return f"AND {alias}.sensor = :sensor" if sensor else ""


# ---------------------------------------------------------------------------
# Summary KPIs
# ---------------------------------------------------------------------------

@router.get("/summary")
async def get_summary(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)

    ev_q = select(func.count(Event.id)).where(Event.timestamp >= since)
    sess_q = select(func.count(Session.id)).where(Session.start_time >= since)
    high_q = select(func.count(Event.id)).where(Event.timestamp >= since, Event.severity == "high")
    login_q = select(func.count(Session.id)).where(Session.start_time >= since, Session.login_success.is_(True))
    malware_q = select(func.coalesce(func.sum(Session.files_downloaded), 0)).where(Session.start_time >= since)

    if sensor:
        ev_q      = ev_q.where(Event.sensor == sensor)
        sess_q    = sess_q.where(Session.sensor == sensor)
        high_q    = high_q.where(Event.sensor == sensor)
        login_q   = login_q.where(Session.sensor == sensor)
        malware_q = malware_q.where(Session.sensor == sensor)

    total_events    = await db.scalar(ev_q) or 0
    total_sessions  = await db.scalar(sess_q) or 0
    high_severity   = await db.scalar(high_q) or 0
    login_successes = await db.scalar(login_q) or 0
    malware_downloads = int(await db.scalar(malware_q) or 0)

    unique_ips_q = select(func.count(func.distinct(Event.src_ip))).where(Event.timestamp >= since)
    if sensor:
        unique_ips_q = unique_ips_q.where(Event.sensor == sensor)
    unique_ips = await db.scalar(unique_ips_q) or 0

    countries_q = (
        select(func.count(func.distinct(IPEnrichment.country)))
        .select_from(IPEnrichment)
        .join(Event, Event.src_ip == IPEnrichment.ip_address)
        .where(IPEnrichment.country.isnot(None), Event.timestamp >= since)
    )
    if sensor:
        countries_q = countries_q.where(Event.sensor == sensor)
    countries_seen = await db.scalar(countries_q) or 0

    ml_q = select(func.count(Session.id)).where(Session.start_time >= since, Session.is_anomaly.is_(True))
    if sensor:
        ml_q = ml_q.where(Session.sensor == sensor)
    ml_anomalies = await db.scalar(ml_q) or 0

    return {
        "days": days,
        "sensor": sensor,
        "total_events": total_events,
        "total_sessions": total_sessions,
        "unique_ips": unique_ips,
        "high_severity": high_severity,
        "login_successes": login_successes,
        "malware_downloads": malware_downloads,
        "countries_seen": countries_seen,
        "ml_anomalies": ml_anomalies,
        "generated_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Daily timeline
# ---------------------------------------------------------------------------

@router.get("/timeline")
async def get_timeline(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)
    sensor_sql = "AND sensor = :sensor" if sensor else ""

    result = await db.execute(
        text(f"""
            SELECT TO_CHAR(timestamp, 'YYYY-MM-DD') AS day, COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= :since
            {sensor_sql}
            GROUP BY TO_CHAR(timestamp, 'YYYY-MM-DD')
            ORDER BY day
        """),
        {"since": since, "sensor": sensor} if sensor else {"since": since},
    )
    rows = result.fetchall()

    counts = {row.day: row.cnt for row in rows}
    all_days = _all_days(since, days)
    return {"days": days, "labels": all_days, "data": [counts.get(d, 0) for d in all_days]}


# ---------------------------------------------------------------------------
# Attack type distribution
# ---------------------------------------------------------------------------

@router.get("/attack-types")
async def get_attack_types(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)

    q = (
        select(Event.attack_type, func.count(Event.id).label("cnt"))
        .where(Event.timestamp >= since, Event.attack_type.isnot(None))
    )
    if sensor:
        q = q.where(Event.sensor == sensor)
    q = q.group_by(Event.attack_type).order_by(func.count(Event.id).desc())

    rows = (await db.execute(q)).fetchall()
    total = sum(r.cnt for r in rows) or 1
    items = [
        {"attack_type": r.attack_type, "count": r.cnt, "percentage": round(r.cnt / total * 100, 1)}
        for r in rows
    ]
    return {
        "days": days,
        "labels": [i["attack_type"] for i in items],
        "data": [i["count"] for i in items],
        "percentages": [i["percentage"] for i in items],
        "items": items,
    }


# ---------------------------------------------------------------------------
# Severity trend (stacked bar per day)
# ---------------------------------------------------------------------------

@router.get("/severity-trend")
async def get_severity_trend(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)
    sensor_sql = "AND sensor = :sensor" if sensor else ""

    result = await db.execute(
        text(f"""
            SELECT TO_CHAR(timestamp, 'YYYY-MM-DD') AS day,
                   severity,
                   COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= :since
            {sensor_sql}
            GROUP BY TO_CHAR(timestamp, 'YYYY-MM-DD'), severity
            ORDER BY day
        """),
        {"since": since, "sensor": sensor} if sensor else {"since": since},
    )
    rows = result.fetchall()

    all_days = _all_days(since, days)
    high_map: dict[str, int] = {}
    medium_map: dict[str, int] = {}
    low_map: dict[str, int] = {}

    for row in rows:
        if row.severity == "high":
            high_map[row.day] = row.cnt
        elif row.severity == "medium":
            medium_map[row.day] = row.cnt
        else:
            low_map[row.day] = row.cnt

    return {
        "days": days,
        "labels": all_days,
        "high":   [high_map.get(d, 0) for d in all_days],
        "medium": [medium_map.get(d, 0) for d in all_days],
        "low":    [low_map.get(d, 0) for d in all_days],
    }


# ---------------------------------------------------------------------------
# Top attackers
# ---------------------------------------------------------------------------

@router.get("/top-attackers")
async def get_top_attackers(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)
    sensor_sql = "AND s.sensor = :sensor" if sensor else ""

    result = await db.execute(
        text(f"""
            SELECT s.src_ip,
                   COUNT(s.id)                         AS session_count,
                   MAX(CASE s.severity
                           WHEN 'high'   THEN 3
                           WHEN 'medium' THEN 2
                           ELSE 1 END)                 AS sev_order,
                   MAX(s.severity)                     AS max_severity,
                   e.country,
                   e.country_code
            FROM sessions s
            LEFT JOIN ip_enrichments e ON e.ip_address = s.src_ip
            WHERE s.start_time >= :since
            {sensor_sql}
            GROUP BY s.src_ip, e.country, e.country_code
            ORDER BY session_count DESC
            LIMIT 10
        """),
        {"since": since, "sensor": sensor} if sensor else {"since": since},
    )
    rows = result.fetchall()

    attackers = [
        {
            "rank": i + 1,
            "ip": r.src_ip,
            "count": r.session_count,
            "severity": r.max_severity or "low",
            "country": r.country or "Unknown",
            "country_code": (r.country_code or "").lower(),
        }
        for i, r in enumerate(rows)
    ]
    return {"days": days, "attackers": attackers}


# ---------------------------------------------------------------------------
# Top countries
# ---------------------------------------------------------------------------

@router.get("/top-countries")
async def get_top_countries(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)
    sensor_sql = "AND s.sensor = :sensor" if sensor else ""

    result = await db.execute(
        text(f"""
            SELECT e.country,
                   e.country_code,
                   COUNT(DISTINCT s.src_ip) AS unique_ips,
                   COUNT(s.id)              AS session_count
            FROM sessions s
            JOIN ip_enrichments e ON e.ip_address = s.src_ip
            WHERE s.start_time >= :since
              AND e.country IS NOT NULL
            {sensor_sql}
            GROUP BY e.country, e.country_code
            ORDER BY session_count DESC
            LIMIT 10
        """),
        {"since": since, "sensor": sensor} if sensor else {"since": since},
    )
    rows = result.fetchall()

    items = [
        {
            "country": r.country,
            "country_code": (r.country_code or "").lower(),
            "unique_ips": r.unique_ips,
            "session_count": r.session_count,
        }
        for r in rows
    ]
    return {
        "days": days,
        "labels": [i["country"] for i in items],
        "data": [i["session_count"] for i in items],
        "items": items,
    }


# ---------------------------------------------------------------------------
# CSV export (streaming)
# ---------------------------------------------------------------------------

@router.get("/export/csv")
async def export_csv(
    days: int = Query(7, ge=1, le=365),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    since = _since(days)
    sensor_sql = "AND ev.sensor = :sensor" if sensor else ""

    result = await db.execute(
        text(f"""
            SELECT ev.timestamp,
                   ev.src_ip,
                   ev.sensor,
                   ip.country,
                   ip.city,
                   ev.event_id,
                   ev.attack_type,
                   ev.severity,
                   ev.username,
                   ev.password,
                   ev.command_input,
                   ev.download_url
            FROM events ev
            LEFT JOIN ip_enrichments ip ON ip.ip_address = ev.src_ip
            WHERE ev.timestamp >= :since
            {sensor_sql}
            ORDER BY ev.timestamp DESC
            LIMIT 50000
        """),
        {"since": since, "sensor": sensor} if sensor else {"since": since},
    )
    rows = result.fetchall()

    def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "timestamp", "src_ip", "sensor", "country", "city",
            "event_type", "attack_type", "severity",
            "username", "password", "command", "download_url",
        ])
        yield buf.getvalue()
        buf.truncate(0)
        buf.seek(0)

        for row in rows:
            writer.writerow([
                row.timestamp.isoformat() if row.timestamp else "",
                row.src_ip or "",
                row.sensor or "",
                row.country or "",
                row.city or "",
                row.event_id or "",
                row.attack_type or "",
                row.severity or "",
                row.username or "",
                row.password or "",
                row.command_input or "",
                row.download_url or "",
            ])
            yield buf.getvalue()
            buf.truncate(0)
            buf.seek(0)

    sensor_tag = f"_{sensor}" if sensor else ""
    filename = f"honeydash_events_{days}d{sensor_tag}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
