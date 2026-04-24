from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Event, IPEnrichment, Session

router = APIRouter()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def compute_stats(db: AsyncSession, sensor: str = "") -> dict:
    cutoff = _now_utc() - timedelta(hours=24)

    total_q = select(func.count(Event.id)).where(Event.timestamp >= cutoff)
    if sensor:
        total_q = total_q.where(Event.sensor == sensor)
    total = await db.scalar(total_q)

    unique_q = select(func.count(func.distinct(Event.src_ip))).where(Event.timestamp >= cutoff)
    if sensor:
        unique_q = unique_q.where(Event.sensor == sensor)
    unique = await db.scalar(unique_q)

    high_sev_q = select(func.count(Event.id)).where(
        Event.timestamp >= cutoff, Event.severity == "high"
    )
    if sensor:
        high_sev_q = high_sev_q.where(Event.sensor == sensor)
    high_sev = await db.scalar(high_sev_q)

    alerts_q = select(func.count(Session.id)).where(
        Session.start_time >= cutoff, Session.severity == "high"
    )
    if sensor:
        alerts_q = alerts_q.where(Session.sensor == sensor)
    alerts = await db.scalar(alerts_q)

    total_sessions_q = select(func.count(Session.id))
    if sensor:
        total_sessions_q = total_sessions_q.where(Session.sensor == sensor)
    total_sessions = await db.scalar(total_sessions_q)

    commands_q = select(func.coalesce(func.sum(Session.commands_run), 0)).where(
        Session.start_time >= cutoff
    )
    if sensor:
        commands_q = commands_q.where(Session.sensor == sensor)
    commands_24h = await db.scalar(commands_q)

    files_q = select(func.coalesce(func.sum(Session.files_downloaded), 0)).where(
        Session.start_time >= cutoff
    )
    if sensor:
        files_q = files_q.where(Session.sensor == sensor)
    files_24h = await db.scalar(files_q)

    countries_q = (
        select(func.count(func.distinct(IPEnrichment.country)))
        .join(Event, Event.src_ip == IPEnrichment.ip_address)
        .where(Event.timestamp >= cutoff, IPEnrichment.country.isnot(None))
    )
    if sensor:
        countries_q = countries_q.where(Event.sensor == sensor)
    countries_24h = await db.scalar(countries_q)

    login_q = select(func.count(Session.id)).where(
        Session.start_time >= cutoff, Session.login_success == True  # noqa: E712
    )
    if sensor:
        login_q = login_q.where(Session.sensor == sensor)
    login_successes = await db.scalar(login_q)

    brute_q = select(func.count(Session.id)).where(
        Session.start_time >= cutoff, Session.login_attempts > 5
    )
    if sensor:
        brute_q = brute_q.where(Session.sensor == sensor)
    brute_force = await db.scalar(brute_q)

    active_q = select(func.count(Session.id)).where(Session.end_time.is_(None))
    if sensor:
        active_q = active_q.where(Session.sensor == sensor)
    active_sessions = await db.scalar(active_q)

    # ML anomalies (graceful fallback if column not yet migrated)
    try:
        ml_q = select(func.count(Session.id)).where(Session.is_anomaly == True)  # noqa: E712
        if sensor:
            ml_q = ml_q.where(Session.sensor == sensor)
        ml_anomalies = await db.scalar(ml_q)
    except Exception:
        ml_anomalies = 0

    return {
        "total_attacks_24h": total or 0,
        "unique_sources_24h": unique or 0,
        "high_severity_24h": high_sev or 0,
        "active_alerts": alerts or 0,
        "total_sessions": total_sessions or 0,
        "commands_24h": int(commands_24h or 0),
        "files_24h": int(files_24h or 0),
        "countries_24h": countries_24h or 0,
        "login_successes_24h": login_successes or 0,
        "brute_force_24h": brute_force or 0,
        "active_sessions": active_sessions or 0,
        "ml_anomalies": ml_anomalies or 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def get_stats(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    return await compute_stats(db, sensor=sensor)


@router.get("/timeline")
async def get_timeline(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    now = _now_utc()

    if range == "24h":
        cutoff = now - timedelta(hours=24)
        result = await db.execute(
            text(
                """
                SELECT TO_CHAR(DATE_TRUNC('hour', timestamp), 'HH24:00') AS bucket,
                       COUNT(*) AS cnt
                FROM events
                WHERE timestamp >= :cutoff
                  AND (:sensor = '' OR sensor = :sensor)
                GROUP BY DATE_TRUNC('hour', timestamp)
                ORDER BY DATE_TRUNC('hour', timestamp)
                """
            ),
            {"cutoff": cutoff, "sensor": sensor},
        )
        rows = result.fetchall()
        slots = {f"{h:02d}:00": 0 for h in range(24)}
        for row in rows:
            slots[row.bucket] = slots.get(row.bucket, 0) + row.cnt
        labels = list(slots.keys())
        data = list(slots.values())

    elif range == "7d":
        cutoff = now - timedelta(days=7)
        result = await db.execute(
            text(
                """
                SELECT TO_CHAR(DATE_TRUNC('day', timestamp), 'Mon DD') AS day,
                       COUNT(*) AS cnt
                FROM events
                WHERE timestamp >= :cutoff
                  AND (:sensor = '' OR sensor = :sensor)
                GROUP BY DATE_TRUNC('day', timestamp)
                ORDER BY DATE_TRUNC('day', timestamp)
                """
            ),
            {"cutoff": cutoff, "sensor": sensor},
        )
        rows = result.fetchall()
        labels = [r.day.strip() for r in rows]
        data = [r.cnt for r in rows]

    else:  # 30d
        cutoff = now - timedelta(days=30)
        result = await db.execute(
            text(
                """
                SELECT TO_CHAR(DATE_TRUNC('week', timestamp), 'Mon DD') AS week,
                       COUNT(*) AS cnt
                FROM events
                WHERE timestamp >= :cutoff
                  AND (:sensor = '' OR sensor = :sensor)
                GROUP BY DATE_TRUNC('week', timestamp)
                ORDER BY DATE_TRUNC('week', timestamp)
                """
            ),
            {"cutoff": cutoff, "sensor": sensor},
        )
        rows = result.fetchall()
        labels = [r.week.strip() for r in rows]
        data = [r.cnt for r in rows]

    return {"range": range, "labels": labels, "data": data}


@router.get("/attack-types")
async def get_attack_types(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    cutoff = _now_utc() - timedelta(hours=24)
    q = select(Event.attack_type, func.count(Event.id).label("cnt")).where(
        Event.timestamp >= cutoff, Event.attack_type.isnot(None)
    )
    if sensor:
        q = q.where(Event.sensor == sensor)
    q = q.group_by(Event.attack_type).order_by(func.count(Event.id).desc()).limit(8)
    result = await db.execute(q)
    rows = result.fetchall()
    return {"labels": [r.attack_type for r in rows], "data": [r.cnt for r in rows]}


@router.get("/severity-trend")
async def get_severity_trend(
    days: int = Query(7, ge=1, le=30),
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Stacked bar data: high/medium/low counts per day over the last N days."""
    cutoff = _now_utc() - timedelta(days=days)
    result = await db.execute(
        text(
            """
            SELECT TO_CHAR(DATE_TRUNC('day', timestamp), 'Mon DD') AS day,
                   severity, COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= :cutoff AND severity IS NOT NULL
              AND (:sensor = '' OR sensor = :sensor)
            GROUP BY DATE_TRUNC('day', timestamp), severity
            ORDER BY DATE_TRUNC('day', timestamp)
            """
        ),
        {"cutoff": cutoff, "sensor": sensor},
    )
    rows = result.fetchall()

    days_seen: list[str] = []
    day_data: dict[str, dict] = {}
    for r in rows:
        d = r.day.strip()
        if d not in days_seen:
            days_seen.append(d)
        if d not in day_data:
            day_data[d] = {"high": 0, "medium": 0, "low": 0}
        if r.severity in day_data[d]:
            day_data[d][r.severity] += r.cnt

    return {
        "labels": days_seen,
        "high": [day_data.get(d, {}).get("high", 0) for d in days_seen],
        "medium": [day_data.get(d, {}).get("medium", 0) for d in days_seen],
        "low": [day_data.get(d, {}).get("low", 0) for d in days_seen],
    }


@router.get("/top-ports")
async def get_top_ports(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Top 10 targeted ports in last 24 h."""
    cutoff = _now_utc() - timedelta(hours=24)
    q = select(Event.dst_port, func.count(Event.id).label("cnt")).where(
        Event.dst_port.isnot(None), Event.timestamp >= cutoff
    )
    if sensor:
        q = q.where(Event.sensor == sensor)
    q = q.group_by(Event.dst_port).order_by(func.count(Event.id).desc()).limit(10)
    result = await db.execute(q)
    rows = result.fetchall()
    return {"labels": [str(r.dst_port) for r in rows], "data": [r.cnt for r in rows]}


@router.get("/hourly")
async def get_hourly(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        text(
            """
            SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= :cutoff
              AND (:sensor = '' OR sensor = :sensor)
            GROUP BY hour
            ORDER BY hour
            """
        ),
        {"cutoff": cutoff, "sensor": sensor},
    )
    rows = result.fetchall()
    slots = [0] * 24
    for r in rows:
        slots[r.hour] = r.cnt
    return {"data": slots}


@router.get("/top-attackers")
async def get_top_attackers(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        text(
            """
            SELECT e.src_ip,
                   COUNT(*) AS cnt,
                   MAX(e.severity) AS severity,
                   MAX(ie.country) AS country,
                   MAX(ie.country_code) AS country_code,
                   MODE() WITHIN GROUP (ORDER BY e.protocol) AS top_protocol
            FROM events e
            LEFT JOIN ip_enrichments ie ON ie.ip_address = e.src_ip
            WHERE e.timestamp >= :cutoff
              AND (:sensor = '' OR e.sensor = :sensor)
            GROUP BY e.src_ip
            ORDER BY cnt DESC
            LIMIT 10
            """
        ),
        {"cutoff": cutoff, "sensor": sensor},
    )
    rows = result.fetchall()
    return {
        "attackers": [
            {
                "ip": r.src_ip,
                "count": r.cnt,
                "severity": r.severity or "low",
                "country": r.country or "-",
                "country_code": r.country_code or "",
                "protocol": r.top_protocol or "ssh",
            }
            for r in rows
        ]
    }


@router.get("/top-credentials")
async def get_top_credentials(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    cutoff = _now_utc() - timedelta(hours=24)
    u_q = select(Event.username, func.count(Event.id).label("cnt")).where(
        Event.timestamp >= cutoff,
        Event.username.isnot(None),
        Event.username != "",
    )
    if sensor:
        u_q = u_q.where(Event.sensor == sensor)
    u_q = u_q.group_by(Event.username).order_by(func.count(Event.id).desc()).limit(10)
    u_result = await db.execute(u_q)

    p_q = select(Event.password, func.count(Event.id).label("cnt")).where(
        Event.timestamp >= cutoff,
        Event.password.isnot(None),
        Event.password != "",
    )
    if sensor:
        p_q = p_q.where(Event.sensor == sensor)
    p_q = p_q.group_by(Event.password).order_by(func.count(Event.id).desc()).limit(10)
    p_result = await db.execute(p_q)

    return {
        "usernames": [{"value": r.username, "count": r.cnt} for r in u_result.fetchall()],
        "passwords": [{"value": r.password, "count": r.cnt} for r in p_result.fetchall()],
    }


@router.get("/heatmap")
async def get_heatmap(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Country × hour attack heatmap. Returns top 10 countries and count per hour (0-23)."""
    cutoff = _now_utc() - timedelta(days=days)

    result = await db.execute(
        text(
            """
            SELECT ip.country,
                   EXTRACT(HOUR FROM ev.timestamp)::int AS hour,
                   COUNT(*) AS cnt
            FROM events ev
            JOIN ip_enrichments ip ON ip.ip_address = ev.src_ip
            WHERE ev.timestamp >= :cutoff
              AND ip.country IS NOT NULL
            GROUP BY ip.country, EXTRACT(HOUR FROM ev.timestamp)::int
            ORDER BY SUM(COUNT(*)) OVER (PARTITION BY ip.country) DESC
            """
        ),
        {"cutoff": cutoff},
    )
    rows = result.fetchall()

    totals: dict[str, int] = {}
    for r in rows:
        totals[r.country] = totals.get(r.country, 0) + r.cnt
    top10 = sorted(totals, key=lambda c: totals[c], reverse=True)[:10]

    matrix: dict[str, list[int]] = {c: [0] * 24 for c in top10}
    for r in rows:
        if r.country in matrix:
            matrix[r.country][r.hour] = r.cnt

    return {
        "days": days,
        "countries": top10,
        "hours": list(range(24)),
        "matrix": matrix,
    }


@router.get("/map")
async def get_map(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
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


@router.get("/protocol-stats")
async def get_protocol_stats(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Protocol breakdown for the last 24 h (SSH, HTTP, SMB, FTP, MySQL …)."""
    cutoff = _now_utc() - timedelta(hours=24)
    q = select(Event.protocol, func.count(Event.id).label("cnt")).where(
        Event.timestamp >= cutoff, Event.protocol.isnot(None)
    )
    if sensor:
        q = q.where(Event.sensor == sensor)
    q = q.group_by(Event.protocol).order_by(func.count(Event.id).desc())
    result = await db.execute(q)
    rows = result.fetchall()
    return {
        "labels": [r.protocol.upper() for r in rows],
        "data": [r.cnt for r in rows],
    }


@router.get("/malware-recent")
async def get_malware_recent(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """10 most-recently seen malware samples (Dionaea captures)."""
    from ..models import MalwareSample

    total_q = select(func.count(MalwareSample.id))
    if sensor:
        total_q = total_q.where(MalwareSample.sensor == sensor)
    total = await db.scalar(total_q) or 0

    samples_q = select(MalwareSample).order_by(MalwareSample.first_seen.desc()).limit(10)
    if sensor:
        samples_q = samples_q.where(MalwareSample.sensor == sensor)
    result = await db.execute(samples_q)
    samples = result.scalars().all()
    return {
        "total": total,
        "samples": [
            {
                "id": s.id,
                "sha256": s.sha256,
                "md5": s.md5,
                "file_size": s.file_size,
                "first_seen": s.first_seen.isoformat() + "Z" if s.first_seen else None,
                "download_count": s.download_count,
                "src_ip": s.src_ip,
                "protocol": s.protocol,
                "vt_detections": s.vt_detections,
                "vt_total": s.vt_total,
                "vt_family": s.vt_family,
            }
            for s in samples
        ],
    }


@router.get("/sensors")
async def get_sensors(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Sensor health: last-seen time and 24 h event count per sensor name."""
    cutoff_online = _now_utc() - timedelta(minutes=5)
    result = await db.execute(
        text(
            """
            SELECT sensor,
                   MAX(timestamp) AS last_seen,
                   COUNT(*) AS event_count
            FROM events
            WHERE sensor IS NOT NULL
            GROUP BY sensor
            ORDER BY last_seen DESC
            """
        )
    )
    rows = result.fetchall()

    # Protocol labels for each known sensor type
    sensor_protocols = {
        "cowrie-01":  "SSH • Telnet",
        "dionaea-01": "HTTP • SMB • FTP • MySQL • MSSQL • SIP",
    }

    sensors = []
    for r in rows:
        last_dt = r.last_seen
        online = bool(last_dt and last_dt >= cutoff_online)
        sensors.append(
            {
                "name": r.sensor,
                "last_seen": last_dt.isoformat() + "Z" if last_dt else None,
                "event_count_24h": r.event_count,
                "online": online,
                "protocols": sensor_protocols.get(r.sensor, "—"),
            }
        )

    # Add known sensors with zero events so they always appear
    seen_names = {s["name"] for s in sensors}
    for name, protos in sensor_protocols.items():
        if name not in seen_names:
            sensors.append(
                {
                    "name": name,
                    "last_seen": None,
                    "event_count_24h": 0,
                    "online": False,
                    "protocols": protos,
                }
            )

    return {
        "sensors": sensors,
        "total": len(sensors),
        "online": sum(1 for s in sensors if s["online"]),
    }


@router.get("/ml-stats")
async def get_ml_stats(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """ML anomaly detection statistics."""
    try:
        total = await db.scalar(select(func.count(Session.id))) or 0
        anomaly_count = (
            await db.scalar(
                select(func.count(Session.id)).where(Session.is_anomaly == True)  # noqa: E712
            )
            or 0
        )
        anomaly_rate = round(anomaly_count / max(total, 1) * 100, 1)

        top_result = await db.execute(
            select(
                Session.session_id,
                Session.src_ip,
                Session.attack_type,
                Session.login_attempts,
                Session.commands_run,
                Session.anomaly_score,
                Session.start_time,
            )
            .where(Session.is_anomaly == True)  # noqa: E712
            .order_by(Session.anomaly_score.asc())
            .limit(10)
        )
        top_anomalies = [
            {
                "session_id": r.session_id,
                "src_ip": r.src_ip,
                "attack_type": r.attack_type,
                "login_attempts": r.login_attempts,
                "commands_run": r.commands_run,
                "anomaly_score": r.anomaly_score,
                "start_time": r.start_time.isoformat() if r.start_time else None,
            }
            for r in top_result.fetchall()
        ]
        return {
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_rate,
            "total_sessions": total,
            "top_anomalies": top_anomalies,
        }
    except Exception:
        return {
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "total_sessions": 0,
            "top_anomalies": [],
        }


@router.get("/unique-attackers")
async def unique_attackers(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Return unique attacker IPs per day for the last 14 days."""
    try:
        sql = text(
            """
            SELECT DATE(timestamp) AS day, COUNT(DISTINCT src_ip) AS cnt
            FROM events
            WHERE timestamp >= NOW() - INTERVAL '14 days'
              AND (:sensor = '' OR sensor = :sensor)
            GROUP BY day
            ORDER BY day
            """
        )
        result = await db.execute(sql, {"sensor": sensor})
        rows = result.fetchall()
        return {
            "labels": [str(r.day) for r in rows],
            "data":   [r.cnt for r in rows],
        }
    except Exception:
        return {"labels": [], "data": []}


@router.get("/login-breakdown")
async def login_breakdown(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Return daily login attempts vs successes for the last 7 days."""
    try:
        sql = text(
            """
            SELECT DATE(start_time) AS day,
                   SUM(login_attempts)::int AS attempts,
                   SUM(CASE WHEN login_success THEN 1 ELSE 0 END)::int AS successes
            FROM sessions
            WHERE start_time >= NOW() - INTERVAL '7 days'
              AND (:sensor = '' OR sensor = :sensor)
            GROUP BY day
            ORDER BY day
            """
        )
        result = await db.execute(sql, {"sensor": sensor})
        rows = result.fetchall()
        return {
            "labels":    [str(r.day) for r in rows],
            "attempts":  [r.attempts  for r in rows],
            "successes": [r.successes for r in rows],
        }
    except Exception:
        return {"labels": [], "attempts": [], "successes": []}


@router.get("/dionaea-deep")
async def get_dionaea_deep(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Deep Dionaea/malware stats for the expanded dashboard tab."""
    from ..models import MalwareSample
    try:
        sensor_where = "AND (:sensor = '' OR sensor = :sensor)"
        sensor_params = {"sensor": sensor}

        # Total captures, unique files, unique IPs
        total_q = select(func.count(MalwareSample.id))
        ufiles_q = select(func.count(func.distinct(MalwareSample.sha256)))
        uips_q = select(func.count(func.distinct(MalwareSample.src_ip)))
        vtdet_q = select(func.count(MalwareSample.id)).where(MalwareSample.vt_detections > 0)
        if sensor:
            total_q  = total_q.where(MalwareSample.sensor == sensor)
            ufiles_q = ufiles_q.where(MalwareSample.sensor == sensor)
            uips_q   = uips_q.where(MalwareSample.sensor == sensor)
            vtdet_q  = vtdet_q.where(MalwareSample.sensor == sensor)
        total       = await db.scalar(total_q) or 0
        unique_files = await db.scalar(ufiles_q) or 0
        unique_ips   = await db.scalar(uips_q) or 0
        vt_detected  = await db.scalar(vtdet_q) or 0

        # Timeline: captures per day for last 14 days
        timeline_result = await db.execute(text(f"""
            SELECT DATE(first_seen) AS day, COUNT(*) AS cnt
            FROM malware_samples
            WHERE first_seen >= NOW() - INTERVAL '14 days'
              {sensor_where}
            GROUP BY day ORDER BY day
        """), sensor_params)
        timeline_rows = timeline_result.fetchall()

        # Protocol breakdown
        proto_result = await db.execute(text(f"""
            SELECT COALESCE(protocol, 'unknown') AS proto, COUNT(*) AS cnt
            FROM malware_samples
            WHERE 1=1 {sensor_where}
            GROUP BY proto ORDER BY cnt DESC
        """), sensor_params)
        proto_rows = proto_result.fetchall()

        # Top malware families from VT
        family_result = await db.execute(text(f"""
            SELECT COALESCE(vt_family, 'Unknown') AS family, COUNT(*) AS cnt
            FROM malware_samples WHERE vt_family IS NOT NULL
              {sensor_where}
            GROUP BY vt_family ORDER BY cnt DESC LIMIT 8
        """), sensor_params)
        family_rows = family_result.fetchall()

        # VT detection rate buckets: clean (0), low (1-5), medium (6-20), high (>20)
        vt_result = await db.execute(text(f"""
            SELECT
              SUM(CASE WHEN vt_detections = 0 THEN 1 ELSE 0 END) AS clean,
              SUM(CASE WHEN vt_detections BETWEEN 1 AND 5 THEN 1 ELSE 0 END) AS low_det,
              SUM(CASE WHEN vt_detections BETWEEN 6 AND 20 THEN 1 ELSE 0 END) AS medium_det,
              SUM(CASE WHEN vt_detections > 20 THEN 1 ELSE 0 END) AS high_det
            FROM malware_samples WHERE vt_detections IS NOT NULL
              {sensor_where}
        """), sensor_params)
        vt_row = vt_result.fetchone()

        # Recent 15 samples with VT info
        samples_q = select(MalwareSample).order_by(MalwareSample.first_seen.desc()).limit(15)
        if sensor:
            samples_q = samples_q.where(MalwareSample.sensor == sensor)
        samples_result = await db.execute(samples_q)
        samples = samples_result.scalars().all()

        return {
            "total": total,
            "unique_files": unique_files,
            "unique_ips": unique_ips,
            "vt_detected": vt_detected,
            "vt_rate": round(vt_detected / max(total, 1) * 100, 1),
            "timeline": {
                "labels": [str(r.day) for r in timeline_rows],
                "data": [r.cnt for r in timeline_rows],
            },
            "protocol": {
                "labels": [r.proto.upper() for r in proto_rows],
                "data": [r.cnt for r in proto_rows],
            },
            "families": {
                "labels": [r.family for r in family_rows],
                "data": [r.cnt for r in family_rows],
            },
            "vt_buckets": {
                "labels": ["Clean (0)", "Low (1-5)", "Medium (6-20)", "High (>20)"],
                "data": [
                    int(vt_row.clean or 0), int(vt_row.low_det or 0),
                    int(vt_row.medium_det or 0), int(vt_row.high_det or 0)
                ] if vt_row else [0, 0, 0, 0],
            },
            "samples": [
                {
                    "sha256": s.sha256,
                    "md5": s.md5,
                    "file_type": s.file_type,
                    "file_size": s.file_size,
                    "protocol": s.protocol,
                    "src_ip": s.src_ip,
                    "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                    "download_count": s.download_count,
                    "vt_detections": s.vt_detections,
                    "vt_total": s.vt_total,
                    "vt_family": s.vt_family,
                }
                for s in samples
            ],
        }
    except Exception as e:
        return {"total": 0, "unique_files": 0, "unique_ips": 0, "vt_detected": 0, "vt_rate": 0,
                "timeline": {"labels": [], "data": []}, "protocol": {"labels": [], "data": []},
                "families": {"labels": [], "data": []}, "vt_buckets": {"labels": [], "data": []}, "samples": []}


@router.get("/top-isps")
async def get_top_isps(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Top 10 ISPs/organisations by attack count (7 day window)."""
    try:
        sensor_clause = "AND (:sensor = '' OR e.sensor = :sensor)"
        result = await db.execute(text(f"""
            SELECT ie.isp,
                   COUNT(DISTINCT e.src_ip) AS unique_ips,
                   COUNT(e.id) AS total_events,
                   MAX(ie.country) AS country
            FROM events e
            JOIN ip_enrichments ie ON ie.ip_address = e.src_ip
            WHERE ie.isp IS NOT NULL AND ie.isp != ''
              AND e.timestamp >= NOW() - INTERVAL '7 days'
              {sensor_clause}
            GROUP BY ie.isp
            ORDER BY total_events DESC LIMIT 10
        """), {"sensor": sensor})
        rows = result.fetchall()
        return {
            "isps": [
                {"isp": r.isp, "unique_ips": r.unique_ips, "total_events": r.total_events, "country": r.country or ""}
                for r in rows
            ]
        }
    except Exception:
        return {"isps": []}


@router.get("/repeat-attackers")
async def get_repeat_attackers(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """IPs that attacked on multiple different calendar days (persistent threats)."""
    try:
        sensor_clause = "AND (:sensor = '' OR e.sensor = :sensor)"
        result = await db.execute(text(f"""
            SELECT e.src_ip,
                   COUNT(DISTINCT DATE(e.timestamp)) AS days_active,
                   COUNT(e.id) AS total_events,
                   MIN(e.timestamp) AS first_seen,
                   MAX(e.timestamp) AS last_seen,
                   MAX(ie.country) AS country,
                   MAX(ie.country_code) AS country_code,
                   MAX(e.severity) AS max_severity
            FROM events e
            LEFT JOIN ip_enrichments ie ON ie.ip_address = e.src_ip
            WHERE 1=1 {sensor_clause}
            GROUP BY e.src_ip
            HAVING COUNT(DISTINCT DATE(e.timestamp)) >= 2
            ORDER BY days_active DESC, total_events DESC
            LIMIT 15
        """), {"sensor": sensor})
        rows = result.fetchall()
        return {
            "attackers": [
                {
                    "ip": r.src_ip,
                    "days_active": r.days_active,
                    "total_events": r.total_events,
                    "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                    "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                    "country": r.country or "—",
                    "country_code": r.country_code or "",
                    "max_severity": r.max_severity or "low",
                }
                for r in rows
            ]
        }
    except Exception:
        return {"attackers": []}


@router.get("/credential-analysis")
async def get_credential_analysis(
    sensor: str = Query(""),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Password pattern analysis and credential stats."""
    try:
        cutoff = _now_utc() - timedelta(days=30)
        sensor_clause = "AND (:sensor = '' OR sensor = :sensor)"
        params = {"cutoff": cutoff, "sensor": sensor}

        # Top 15 username+password combos
        combo_result = await db.execute(text(f"""
            SELECT username, password, COUNT(*) AS cnt
            FROM events
            WHERE username IS NOT NULL AND password IS NOT NULL
              AND username != '' AND password != ''
              AND timestamp >= :cutoff
              {sensor_clause}
            GROUP BY username, password
            ORDER BY cnt DESC LIMIT 15
        """), params)
        combos = combo_result.fetchall()

        # Password length distribution (buckets: 1-4, 5-8, 9-12, 13+)
        length_result = await db.execute(text(f"""
            SELECT
              SUM(CASE WHEN LENGTH(password) <= 4 THEN 1 ELSE 0 END) AS len_1_4,
              SUM(CASE WHEN LENGTH(password) BETWEEN 5 AND 8 THEN 1 ELSE 0 END) AS len_5_8,
              SUM(CASE WHEN LENGTH(password) BETWEEN 9 AND 12 THEN 1 ELSE 0 END) AS len_9_12,
              SUM(CASE WHEN LENGTH(password) > 12 THEN 1 ELSE 0 END) AS len_13plus
            FROM events
            WHERE password IS NOT NULL AND password != ''
              AND timestamp >= :cutoff
              {sensor_clause}
        """), params)
        len_row = length_result.fetchone()

        # Password type categories
        cat_result = await db.execute(text(f"""
            SELECT
              SUM(CASE WHEN password ~ '^[0-9]+$' THEN 1 ELSE 0 END) AS numeric_only,
              SUM(CASE WHEN password ~ '^[a-zA-Z]+$' THEN 1 ELSE 0 END) AS alpha_only,
              SUM(CASE WHEN password ~ '^[a-zA-Z0-9]+$' AND password !~ '^[0-9]+$' AND password !~ '^[a-zA-Z]+$' THEN 1 ELSE 0 END) AS alphanumeric,
              SUM(CASE WHEN password !~ '^[a-zA-Z0-9]+$' THEN 1 ELSE 0 END) AS has_special
            FROM events
            WHERE password IS NOT NULL AND password != ''
              AND timestamp >= :cutoff
              {sensor_clause}
        """), params)
        cat_row = cat_result.fetchone()

        # Top 10 usernames
        user_result = await db.execute(text(f"""
            SELECT username, COUNT(*) AS cnt
            FROM events
            WHERE username IS NOT NULL AND username != ''
              AND timestamp >= :cutoff
              {sensor_clause}
            GROUP BY username ORDER BY cnt DESC LIMIT 10
        """), params)
        users = user_result.fetchall()

        return {
            "top_combos": [{"user": r.username, "pass": r.password, "count": r.cnt} for r in combos],
            "password_lengths": {
                "labels": ["1-4 chars", "5-8 chars", "9-12 chars", "13+ chars"],
                "data": [int(len_row.len_1_4 or 0), int(len_row.len_5_8 or 0),
                         int(len_row.len_9_12 or 0), int(len_row.len_13plus or 0)] if len_row else [0,0,0,0],
            },
            "password_types": {
                "labels": ["Numeric only", "Alpha only", "Alphanumeric", "Has special chars"],
                "data": [int(cat_row.numeric_only or 0), int(cat_row.alpha_only or 0),
                         int(cat_row.alphanumeric or 0), int(cat_row.has_special or 0)] if cat_row else [0,0,0,0],
            },
            "top_usernames": [{"username": r.username, "count": r.cnt} for r in users],
        }
    except Exception as e:
        return {"top_combos": [], "password_lengths": {"labels": [], "data": []},
                "password_types": {"labels": [], "data": []}, "top_usernames": []}
