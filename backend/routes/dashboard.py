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


async def compute_stats(db: AsyncSession) -> dict:
    cutoff = _now_utc() - timedelta(hours=24)

    total = await db.scalar(
        select(func.count(Event.id)).where(Event.timestamp >= cutoff)
    )
    unique = await db.scalar(
        select(func.count(func.distinct(Event.src_ip))).where(Event.timestamp >= cutoff)
    )
    high_sev = await db.scalar(
        select(func.count(Event.id)).where(
            Event.timestamp >= cutoff, Event.severity == "high"
        )
    )
    # Active alerts = high-severity sessions in last 24h
    alerts = await db.scalar(
        select(func.count(Session.id)).where(
            Session.start_time >= cutoff, Session.severity == "high"
        )
    )

    return {
        "total_attacks_24h": total or 0,
        "unique_sources_24h": unique or 0,
        "high_severity_24h": high_sev or 0,
        "active_alerts": alerts or 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    return await compute_stats(db)


@router.get("/timeline")
async def get_timeline(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    now = _now_utc()

    if range == "24h":
        cutoff = now - timedelta(hours=24)
        # 12 buckets of 2 hours
        result = await db.execute(
            text(
                """
                SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt
                FROM events
                WHERE timestamp >= :cutoff
                GROUP BY strftime('%Y-%m-%d %H', timestamp)
                ORDER BY hour
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        # Build 12 slots for 00,02,...,22
        slots = {f"{h:02d}": 0 for h in range(0, 24, 2)}
        for row in rows:
            bucket = f"{(int(row.hour) // 2) * 2:02d}"
            slots[bucket] = slots.get(bucket, 0) + row.cnt
        labels = list(slots.keys())
        data = list(slots.values())

    elif range == "7d":
        cutoff = now - timedelta(days=7)
        result = await db.execute(
            text(
                """
                SELECT strftime('%w', timestamp) as dow, COUNT(*) as cnt
                FROM events
                WHERE timestamp >= :cutoff
                GROUP BY strftime('%Y-%m-%d', timestamp)
                ORDER BY timestamp
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        slots = {d: 0 for d in day_names}
        for row in rows:
            day_name = day_names[int(row.dow)]
            slots[day_name] += row.cnt
        labels = list(slots.keys())
        data = list(slots.values())

    else:  # 30d
        cutoff = now - timedelta(days=30)
        result = await db.execute(
            text(
                """
                SELECT CAST((julianday(timestamp) - julianday(:cutoff)) / 7 AS INTEGER) as week_num,
                       COUNT(*) as cnt
                FROM events
                WHERE timestamp >= :cutoff
                GROUP BY week_num
                ORDER BY week_num
                """
            ),
            {"cutoff": cutoff},
        )
        rows = result.fetchall()
        slots = {"Week 1": 0, "Week 2": 0, "Week 3": 0, "Week 4": 0}
        for row in rows:
            week = min(int(row.week_num) + 1, 4)
            slots[f"Week {week}"] += row.cnt
        labels = list(slots.keys())
        data = list(slots.values())

    return {"range": range, "labels": labels, "data": data}


@router.get("/attack-types")
async def get_attack_types(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    cutoff = _now_utc() - timedelta(hours=24)
    result = await db.execute(
        select(Event.attack_type, func.count(Event.id).label("cnt"))
        .where(Event.timestamp >= cutoff, Event.attack_type.isnot(None))
        .group_by(Event.attack_type)
        .order_by(func.count(Event.id).desc())
        .limit(5)
    )
    rows = result.fetchall()
    labels = [r.attack_type for r in rows]
    data = [r.cnt for r in rows]
    return {"labels": labels, "data": data}


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
    markers = [
        {
            "country": r.country,
            "country_code": r.country_code,
            "lat": r.latitude,
            "lng": r.longitude,
            "count": r.cnt,
        }
        for r in rows
    ]
    return {"markers": markers}
