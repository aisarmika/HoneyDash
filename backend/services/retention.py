"""HD_UC_15 — Data retention enforcement: daily background purge of old records."""
import asyncio
from datetime import datetime, timedelta

from sqlalchemy import delete, select

from ..database import AsyncSessionLocal
from ..models import Event, IPEnrichment, RetentionConfig, Session


async def run_purge(db=None) -> dict:
    """Run a single purge pass. Pass an open db session for manual triggers."""
    own_db = db is None
    if own_db:
        db = AsyncSessionLocal()
        await db.__aenter__()

    try:
        result = await db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))
        cfg = result.scalar_one_or_none()
        if cfg is None:
            cfg = RetentionConfig(id=1)
            db.add(cfg)
            await db.flush()

        events_cutoff = datetime.utcnow() - timedelta(days=cfg.events_days)
        sessions_cutoff = datetime.utcnow() - timedelta(days=cfg.sessions_days)

        # Delete old events
        ev_result = await db.execute(
            delete(Event).where(Event.timestamp < events_cutoff)
        )
        deleted_events = ev_result.rowcount

        # Delete old sessions (cascade should handle orphaned events via FK,
        # but we already purged events above so this is safe)
        sess_result = await db.execute(
            delete(Session).where(Session.start_time < sessions_cutoff)
        )
        deleted_sessions = sess_result.rowcount

        cfg.last_purge_at = datetime.utcnow()
        await db.commit()

        summary = {
            "deleted_events": deleted_events,
            "deleted_sessions": deleted_sessions,
            "events_cutoff": events_cutoff.isoformat(),
            "sessions_cutoff": sessions_cutoff.isoformat(),
            "purged_at": cfg.last_purge_at.isoformat(),
        }
        print(f"[retention] Purge complete: {summary}")
        return summary

    except Exception as exc:
        await db.rollback()
        print(f"[retention] Purge failed: {exc}")
        raise
    finally:
        if own_db:
            await db.__aexit__(None, None, None)


async def start_retention_scheduler():
    """Run purge once per day (at startup after a short delay, then every 24h)."""
    print("[retention] Scheduler started — first run in 60s")
    await asyncio.sleep(60)
    while True:
        try:
            await run_purge()
        except Exception as exc:
            print(f"[retention] Scheduled purge error: {exc}")
        await asyncio.sleep(24 * 60 * 60)  # 24 hours
