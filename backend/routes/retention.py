"""HD_UC_15 — Retention configuration: GET/POST settings + manual purge trigger."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import RetentionConfig
from ..services.retention import run_purge

router = APIRouter()


class RetentionPayload(BaseModel):
    events_days: int = 60
    sessions_days: int = 90
    enrichment_days: int = 90


@router.get("")
async def get_retention(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        return {"events_days": 60, "sessions_days": 90, "enrichment_days": 90, "last_purge_at": None}
    return {
        "events_days": cfg.events_days,
        "sessions_days": cfg.sessions_days,
        "enrichment_days": cfg.enrichment_days,
        "last_purge_at": cfg.last_purge_at.isoformat() if cfg.last_purge_at else None,
    }


@router.post("")
async def save_retention(
    payload: RetentionPayload,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = RetentionConfig(id=1)
        db.add(cfg)
    cfg.events_days = payload.events_days
    cfg.sessions_days = payload.sessions_days
    cfg.enrichment_days = payload.enrichment_days
    await db.commit()
    return {"saved": True}


@router.post("/purge")
async def trigger_purge(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    """Manually trigger an immediate data purge."""
    try:
        summary = await run_purge()
        return {"success": True, **summary}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Purge failed: {exc}")
