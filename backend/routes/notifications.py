"""Notification configuration: webhook + email settings, and test endpoint."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import NotificationConfig
from ..services.notifier import send_webhook

router = APIRouter()


class NotifPayload(BaseModel):
    webhook_url: str | None = None
    webhook_enabled: bool = False
    email_to: str | None = None
    email_host: str | None = None
    email_port: int = 587
    email_user: str | None = None
    email_pass: str | None = None
    email_enabled: bool = False
    min_severity: str = "high"
    tg_bot_token: str | None = None
    tg_chat_id:   str | None = None
    tg_enabled:   bool = False


def _cfg_out(cfg: NotificationConfig) -> dict:
    return {
        "webhook_url": cfg.webhook_url,
        "webhook_enabled": cfg.webhook_enabled,
        "email_to": cfg.email_to,
        "email_host": cfg.email_host,
        "email_port": cfg.email_port,
        "email_user": cfg.email_user,
        "email_enabled": cfg.email_enabled,
        "min_severity": cfg.min_severity,
        "tg_bot_token": cfg.tg_bot_token,
        "tg_chat_id":   cfg.tg_chat_id,
        "tg_enabled":   cfg.tg_enabled,
    }


_DEFAULTS = {
    "webhook_url": None, "webhook_enabled": False,
    "email_to": None, "email_host": None, "email_port": 587,
    "email_user": None, "email_enabled": False, "min_severity": "high",
    "tg_bot_token": None, "tg_chat_id": None, "tg_enabled": False,
}


@router.get("")
async def get_config(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(NotificationConfig).where(NotificationConfig.id == 1))
    cfg = result.scalar_one_or_none()
    return _cfg_out(cfg) if cfg else _DEFAULTS


@router.post("")
async def save_config(
    payload: NotifPayload,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    if payload.min_severity not in ("low", "medium", "high"):
        raise HTTPException(status_code=400, detail="min_severity must be low, medium, or high")
    result = await db.execute(select(NotificationConfig).where(NotificationConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = NotificationConfig(id=1)
        db.add(cfg)
    cfg.webhook_url = payload.webhook_url
    cfg.webhook_enabled = payload.webhook_enabled
    cfg.email_to = payload.email_to
    cfg.email_host = payload.email_host
    cfg.email_port = payload.email_port
    cfg.email_user = payload.email_user
    cfg.email_pass = payload.email_pass
    cfg.email_enabled = payload.email_enabled
    cfg.min_severity = payload.min_severity
    cfg.tg_bot_token = payload.tg_bot_token
    cfg.tg_chat_id   = payload.tg_chat_id
    cfg.tg_enabled   = payload.tg_enabled
    await db.commit()
    return {"saved": True}


@router.post("/test-webhook")
async def test_webhook(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(NotificationConfig).where(NotificationConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if not cfg or not cfg.webhook_url:
        raise HTTPException(status_code=400, detail="No webhook URL configured")
    ok, msg = await send_webhook(cfg.webhook_url, {
        "source": "HoneyDash",
        "type": "test",
        "message": "HoneyDash webhook test — connection successful",
    })
    return {"success": ok, "message": msg}


@router.post("/test-telegram")
async def test_telegram(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    from ..services.notifier import send_telegram
    result = await db.execute(select(NotificationConfig).where(NotificationConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if not cfg or not cfg.tg_bot_token or not cfg.tg_chat_id:
        raise HTTPException(status_code=400, detail="Telegram not configured")
    ok, msg = await send_telegram(
        cfg.tg_bot_token, cfg.tg_chat_id,
        "✅ <b>HoneyDash</b> — Telegram test successful!\nYour alerts are connected."
    )
    return {"success": ok, "message": msg}
