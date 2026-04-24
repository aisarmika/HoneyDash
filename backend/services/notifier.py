"""Notification service: send webhook and/or email when alert rules fire."""
import json
from datetime import datetime

import aiohttp

from ..database import AsyncSessionLocal
from ..models import NotificationConfig


async def _get_config():
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(NotificationConfig).where(NotificationConfig.id == 1))
        return result.scalar_one_or_none()


async def send_webhook(url: str, payload: dict) -> tuple[bool, str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                ok = resp.status < 400
                return ok, f"HTTP {resp.status}"
    except Exception as exc:
        return False, str(exc)


async def send_telegram(bot_token: str, chat_id: str, text: str) -> tuple[bool, str]:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                ok = resp.status < 400
                body = await resp.text()
                return ok, f"HTTP {resp.status}: {body[:120]}"
    except Exception as exc:
        return False, str(exc)


async def notify_alert(
    rule_name: str,
    session_id: str,
    src_ip: str,
    severity: str,
    attack_type: str | None,
    details: str = "",
) -> None:
    """Fire webhook/email for a triggered alert rule. Called from log_collector."""
    cfg = await _get_config()
    if not cfg:
        return

    sev_order = {"low": 0, "medium": 1, "high": 2}
    if sev_order.get(severity, 0) < sev_order.get(cfg.min_severity, 2):
        return

    payload = {
        "source": "HoneyDash",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "rule": rule_name,
        "session_id": session_id,
        "src_ip": src_ip,
        "severity": severity,
        "attack_type": attack_type or "Unknown",
        "details": details,
    }

    if cfg.webhook_enabled and cfg.webhook_url:
        ok, msg = await send_webhook(cfg.webhook_url, payload)
        print(f"[notifier] Webhook → {cfg.webhook_url}: {msg}")

    if cfg.tg_enabled and cfg.tg_bot_token and cfg.tg_chat_id:
        sev_emoji = {"high": "🔴", "medium": "🟠", "low": "🔵"}.get(severity, "⚪")
        tg_text = (
            f"{sev_emoji} <b>HoneyDash Alert</b>\n"
            f"━━━━━━━━━━━━━━\n"
            f"📋 <b>Rule:</b> {rule_name}\n"
            f"🌐 <b>IP:</b> <code>{src_ip}</code>\n"
            f"⚔️ <b>Attack:</b> {attack_type or 'Unknown'}\n"
            f"🚨 <b>Severity:</b> {severity.upper()}\n"
            f"🕐 <b>Time:</b> {payload['timestamp']}\n"
            f"📝 <b>Session:</b> <code>{session_id[:16]}…</code>"
        )
        ok, msg = await send_telegram(cfg.tg_bot_token, cfg.tg_chat_id, tg_text)
        print(f"[notifier] Telegram → chat {cfg.tg_chat_id}: {msg}")

    # Email would go here (requires aiosmtplib — left as future work)
    # if cfg.email_enabled and cfg.email_to and cfg.email_host:
    #     await send_email(cfg, payload)
