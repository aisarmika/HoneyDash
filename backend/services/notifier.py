"""Notification service: send webhook, Telegram, and email when alert rules fire."""
import asyncio
import json
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage

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
                body = await resp.text()
                suffix = f": {body[:200]}" if body else ""
                return ok, f"HTTP {resp.status}{suffix}"
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


def _send_email_sync(cfg: NotificationConfig, subject: str, body: str) -> tuple[bool, str]:
    sender = cfg.email_user or cfg.email_to
    if not sender:
        return False, "Missing sender email. Set SMTP username or recipient email."

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = cfg.email_to
    msg["Subject"] = subject
    msg.set_content(body)

    host = cfg.email_host
    port = int(cfg.email_port or 587)
    context = ssl.create_default_context()

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15, context=context) as smtp:
                if cfg.email_user and cfg.email_pass:
                    smtp.login(cfg.email_user, cfg.email_pass)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if cfg.email_user and cfg.email_pass:
                    smtp.login(cfg.email_user, cfg.email_pass)
                smtp.send_message(msg)
        return True, f"SMTP {host}:{port} accepted message"
    except Exception as exc:
        return False, str(exc)


async def send_email(cfg: NotificationConfig, subject: str, body: str) -> tuple[bool, str]:
    if not cfg.email_to or not cfg.email_host:
        return False, "Email recipient or SMTP host is missing"
    return await asyncio.to_thread(_send_email_sync, cfg, subject, body)


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
        sev_label = {"high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}.get(
            severity, "[INFO]"
        )
        tg_text = (
            f"{sev_label} <b>HoneyDash Alert</b>\n"
            f"<b>Rule:</b> {rule_name}\n"
            f"<b>IP:</b> <code>{src_ip}</code>\n"
            f"<b>Attack:</b> {attack_type or 'Unknown'}\n"
            f"<b>Severity:</b> {severity.upper()}\n"
            f"<b>Time:</b> {payload['timestamp']}\n"
            f"<b>Session:</b> <code>{session_id[:16]}...</code>"
        )
        ok, msg = await send_telegram(cfg.tg_bot_token, cfg.tg_chat_id, tg_text)
        print(f"[notifier] Telegram → chat {cfg.tg_chat_id}: {msg}")

    if cfg.email_enabled and cfg.email_to and cfg.email_host:
        subject = f"HoneyDash Alert: {severity.upper()} {attack_type or 'Unknown'} from {src_ip}"
        body = (
            "HoneyDash Alert\n"
            "===============\n"
            f"Rule: {rule_name}\n"
            f"Severity: {severity.upper()}\n"
            f"Source IP: {src_ip}\n"
            f"Attack: {attack_type or 'Unknown'}\n"
            f"Session: {session_id}\n"
            f"Time: {payload['timestamp']}\n"
            f"Details: {details or '-'}\n"
        )
        ok, msg = await send_email(cfg, subject, body)
        print(f"[notifier] Email → {cfg.email_to}: {msg}")
