"""HD_UC_03 — Honeypot connection configuration: persist and TCP-test connection settings."""
import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import HoneypotConfig

router = APIRouter()


class ConfigPayload(BaseModel):
    honeypot_type: str = "cowrie"
    connection_mode: str = "live"
    host: str = "cowrie"
    port: int = 2222
    protocol: str = "TCP"
    sensor_name: str = "honeypot-01"
    log_path: str = "/var/log/cowrie/cowrie.json"
    notes: str | None = None


class TestRequest(BaseModel):
    host: str
    port: int


def _cfg_to_dict(cfg: HoneypotConfig) -> dict:
    return {
        "honeypot_type": cfg.honeypot_type,
        "connection_mode": cfg.connection_mode,
        "host": cfg.host,
        "port": cfg.port,
        "protocol": cfg.protocol,
        "sensor_name": cfg.sensor_name,
        "log_path": cfg.log_path,
        "notes": cfg.notes,
        "last_test_status": cfg.last_test_status,
        "last_test_at": cfg.last_test_at.isoformat() if cfg.last_test_at else None,
    }


_DEFAULTS = {
    "honeypot_type": "cowrie",
    "connection_mode": "live",
    "host": "cowrie",
    "port": 2222,
    "protocol": "TCP",
    "sensor_name": "honeypot-01",
    "log_path": "/var/log/cowrie/cowrie.json",
    "notes": None,
    "last_test_status": None,
    "last_test_at": None,
}


@router.get("")
async def get_config(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotConfig).where(HoneypotConfig.id == 1))
    cfg = result.scalar_one_or_none()
    return _cfg_to_dict(cfg) if cfg else _DEFAULTS


@router.post("")
async def save_config(
    payload: ConfigPayload,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(HoneypotConfig).where(HoneypotConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = HoneypotConfig(id=1)
        db.add(cfg)

    cfg.honeypot_type = payload.honeypot_type
    cfg.connection_mode = payload.connection_mode
    cfg.host = payload.host
    cfg.port = payload.port
    cfg.protocol = payload.protocol
    cfg.sensor_name = payload.sensor_name
    cfg.log_path = payload.log_path
    cfg.notes = payload.notes
    await db.commit()
    return {"saved": True, "message": "Configuration saved successfully"}


@router.post("/test")
async def test_connection(
    body: TestRequest,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    connected = False
    message = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(body.host, body.port), timeout=3.0
        )
        writer.close()
        await writer.wait_closed()
        connected = True
        message = f"Successfully connected to {body.host}:{body.port}"
    except asyncio.TimeoutError:
        message = f"Connection timed out after 3s ({body.host}:{body.port})"
    except ConnectionRefusedError:
        message = f"Connection refused by {body.host}:{body.port}"
    except OSError as e:
        message = f"Connection failed: {e}"

    # Persist test result if config row exists
    result = await db.execute(select(HoneypotConfig).where(HoneypotConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if cfg:
        cfg.last_test_status = "connected" if connected else "failed"
        cfg.last_test_at = datetime.utcnow()
        await db.commit()

    return {
        "connected": connected,
        "status": "connected" if connected else "failed",
        "message": message,
    }
