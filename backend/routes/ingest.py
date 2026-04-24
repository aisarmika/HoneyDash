"""
Remote Sensor Ingest — HD_UC_Remote

Accepts Cowrie-format JSON events from remote honeypot sensors over HTTPS.
Authentication: X-Sensor-Key header (shared secret, set via SENSOR_API_KEY env var).

POST /api/ingest/event    — single JSON event
POST /api/ingest/batch    — array of up to 500 JSON events

The payload format is identical to a Cowrie JSON log line, e.g.:
  {
    "eventid": "cowrie.login.failed",
    "timestamp": "2024-01-15T10:30:00.000000Z",
    "src_ip": "1.2.3.4",
    "src_port": 41022,
    "dst_port": 22,
    "username": "root",
    "password": "123456",
    "session": "abc123",
    "sensor": "friend-vps-1"
  }
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Header, HTTPException, Request, status

from ..config import settings
from ..services.log_collector import process_line

router = APIRouter()

_MAX_BATCH = 500


def _check_key(x_sensor_key: str | None):
    if not x_sensor_key or x_sensor_key != settings.sensor_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Sensor-Key header",
        )


@router.post("/event", status_code=202)
async def ingest_event(
    request: Request,
    x_sensor_key: str | None = Header(default=None),
):
    """Accept a single Cowrie-format JSON event from a remote sensor."""
    _check_key(x_sensor_key)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object")

    line = json.dumps(body)
    await process_line(line)
    return {"accepted": 1}


@router.post("/batch", status_code=202)
async def ingest_batch(
    request: Request,
    x_sensor_key: str | None = Header(default=None),
):
    """Accept up to 500 Cowrie-format JSON events in one request."""
    _check_key(x_sensor_key)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a JSON array")

    if len(body) > _MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"Batch too large (max {_MAX_BATCH})")

    accepted = 0
    errors = 0
    for item in body:
        if not isinstance(item, dict):
            errors += 1
            continue
        try:
            await process_line(json.dumps(item))
            accepted += 1
        except Exception:
            errors += 1

    return {"accepted": accepted, "errors": errors, "total": len(body)}
