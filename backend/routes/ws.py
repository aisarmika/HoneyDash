import json
from datetime import datetime, timezone

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ..auth import decode_token
from ..services.broadcaster import manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
):
    # Validate JWT before accepting
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)

    # Send connection acknowledgment
    await websocket.send_text(json.dumps({
        "type": "connected",
        "data": {
            "message": "Connected to HoneyDash live feed",
            "server_time": datetime.now(timezone.utc).isoformat(),
        },
    }))

    # Send current stats immediately on connect
    try:
        from ..database import AsyncSessionLocal
        from .dashboard import compute_stats
        async with AsyncSessionLocal() as db:
            stats = await compute_stats(db)
        await websocket.send_text(json.dumps({"type": "stats_update", "data": stats}))
    except Exception:
        pass

    try:
        while True:
            # Keep connection alive; ignore any client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
