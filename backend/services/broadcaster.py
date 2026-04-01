import asyncio
import json
from datetime import datetime, timezone
from typing import Set

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, message: dict):
        if not self.active:
            return
        data = json.dumps(message, default=str)
        dead = set()
        for ws in list(self.active):
            try:
                await ws.send_text(data)
            except Exception:
                dead.add(ws)
        self.active -= dead


manager = ConnectionManager()


async def start_stats_broadcaster():
    """Broadcast aggregate stats to all WebSocket clients every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        try:
            from ..database import AsyncSessionLocal
            from ..routes.dashboard import compute_stats
            async with AsyncSessionLocal() as db:
                stats = await compute_stats(db)
            await manager.broadcast({"type": "stats_update", "data": stats})
        except Exception as exc:
            print(f"[broadcaster] stats broadcast error: {exc}")
