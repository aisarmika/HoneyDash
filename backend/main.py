import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .routes import auth, dashboard, events, sessions, ws
from .services.broadcaster import start_stats_broadcaster
from .services.enrichment import start_enrichment_worker
from .services.log_collector import start_log_collector


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(start_log_collector())
    asyncio.create_task(start_enrichment_worker())
    asyncio.create_task(start_stats_broadcaster())
    yield


app = FastAPI(title="HoneyDash API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(ws.router, tags=["websocket"])


@app.get("/health")
async def health():
    return {"status": "ok"}
