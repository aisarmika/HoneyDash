import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import AsyncSessionLocal, init_db
from .routes import auth, dashboard, events, sessions, ws
from .routes import (
    alert_rules,
    attacker,
    honeypot_config,
    ingest,
    malware,
    notifications,
    public,
    remediation,
    reports,
    retention,
    upload,
    users,
)
from .services.broadcaster import start_stats_broadcaster
from .services.dionaea_collector import start_dionaea_collector
from .services.enrichment import start_enrichment_worker
from .services.log_collector import start_log_collector
from .services.ml_detector import start_ml_scheduler
from .services.retention import start_retention_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    # Seed the admin user from settings if users table is empty
    async with AsyncSessionLocal() as db:
        await users.seed_admin_user(
            db,
            admin_email=settings.admin_email,
            admin_password_hash=settings.admin_password_hash,
        )
        await alert_rules.seed_default_rules(db)

    asyncio.create_task(start_log_collector())
    asyncio.create_task(start_dionaea_collector())
    asyncio.create_task(start_enrichment_worker())
    asyncio.create_task(start_stats_broadcaster())
    asyncio.create_task(start_retention_scheduler())
    asyncio.create_task(start_ml_scheduler())
    yield


app = FastAPI(title="HoneyDash API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ────────────────────────────────────────────────────────────────────
app.include_router(auth.router,             prefix="/auth",                    tags=["auth"])

# ── User management (HD_UC_02) ──────────────────────────────────────────────
app.include_router(users.router,            prefix="/api/users",               tags=["users"])

# ── Core data ───────────────────────────────────────────────────────────────
app.include_router(dashboard.router,        prefix="/api/dashboard",           tags=["dashboard"])
app.include_router(events.router,           prefix="/api/events",              tags=["events"])
app.include_router(sessions.router,         prefix="/api/sessions",            tags=["sessions"])

# ── Attacker profile ─────────────────────────────────────────────────────────
app.include_router(attacker.router,         prefix="/api/attacker",            tags=["attacker"])

# ── Reports + export ─────────────────────────────────────────────────────────
app.include_router(reports.router,          prefix="/api/reports",             tags=["reports"])
app.include_router(malware.router,          prefix="/api/malware",             tags=["malware"])

# ── Configuration features ───────────────────────────────────────────────────
app.include_router(honeypot_config.router,  prefix="/api/honeypot-config",     tags=["honeypot-config"])
app.include_router(upload.router,           prefix="/api/upload",              tags=["upload"])
app.include_router(alert_rules.router,      prefix="/api/alert-rules",         tags=["alert-rules"])
app.include_router(remediation.router,      prefix="/api/remediation",         tags=["remediation"])

# ── Remote sensor ingest ─────────────────────────────────────────────────────
app.include_router(ingest.router,           prefix="/api/ingest",              tags=["ingest"])
app.include_router(retention.router,        prefix="/api/retention",           tags=["retention"])
app.include_router(notifications.router,    prefix="/api/notifications",       tags=["notifications"])
app.include_router(public.router,           prefix="/api/public",              tags=["public"])

# ── WebSocket ────────────────────────────────────────────────────────────────
app.include_router(ws.router, tags=["websocket"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
