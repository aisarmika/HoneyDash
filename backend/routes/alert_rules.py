"""
Alert Rules CRUD — HD_UC_11

Conditions:
  login_attempts_gt   — session.login_attempts > threshold
  login_success       — any successful login (threshold ignored)
  commands_run_gt     — session.commands_run > threshold
  files_downloaded_gt — session.files_downloaded > threshold
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import AlertRule

router = APIRouter()

VALID_CONDITIONS = {
    "login_attempts_gt",
    "login_success",
    "commands_run_gt",
    "files_downloaded_gt",
}

CONDITION_LABELS = {
    "login_attempts_gt":   "Login Attempts >",
    "login_success":       "Any Successful Login",
    "commands_run_gt":     "Commands Run >",
    "files_downloaded_gt": "Files Downloaded >",
}

DEFAULT_RULES = [
    {"name": "SSH Brute Force",     "condition": "login_attempts_gt",   "threshold": 10, "severity": "high"},
    {"name": "Successful Login",    "condition": "login_success",        "threshold": 1,  "severity": "high"},
    {"name": "Command Execution",   "condition": "commands_run_gt",      "threshold": 0,  "severity": "medium"},
    {"name": "Malware Download",    "condition": "files_downloaded_gt",  "threshold": 0,  "severity": "high"},
]


def _rule_to_dict(r: AlertRule) -> dict:
    return {
        "id":           r.id,
        "name":         r.name,
        "condition":    r.condition,
        "condition_label": CONDITION_LABELS.get(r.condition, r.condition),
        "threshold":    r.threshold,
        "severity":     r.severity,
        "enabled":      r.enabled,
        "created_at":   r.created_at.isoformat() + "Z" if r.created_at else None,
    }


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name:      str = Field(..., min_length=1, max_length=255)
    condition: str
    threshold: int = Field(1, ge=0)
    severity:  str = Field("high", pattern="^(high|medium|low)$")
    enabled:   bool = True


class RuleUpdate(BaseModel):
    name:      str | None = Field(None, min_length=1, max_length=255)
    condition: str | None = None
    threshold: int | None = Field(None, ge=0)
    severity:  str | None = Field(None, pattern="^(high|medium|low)$")
    enabled:   bool | None = None


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(AlertRule).order_by(AlertRule.id))
    return {"rules": [_rule_to_dict(r) for r in result.scalars()]}


@router.post("", status_code=201)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    if body.condition not in VALID_CONDITIONS:
        raise HTTPException(400, f"Invalid condition. Choose from: {', '.join(VALID_CONDITIONS)}")
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.put("/{rule_id}")
async def update_rule(
    rule_id: int,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    updates = body.model_dump(exclude_unset=True)
    if "condition" in updates and updates["condition"] not in VALID_CONDITIONS:
        raise HTTPException(400, f"Invalid condition.")
    for k, v in updates.items():
        setattr(rule, k, v)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/{rule_id}")
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _user: str = Depends(get_current_user),
):
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)
    await db.commit()
    return {"deleted": True}


# ─── Seeder ──────────────────────────────────────────────────────────────────

async def seed_default_rules(db: AsyncSession) -> None:
    """Insert default rules if the table is empty."""
    count = await db.scalar(select(AlertRule.id).limit(1))
    if count is not None:
        return  # already seeded
    for r in DEFAULT_RULES:
        db.add(AlertRule(**r))
    await db.commit()
    print("[alert_rules] Default rules seeded.", flush=True)
