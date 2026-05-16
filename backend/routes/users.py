"""HD_UC_02 — User management: DB-backed users with role (admin | analyst | viewer)."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import bcrypt

from ..auth import get_current_user
from ..database import get_db
from ..models import User

router = APIRouter()


# ── helpers ────────────────────────────────────────────────────────────────

def _hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def _user_out(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


async def _require_admin(
    db: AsyncSession = Depends(get_db),
    email: str = Depends(get_current_user),
) -> User:
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


# ── seeder ─────────────────────────────────────────────────────────────────

async def seed_admin_user(db: AsyncSession, admin_email: str, admin_password_hash: str) -> None:
    """Create the default admin user if no users exist."""
    count = await db.scalar(select(User).with_only_columns(
        __import__("sqlalchemy", fromlist=["func"]).func.count(User.id)
    ))
    if count and count > 0:
        return
    if not admin_password_hash:
        admin_password_hash = _hash("admin")
        print(
            "[users] WARNING: ADMIN_PASSWORD_HASH is empty; seeded default "
            "admin password as 'admin'. Change this in production.",
            flush=True,
        )
    admin = User(
        email=admin_email,
        password_hash=admin_password_hash,
        role="admin",
        full_name="Administrator",
        is_active=True,
    )
    db.add(admin)
    await db.commit()
    print(f"[users] Seeded default admin: {admin_email}")


# ── schemas ────────────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    role: str = "analyst"


class UpdateUserRequest(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


# ── routes ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(_require_admin),
):
    result = await db.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    return [_user_out(u) for u in users]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(_require_admin),
):
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="role must be admin, analyst, or viewer")
    existing = await db.scalar(select(User).where(User.email == body.email))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=body.email,
        password_hash=_hash(body.password),
        full_name=body.full_name,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.get("/me")
async def get_me(
    db: AsyncSession = Depends(get_db),
    email: str = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_out(user)


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(_require_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        if body.role not in ("admin", "analyst", "viewer"):
            raise HTTPException(status_code=400, detail="Invalid role")
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password:
        user.password_hash = _hash(body.password)
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_require_admin),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
