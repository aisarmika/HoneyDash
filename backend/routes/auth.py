from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ..auth import create_access_token, verify_password
from ..config import settings

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    if body.email != settings.admin_email or not verify_password(
        body.password, settings.admin_password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = create_access_token({"sub": body.email})
    return TokenResponse(access_token=token)
