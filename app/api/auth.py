from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/auth", tags=["Auth"])
auth_service = AuthService()


class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(payload: RegisterRequest):
    try:
        user = auth_service.register(payload.username, payload.password, payload.full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"success": True, "user": user}


@router.post("/login")
def login(payload: LoginRequest):
    try:
        user = auth_service.authenticate(payload.username, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    token = auth_service.create_session(user["username"])
    return {"token": token, "username": user["username"], "full_name": user.get("full_name", "")}


@router.get("/me")
def me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Non authentifié.")
    token = authorization.split(" ", 1)[1]
    username = auth_service.get_user_by_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée.")
    return {"username": username}


@router.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        auth_service.revoke(authorization.split(" ", 1)[1])
    return {"success": True}