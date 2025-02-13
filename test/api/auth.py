from fastapi import APIRouter, HTTPException, Body
import secrets

from models.auth_models import LoginRequest
from services.auth_service import login_service, verify_otp_service

auth_router = APIRouter()

@auth_router.post("/login")
async def login(request: LoginRequest):
    return await login_service(request)

@auth_router.post("/verify_otp")
async def verify_otp(session_id: str = Body(...), otp: int = Body(...)):
    return await verify_otp_service(session_id, otp)
