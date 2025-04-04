from fastapi import APIRouter, HTTPException, Depends
from models.auth_models import LoginRequest, VerifyOTPRequest
from services.auth.auth_service import login_service, verify_otp_service, logout_service
from services.auth.jwt import verify_token  

auth_router = APIRouter()

@auth_router.post("/login")
async def login(request: LoginRequest):
    return await login_service(request)

@auth_router.post("/verify_otp")
async def verify_otp(request: VerifyOTPRequest): 
    return await verify_otp_service(request)

@auth_router.post("/logout")
async def logout(current_user: dict = Depends(verify_token)): 
    username = current_user["sub"] 
    return await logout_service(username)