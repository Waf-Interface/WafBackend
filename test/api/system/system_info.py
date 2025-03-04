from fastapi import APIRouter
from services.system.system_service import get_system_info_service

system_info_router = APIRouter()

@system_info_router.get("/system_info")
async def get_system_info():
    return await get_system_info_service()
