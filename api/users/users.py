from fastapi import APIRouter, Depends, HTTPException
from services.auth.verify_token import verify_token 
from services.users.users import create_user, delete_active_user, update_user, delete_user, get_users,get_active_users
from models.user_model import UserCreate, UserUpdate
from pydantic import BaseModel
from typing import List

user_router = APIRouter()

class UserCreateWithToken(UserCreate):
    token: str

@user_router.post("/create_users/")
async def create_new_user(
    user_create: UserCreate, 
    current_user: dict = Depends(verify_token)
):
    if current_user.get("rule") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return await create_user(
        user_create.username,
        user_create.password,
        user_create.first_name,
        user_create.last_name,
        user_create.email,
        user_create.rule
    )

@user_router.put("/users/{user_id}")
async def update_existing_user(
    user_id: int, 
    user_update: UserUpdate,
    current_user: dict = Depends(verify_token) 
):
    if current_user.get("rule") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return await update_user(
        user_id,
        user_update.username,
        user_update.first_name,
        user_update.last_name,
        user_update.email,
        user_update.rule
    )


@user_router.delete("/users/{user_id}")
async def remove_user(
    user_id: int, 
    current_user: dict = Depends(verify_token)
):
    if current_user.get("rule") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return await delete_user(user_id)

@user_router.get("/users/")
async def users(current_user: dict = Depends(verify_token)):  
    return await get_users()

@user_router.get("/active_users/", response_model=List[dict])
async def active_users(current_user: dict = Depends(verify_token)):
    return await get_active_users()

@user_router.delete("/active_users/{access_id}")
async def remove_active_user(
    access_id: int, 
    current_user: dict = Depends(verify_token)
):
    if current_user.get("rule") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return await delete_active_user(access_id)