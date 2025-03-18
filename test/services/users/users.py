from fastapi import APIRouter, Depends, HTTPException
from services.auth.jwt import verify_token 
from services.users.users import create_user, update_user, delete_user 

user_router = APIRouter()

@user_router.post("/users/")
async def create_new_user(username: str, password: str, first_name: str, last_name: str, email: str, role: str, user: dict = Depends(verify_token)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return await create_user(username, password, first_name, last_name, email, role)

@user_router.put("/users/{user_id}")
async def update_existing_user(user_id: int, username: str, first_name: str, last_name: str, email: str, role: str, user: dict = Depends(verify_token)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return await update_user(user_id, username, first_name, last_name, email, role)

@user_router.delete("/users/{user_id}")
async def remove_user(user_id: int, user: dict = Depends(verify_token)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return await delete_user(user_id)

