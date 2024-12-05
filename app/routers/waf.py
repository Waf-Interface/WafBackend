from fastapi import Depends, APIRouter, HTTPException, status
from app.database import get_db
from sqlalchemy.orm import Session
from app.schemas import LoginRequest



router = APIRouter()


@router.get("/")
async def get():
    return {"message": "Hello World"}

#TODO
# @router.post("/login")
# async def login(request: LoginRequest,db:Session=Depends(get_db)):
#     if request.username == "test" and request.password == "test":
#         session_id = secrets.token_hex(16)
#         otp = secrets.randbelow(9999)
#         sessions[session_id] = otp
#         print(f"Generated OTP for session {session_id}: {otp}")
#         return {"login_status": "pending", "id": session_id, "message": "OTP sent"}
#     else:
#         raise HTTPException(status_code=401, detail="Invalid username or password")
