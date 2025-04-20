import secrets
from fastapi import HTTPException
from sqlalchemy.orm import Session
from models.access_model import Access
from services.database.database import SessionLocal
from models.user_model import User
from models.auth_model import Auth  
from models.auth_models import LoginRequest, VerifyOTPRequest  
from services.auth.jwt import create_access_token  
from datetime import datetime, timedelta

from services.users.users import get_access_db

sessions = {}  

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def login_service(request: LoginRequest):
    db = next(get_db())  
    user = db.query(User).filter(User.username == request.username).first()
    if user and user.password == request.password:  
        session_id = secrets.token_hex(16)
        otp = secrets.randbelow(8999) + 1000
        sessions[session_id] = (user.username, otp)  

        return {
            "login_status": "pending",
            "id": session_id,
            "otp": str(otp),
            "message": "OTP sent"
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

async def verify_otp_service(request: VerifyOTPRequest): 
    db = next(get_db())
    access_db = next(get_access_db())
    session_id = request.session_id
    otp = request.otp

    if session_id in sessions:
        expected_username, expected_otp = sessions[session_id]
        if expected_otp == otp:
            del sessions[session_id]  

            user = db.query(User).filter(User.username == expected_username).first()  

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            existing_access_entries = access_db.query(Access).filter(Access.username == expected_username).all()
            if existing_access_entries:
                for entry in existing_access_entries:
                    access_db.delete(entry)
                access_db.commit()

            access_code = secrets.token_hex(16)  
            expires_at = datetime.utcnow() + timedelta(minutes=45)  

            access_entry = Access(
                username=user.username,
                rule=user.rule.value,  
                access_code=access_code,
                expires_at=expires_at
            )
            access_db.add(access_entry)
            access_db.commit()
            access_token = create_access_token(
                data={"sub": expected_username}, 
                user_rule=user.rule.value,  
                expires_delta=timedelta(minutes=45))
            
            return {
                "login_status": "success",
                "message": "Login successful",
                "access_token": access_token,
                "token_type": "bearer",
                "access_code": access_code,  
                "expires_at": expires_at.isoformat()  
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid OTP")
    else:
        raise HTTPException(status_code=404, detail="Session ID not found")
    
async def logout_service(username: str):
    access_db = next(get_access_db())
    
    access_entry = access_db.query(Access).filter(Access.username == username).first()
    
    if access_entry:
        access_db.delete(access_entry)
        access_db.commit()
        return {"message": "Logout successful"}
    else:
        raise HTTPException(status_code=404, detail="User  not found in access database")
