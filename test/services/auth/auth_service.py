import secrets
from fastapi import HTTPException
from sqlalchemy.orm import Session
from services.database.database import SessionLocal
from models.user_model import User
from models.auth_model import Auth  # Import Auth model
from models.auth_models import LoginRequest, VerifyOTPRequest  
from services.auth.jwt import create_access_token  
from datetime import datetime, timedelta

sessions = {}  # Store session_id to (username, otp) mapping

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def login_service(request: LoginRequest):
    db = next(get_db())  
    user = db.query(User).filter(User.username == request.username).first()
    
    if user and user.password == request.password:  # In production, use hashed passwords
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
    session_id = request.session_id
    otp = request.otp

    if session_id in sessions:
        expected_username, expected_otp = sessions[session_id]
        if expected_otp == otp:
            del sessions[session_id]  

            user = db.query(User).filter(User.username == expected_username).first()  

            if not user:
                raise HTTPException(status_code=404, detail="User  not found")

            access_code = secrets.token_hex(16)  
            expires_at = datetime.utcnow() + timedelta(minutes=45)  

            auth_entry = Auth(user_id=user.id, access_code=access_code, expires_at=expires_at)
            db.add(auth_entry)
            db.commit()
            db.refresh(auth_entry)

            access_token = create_access_token(data={"sub": expected_username})  
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