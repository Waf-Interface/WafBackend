import secrets
from fastapi import HTTPException

sessions = {}

async def login_service(request):
    if request.username == "test" and request.password == "test":
        session_id = secrets.token_hex(16)
        otp = secrets.randbelow(8999) + 1000
        sessions[session_id] = otp
        return {
            "login_status": "pending",
            "id": session_id,
            "otp": str(otp),
            "message": "OTP sent"
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

async def verify_otp_service(session_id: str, otp: int):
    if session_id in sessions:
        expected_otp = sessions[session_id]
        if expected_otp == otp:
            del sessions[session_id]
            return {"login_status": "success", "message": "Login successful"}
        else:
            raise HTTPException(status_code=401, detail="Invalid OTP")
    else:
        raise HTTPException(status_code=404, detail="Session ID not found")
