import secrets
from fastapi import HTTPException
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'services'))
from services.logger.logger_service import login_logger  

sessions = {}

async def login_service(request):
    if request.username == "test" and request.password == "test":
        session_id = secrets.token_hex(16)
        otp = secrets.randbelow(8999) + 1000
        sessions[session_id] = otp

        login_logger.info(f"Login attempt: username=test, session_id={session_id}, status=pending")  # Log using login_logger

        return {
            "login_status": "pending",
            "id": session_id,
            "otp": str(otp),
            "message": "OTP sent"
        }
    else:
        login_logger.warning(f"Invalid login attempt: username={request.username}")  # Log invalid attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")

async def verify_otp_service(session_id: str, otp: int):
    if session_id in sessions:
        expected_otp = sessions[session_id]
        if expected_otp == otp:
            del sessions[session_id]

            login_logger.info(f"OTP verified successfully for session_id={session_id}")  # Log OTP verification success
            return {"login_status": "success", "message": "Login successful"}
        else:
            login_logger.warning(f"Invalid OTP for session_id={session_id}")  # Log invalid OTP
            raise HTTPException(status_code=401, detail="Invalid OTP")
    else:
        login_logger.warning(f"Invalid session ID: {session_id}")  # Log missing session ID
        raise HTTPException(status_code=404, detail="Session ID not found")
