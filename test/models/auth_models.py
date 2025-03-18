from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class VerifyOTPRequest(BaseModel):
    session_id: str
    otp: int