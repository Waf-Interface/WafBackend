from datetime import timedelta
from typing import Annotated
from fastapi import Depends, APIRouter, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app import crud
from app import schemas
from app.auth import authenticate, tokens
from app.database import get_db
from sqlalchemy.orm import Session
from app.schemas import LoginRequest, VerifyOTPRequest
import config
from redis_client import redis_client
import pyotp

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def send_otp_to_user(user, otp_code: str):
    # TODO
    # Replace this with actual email/SMS logic
    print(f"Sending OTP {otp_code} to {user.username}")


@router.get("/")
async def get():
    return {"message": "Hello World"}


@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> dict:
    user = authenticate.authenticate_user(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate OTP
    otp = pyotp.TOTP(pyotp.random_base32()).now()  # Generate a 6-digit OTP

    # Store OTP in Redis with a timeout (e.g., 5 minutes)
    otp_key = f"otp:{user.id}"
    redis_client.setex(otp_key, timedelta(minutes=5), otp)

    # Send OTP to user (e.g., via email or SMS)
    background_tasks.add_task(
        send_otp_to_user, user, otp
    )  # Implement send_otp_to_user()

    return {"message": "OTP sent to your email or phone", "otp_required": True}


@router.post("/verify-otp")
async def verify_otp(
    otp_request: VerifyOTPRequest,
    db: Session = Depends(get_db),
) -> schemas.Token:
    user_id = otp_request.user_id
    otp = otp_request.otp

    # Retrieve OTP from Redis
    otp_key = f"otp:{user_id}"
    stored_otp = redis_client.get(otp_key)

    if stored_otp is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired or invalid",
        )

    if stored_otp != otp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP",
        )

    # Delete OTP after successful verification
    redis_client.delete(otp_key)

    # Create the access token
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = tokens.create_access_token(
        data=schemas.TokenData(
            id=user_id,
            #    username=user.username,
            #    role=user.role
        ), expires_delta=access_token_expires
    )
    return schemas.Token(access_token=access_token, token_type="bearer")
