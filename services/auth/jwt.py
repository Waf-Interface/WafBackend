import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
from dotenv import load_dotenv

load_dotenv()  

ALGORITHM = "RS256"  
ACCESS_TOKEN_EXPIRE_MINUTES = 45

def load_private_key():
    private_key_path = os.getenv("RSA_PRIVATE_KEY_PATH", ".private_key.pem")
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load private key: {str(e)}")

def load_public_key():
    public_key_path = os.getenv("RSA_PUBLIC_KEY_PATH", ".public_key.pem")
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load public key: {str(e)}")

def create_access_token(data: dict, user_rule: str, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "rule": user_rule})
    
    private_key = load_private_key() 
    encoded_jwt = jwt.encode(to_encode, private_key, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    public_key = load_public_key() 
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
