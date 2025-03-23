import secrets
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException
import os
import json

SECRET_KEY_FILE = 'secret_key.json'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 45

def load_secret_key():
    if not os.path.exists(SECRET_KEY_FILE):
        raise HTTPException(status_code=500, detail="Secret key file not found.")
    
    with open(SECRET_KEY_FILE, 'r') as f:
        data = json.load(f) 
        hashed_key = data["hashed_key"]
        return hashed_key

def create_access_token(data: dict, user_rule: str, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({
        "exp": expire,
        "rule": user_rule  
    })

    hashed_key = load_secret_key()
    encoded_jwt = jwt.encode(to_encode, hashed_key, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    hashed_key = load_secret_key()  
    
    try:
        payload = jwt.decode(token, hashed_key, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
