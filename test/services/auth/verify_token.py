from datetime import datetime
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
import os
import json

from models.access_model import Access
from services.users.users import get_access_db

SECRET_KEY_FILE = 'secret_key.json'
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def load_secret_key():
    if not os.path.exists(SECRET_KEY_FILE):
        raise HTTPException(status_code=500, detail="Secret key file not found.")
    
    with open(SECRET_KEY_FILE, 'r') as f:
        data = json.load(f) 
        hashed_key = data["hashed_key"]
        return hashed_key

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        hashed_key = load_secret_key()
        payload = jwt.decode(token, hashed_key, algorithms=[ALGORITHM])
        
        access_db = next(get_access_db())
        record = access_db.query(Access).filter(
            Access.username == payload.get("sub"),
            Access.rule == payload.get("rule")
        ).first()
        
        if not record:
            raise HTTPException(status_code=401, detail="Invalid token")
            
        if datetime.utcnow() > record.expires_at:
            access_db.delete(record)
            access_db.commit()
            raise HTTPException(status_code=401, detail="Token expired")
            
        return payload
        
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
