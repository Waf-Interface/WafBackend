import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
import os
import json

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
        # Load the secret key
        hashed_key = load_secret_key()
        
        # Decode the token
        payload = jwt.decode(token, hashed_key, algorithms=[ALGORITHM])
        return payload 
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")