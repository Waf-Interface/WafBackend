from datetime import datetime
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

from models.access_model import Access
from services.users.users import get_access_db

load_dotenv()

ALGORITHM = "RS256"
RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", ".public_key.pem")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def load_public_key():
    try:
        with open(RSA_PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load public key: {str(e)}"
        )

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        
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
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
def verify_websocket_token(token: str):
    try:
        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        
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
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
