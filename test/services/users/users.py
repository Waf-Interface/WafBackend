from datetime import datetime
import secrets
from typing import Dict
from fastapi import HTTPException
from sqlalchemy.orm import Session
from models.access_model import Access
from services.database.database import AccessSessionLocal, SessionLocal
from models.user_model import User
from models.auth_model import Auth  
from typing import List, Dict

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_access_db():
    db = AccessSessionLocal()
    try:
        yield db
    finally:
        db.close()
        


async def validate_user_access(access_code: str):
    access_db = next(get_access_db())
    record = access_db.query(Access).filter(Access.access_code == access_code).first()
    
    if not record:
        raise HTTPException(status_code=401, detail="Invalid access code")
    
    if datetime.utcnow() > record.expires_at:
        access_db.delete(record)
        access_db.commit()
        raise HTTPException(status_code=401, detail="Access code expired")
    
    return {
        "username": record.username,
        "rule": record.rule
    }

async def create_user(username: str, password: str, first_name: str, last_name: str, email: str, rule: str):
    db = next(get_db())
    if rule not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid rule. Must be 'admin' or 'user'.")
    
    user = User(username=username, password=password, first_name=first_name, last_name=last_name, email=email, rule=rule)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

async def update_user(user_id: int, username: str, first_name: str, last_name: str, email: str, rule: str):
    db = next(get_db())
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User  not found")
    
    user.username = username
    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.rule = rule
    db.commit()
    db.refresh(user)
    return user

async def delete_user(user_id: int):
    db = next(get_db())
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User  not found")
    
    db.delete(user)
    db.commit()

async def get_users():
    db = next(get_db())
    users = db.query(User).all() 
    return users

async def get_active_users() -> List[Dict[str, str]]:

    access_db = next(get_access_db())
    entries = access_db.query(
        Access.username,
        Access.rule,
        Access.expires_at,
        Access.created_at
    ).all()
    
    return [
        {
            "username": entry.username,
            "rule": entry.rule,
            "expires_at": entry.expires_at.isoformat(),
            "created_at": entry.created_at.isoformat()
        }
        for entry in entries
    ]

async def delete_active_user(access_id: int):
    access_db = next(get_access_db())
    access_record = access_db.query(Access).filter(Access.id == access_id).first()
    
    if not access_record:
        raise HTTPException(status_code=404, detail="Active user not found")
    
    access_db.delete(access_record)
    access_db.commit()