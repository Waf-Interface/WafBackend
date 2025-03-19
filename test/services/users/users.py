import secrets
from fastapi import HTTPException
from sqlalchemy.orm import Session
from services.database.database import SessionLocal
from models.user_model import User
from models.auth_model import Auth  

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
