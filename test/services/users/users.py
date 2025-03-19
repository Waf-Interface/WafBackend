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

async def create_user(username: str, password: str, first_name: str, last_name: str, email: str, role: str):
    db = next(get_db())
    if role not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'user'.")
    
    user = User(username=username, password=password, first_name=first_name, last_name=last_name, email=email, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

async def update_user(user_id: int, username: str, first_name: str, last_name: str, email: str, role: str):
    db = next(get_db())
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User  not found")
    
    user.username = username
    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.role = role
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

async def get_users_by_role(role: str):
    db = next(get_db())
    if role not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'user'.")
    
    users = db.query(User).filter(User.role == role).all()
    return users
