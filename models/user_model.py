from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.sql import func
from services.database.database import Base
import enum
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    first_name: str
    last_name: str
    email: str
    rule: str 
    
class UserUpdate(BaseModel):
    username: str
    password: str
    first_name: str
    last_name: str
    email: str
    rule: str
    
class UserRule(enum.Enum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  
    first_name = Column(String, nullable=True) 
    last_name = Column(String, nullable=True)  
    email = Column(String, nullable=True)       
    rule = Column(Enum(UserRule), nullable=False) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())