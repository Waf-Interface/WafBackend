from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.future import select
from datetime import datetime
from database import Base

# User model to store user details
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  # In a real app, passwords should be hashed
    #TODO
    # Optionally, relationships can be defined (e.g., with Sessions)
#     sessions = relationship("Session", back_populates="user")

# # Session model to store login sessions
# class Session(Base):
#     __tablename__ = "sessions"
    
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("users.id"))
#     session_id = Column(String, unique=True)
#     otp = Column(Integer)
#     created_at = Column(DateTime, default=datetime.utcnow)
    
#     user = relationship("User", back_populates="sessions")
