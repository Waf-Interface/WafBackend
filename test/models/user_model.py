from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from services.database.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  
    first_name = Column(String, nullable=True) 
    last_name = Column(String, nullable=True)  
    email = Column(String, nullable=True)       
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())