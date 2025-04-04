from sqlalchemy import Enum
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from services.database.database import AccessBase  
from models.user_model import UserRule  

class Access(AccessBase):  
    __tablename__ = "access"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    rule = Column(Enum(UserRule))  
    access_code = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
    created_at = Column(DateTime(timezone=True), server_default=func.now())