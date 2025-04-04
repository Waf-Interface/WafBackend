from datetime import datetime
from services.database.database import InterfaceBase  
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Enum

class VirtualIP(InterfaceBase): 
    __tablename__ = "virtual_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    netmask = Column(String)
    interface = Column(String, default="ens33")
    status = Column(Enum("available", "in_use", name="status_enum"), default="available")
    domain = Column(String, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow) 

class VirtualIPCreate(BaseModel):
    ip_address: str
    netmask: str
    interface: str = "ens33"