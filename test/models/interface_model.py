#Its for setup Virutal IP's interface.
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Enum
from services.database.database import Base

class VirtualIP(Base):
    __tablename__ = "virtual_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    netmask = Column(String)
    interface = Column(String, default="ens33")
    status = Column(Enum("available", "in_use", name="status_enum"), default="available")
    domain = Column(String, nullable=True)

class VirtualIPCreate(BaseModel):
    ip_address: str
    netmask: str
    interface: str = "ens33"
