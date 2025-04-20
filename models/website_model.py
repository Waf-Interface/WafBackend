from sqlalchemy import Column, String, Boolean, DateTime, JSON, Text
from datetime import datetime
from services.database.database import WebsiteBase

class Website(WebsiteBase):
    __tablename__ = "websites"

    id = Column(String(16), primary_key=True)
    name = Column(String(255), nullable=False)
    application = Column(String(255), nullable=False)
    listen_to = Column(String(255), nullable=False)
    real_web_s = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)
    init_status = Column(Boolean, default=True)
    mode = Column(String(50), default="disabled")
    waf_enabled = Column(Boolean, default=True)
    modsec_audit_log = Column(String(255))  
    modsec_debug_log = Column(String(255))  
    custom_rules = Column(JSON, default=[])
    rule_backups = Column(JSON, default=[])
    timestamp = Column(DateTime, default=datetime.utcnow)