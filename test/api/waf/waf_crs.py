from fastapi import APIRouter, HTTPException
from services.waf.waf_crs import WAFService
from pydantic import BaseModel

waf_service = WAFService()
router = APIRouter()

class SecRuleEngineRequest(BaseModel):
    value: str  # "On", "Off", "DetectionOnly"

class SecResponseBodyAccessRequest(BaseModel):
    value: bool  # "On", "Off"

@router.post("/set_sec_rule_engine/")
async def set_sec_rule_engine(request: SecRuleEngineRequest):
    try:
        waf_service.set_sec_rule_engine(request.value)
        return {"message": f"SecRuleEngine set to {request.value} successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/set_sec_response_body_access/")
async def set_sec_response_body_access(request: SecResponseBodyAccessRequest):
    try:
        waf_service.set_sec_response_body_access(request.value)
        return {"message": f"SecResponseBodyAccess set to {'On' if request.value else 'Off'} successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/get_sec_audit_log/")
async def get_sec_audit_log():
    try:
        audit_log_path = waf_service.get_sec_audit_log()
        if audit_log_path:
            return {"SecAuditLog": audit_log_path}
        else:
            raise HTTPException(status_code=404, detail="SecAuditLog not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))