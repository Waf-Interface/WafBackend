from fastapi import APIRouter, HTTPException,Request
from services.waf.waf_crs import WAFService
from pydantic import BaseModel
from services.waf.waf_log import Waf_Log

waf_service = WAFService()
router = APIRouter()

class SecRuleEngineRequest(BaseModel):
    value: str  # "On", "Off", "DetectionOnly"

class SecResponseBodyAccessRequest(BaseModel):
    value: bool  # True for "On", False for "Off"

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
        parser = Waf_Log("/var/log/modsec_audit.log")
        logs = parser.parse_audit_log()
        
        return {
            "status": "success",
            "count": len(logs),
            "logs": logs[:500],  
            "filtered": True  
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="ModSecurity audit log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@router.get("/get_config_file/{file_key}")
async def get_config_file(file_key: str):
    try:
        contents = waf_service.get_file_contents(file_key)
        return {"contents": contents}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/restore_config_file/{file_key}")
async def restore_config_file(file_key: str):
    try:
        waf_service.restore_config_file(file_key)
        return {"message": f"{file_key} restored successfully."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/restore_all_config_files/")
async def restore_all_config_files():
    try:
        waf_service.restore_all_config_files()
        return {"message": "All configuration files restored successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.put("/update_config/{file_key}")
async def update_config(file_key: str, request: Request):
    try:
        new_contents = await request.body()
        
        new_contents = new_contents.decode('utf-8')

        waf_service.replace_file_contents(file_key, new_contents)
        
        return {"message": f"{file_key} updated successfully."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))