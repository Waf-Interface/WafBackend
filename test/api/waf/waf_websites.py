import json
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database.database import WebsiteSessionLocal
from services.waf.waf_website import WAFWebsiteManager

router = APIRouter(prefix="/website", tags=["website_waf"])

class RuleCreateRequest(BaseModel):
    name: str
    content: str

class BackupRequest(BaseModel):

    name: str
class NginxConfigUpdateRequest(BaseModel):
    config: str


def get_db():
    db = WebsiteSessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/{website_id}/rule")
def create_rule(website_id: str, request: RuleCreateRequest):
    try:
        waf = WAFWebsiteManager(website_id)
        rule_path = waf.create_rule(request.name, request.content)
        return {"status": "success", "rule_path": rule_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{website_id}/rule/{rule_name}")
def update_rule(website_id: str, rule_name: str, request: RuleCreateRequest):
    try:
        if not rule_name.endswith('.conf'):
         rule_name += '.conf'
        
            
        waf = WAFWebsiteManager(website_id)
        rule_path = waf.update_rule(rule_name, request.content)
        return {"status": "success", "rule_path": rule_path}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{website_id}/rule/{rule_name}")
def delete_rule(website_id: str, rule_name: str):
    try:
        waf = WAFWebsiteManager(website_id)
        if not rule_name.endswith('.conf'):
            rule_name += '.conf'
            
        success = waf.delete_rule(rule_name)
        if not success:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "success", "message": "Rule deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/rule/{rule_name}/disable")
def disable_rule(website_id: str, rule_name: str):
    try:
        waf = WAFWebsiteManager(website_id)
        if not rule_name.endswith('.conf'):
            rule_name += '.conf'
            
        success = waf.disable_rule(rule_name)
        if not success:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "success", "message": "Rule disabled successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/rule/{rule_name}/enable")
def enable_rule(website_id: str, rule_name: str):
    try:
        waf = WAFWebsiteManager(website_id)
        success = waf.enable_rule(rule_name)
        return {"status": "success" if success else "rule not found"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{website_id}/rules")
def get_rules(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        rules = waf.get_rules()
        return {"status": "success", "rules": rules}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/backup")
def create_backup(website_id: str, request: BackupRequest):
    try:
        waf = WAFWebsiteManager(website_id)
        backup_path = waf.backup_rules(request.name)
        return {"status": "success", "backup_path": backup_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/restore/{backup_name}")
def restore_backup(website_id: str, backup_name: str):
    try:
        waf = WAFWebsiteManager(website_id)
        success = waf.restore_backup(backup_name)
        return {"status": "success" if success else "backup not found"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
@router.get("/{website_id}/nginx-config")
def get_nginx_config(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        config = waf.get_nginx_config()
        return {"status": "success", "config": config}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{website_id}/nginx-config")
def get_nginx_config(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        config = waf.get_nginx_config()
        return {"status": "success", "config": config}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{website_id}/modsec-main-config")
def get_modsec_main_config(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        config = waf.get_modsec_main_config()
        return {"status": "success", "config": config}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{website_id}/audit-log")
def get_audit_log(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        log_data = waf.get_audit_log()
        
        if log_data.get("status") == "error":
            raise HTTPException(status_code=404, detail=log_data)
        
        return log_data
        
    except HTTPException:
        raise
    except Exception as e:
        try:
            error_info = json.loads(str(e))
        except json.JSONDecodeError:
            error_info = {"error": str(e)}
        
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "message": "Failed to retrieve audit log",
                "details": error_info
            }
        )

@router.get("/{website_id}/debug-log")
def get_debug_log(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        log = waf.get_debug_log()
        return {"status": "success", "log": log}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/audit-log/reset")
def reset_audit_log(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        success = waf.reset_audit_log()
        return {"status": "success" if success else "failed"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{website_id}/debug-log/reset")
def reset_debug_log(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        success = waf.reset_debug_log()
        return {"status": "success" if success else "failed"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
