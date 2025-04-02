import json
import os
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database.database import WebsiteSessionLocal
from services.waf.waf_website import WAFWebsiteManager
from services.logger.logger_service import app_logger

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
        
        # Debug logging
        app_logger.info(f"Delete request for rule: {rule_name}")
        app_logger.info(f"Current rules: {os.listdir(waf.rules_dir)}")
        
        # Handle .conf extension properly
        if not rule_name.endswith('.conf'):
            rule_name += '.conf'
            
        success = waf.delete_rule(rule_name)
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail={
                    "message": "Rule not found or could not be deleted",
                    "rule": rule_name,
                    "available_rules": os.listdir(waf.rules_dir)
                }
            )
            
        return {
            "status": "success",
            "message": f"Rule {rule_name} deleted",
            "remaining_rules": os.listdir(waf.rules_dir)
        }
        
    except Exception as e:
        app_logger.error(f"Delete rule failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=400,
            detail={
                "error": str(e),
                "type": type(e).__name__,
                "rule": rule_name,
                "website": website_id
            }
        )

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
        
        # Debug logging
        app_logger.info(f"Enable request for rule: {rule_name}")
        app_logger.info(f"Disabled rules: {os.listdir(waf.disabled_rules_dir)}")
        
        success = waf.enable_rule(rule_name)
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail={
                    "message": "Rule not found or could not be enabled",
                    "rule": rule_name,
                    "disabled_rules": os.listdir(waf.disabled_rules_dir)
                }
            )
            
        return {
            "status": "success",
            "message": f"Rule {rule_name} enabled",
            "disabled_rules": os.listdir(waf.disabled_rules_dir),
            "active_rules": os.listdir(waf.rules_dir)
        }
        
    except Exception as e:
        app_logger.error(f"Enable rule failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=400,
            detail={
                "error": str(e),
                "type": type(e).__name__,
                "rule": rule_name,
                "website": website_id
            }
        )

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
            if not log_data.get("file_exists", True):
                raise HTTPException(
                    status_code=404,
                    detail={
                        "status": "error",
                        "message": "Audit log file not found",
                        "path": log_data.get("path")
                    }
                )
            else:
                raise HTTPException(
                    status_code=400,
                    detail=log_data
                )
                
        elif log_data.get("status") == "partial":
            return {
                "status": "partial",
                "message": log_data.get("message", "Partial results available"),
                "file_status": log_data.get("file_status"),
                "count": log_data.get("count", 0),
                "logs": log_data.get("logs", [])
            }
        
        return log_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": "Unexpected error processing audit log",
                "error": str(e)
            }
        )
@router.get("/{website_id}/debug-log")
def get_debug_log(website_id: str):
    try:
        waf = WAFWebsiteManager(website_id)
        log_path = os.path.join(waf.base_dir, "debug.log")
        
        if not os.path.exists(log_path):
            raise HTTPException(
                status_code=404,
                detail={
                    "status": "error",
                    "message": "Debug log file not found",
                    "path": log_path
                }
            )
            
        if not os.access(log_path, os.R_OK):
            raise HTTPException(
                status_code=403,
                detail={
                    "status": "error",
                    "message": "Debug log file not readable",
                    "path": log_path
                }
            )
            
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()[-1000:]
                return {
                    "status": "success",
                    "count": len(lines),
                    "log": "".join(lines)
                }
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "status": "error",
                    "message": "Failed to read debug log",
                    "error": str(e)
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": "Unexpected error processing debug log",
                "error": str(e)
            }
        )

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
