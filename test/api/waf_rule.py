from fastapi import APIRouter, HTTPException
from services.waf_rule import WAFRules  
from pydantic import BaseModel
import os
waf = WAFRules()

router = APIRouter()

class WafRequest(BaseModel):
    username: str
    password: str
    body: str = None  
    rule: str = None  
    power: str = None
    host: str = None
    log: bool = False

@router.get("/load_rule/{rule}")
async def load_rule(rule: str):
    try:
        result = waf.load_rule(rule) 
        
        if result["status"] == "error":
            raise HTTPException(status_code=400, detail=result["message"])
        
        return {"status": "success", "message": result["message"], "rule_content": result["rule_content"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/show_modsec_rules/")
async def show_modsec_rules():
    if not waf.is_mod_security_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    
    rules = waf.show_modsec_rules()
    if not rules:
        raise HTTPException(status_code=400, detail="Failed to show ModSecurity rules. Check directory permissions.")
    
    return {"status": "success", "modsec_rules": rules}

@router.post("/new_rule/")
async def create_new_rule(request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    
    if not request.rule or not request.body:
        raise HTTPException(status_code=400, detail="Both rule and body are required for the rule.")
    
    try:
        rule_created = waf.create_new_rule(request.rule, request.body)
        if not rule_created:
            raise HTTPException(status_code=400, detail="Failed to create new rule.")
    except Exception as e:
        if "already exists" in str(e):
            raise HTTPException(status_code=409, detail=str(e))  
        else:
            raise HTTPException(status_code=500, detail="An unexpected error occurred while creating the rule.")
    
    return {"status": "success", "message": f"Rule '{request.rule}' created successfully."}


@router.put("/update_rule/{rule}")
async def update_rule(rule: str, request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    
    if not request.body:
        raise HTTPException(status_code=400, detail="New rule content is required.")
    
    try:
        result = waf.update_rule(rule, request.body)
        
        if result["status"] == "error":
            raise HTTPException(status_code=400, detail=result["message"])
        
        return {
            "status": "success", 
            "message": result["message"], 
            "rule_content": result["rule_content"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
