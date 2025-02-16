from fastapi import APIRouter, HTTPException
from services.waf_rule import WAFRules  
from pydantic import BaseModel

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

@router.post("/load_rule/")
async def load_rule(request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    if request.rule and not waf.load_rule(request.rule):
        raise HTTPException(status_code=400, detail="Failed to load rule.")
    return {"status": "success"}

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
