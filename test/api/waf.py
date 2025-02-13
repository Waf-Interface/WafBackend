from fastapi import APIRouter, HTTPException
from services.waf import WAF  
from pydantic import BaseModel

waf = WAF()

router = APIRouter()

class WafRequest(BaseModel):

    username: str
    password: str
    body: str = None  
    rule: str = None  
    power: str = None
    host: str = None
    log: bool = False



@router.get("/status/")
async def check_mod_security_status():
    print(waf.is_mod_security_enabled())  # Call the method properly
    if waf.is_mod_security_enabled():
        return {"status": "success", "mod_security_enabled": True}
    else:
        return {"status": "failure", "mod_security_enabled": False}

@router.post("/auth/")
async def authenticate(request: WafRequest):
    if request.username != "test" or request.password != "test":
        raise HTTPException(status_code=401, detail="Authentication failed.")
    return {"status": "success"}

@router.post("/load_rule/")
async def load_rule(request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    if request.rule and not waf.load_rule(request.rule):
        raise HTTPException(status_code=400, detail="Failed to load rule.")
    return {"status": "success"}


@router.post("/set_engine/")
async def set_mod_security(request: WafRequest):
    if request.power not in ["on", "off"]:
        raise HTTPException(status_code=400, detail="Invalid power option. Use 'on' or 'off'.")
    power = True if request.power == "on" else False
    success = waf.set_mod_security_power(power)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to set ModSecurity power. Check permissions.")
    return {"status": "success"}


@router.post("/log_user/")
async def log_user_access(request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    if not waf.log_user_access(request.username):
        raise HTTPException(status_code=400, detail="Failed to log user access.")
    
    return {"status": "success", "message": f"User access logged for {request.username}"}

@router.get("/show_logs/")
async def show_logs():
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    logs = waf.show_logs()  
    if not logs:
        raise HTTPException(status_code=400, detail="Failed to show logs.")
    
    return {"status": "success", "logs": logs}

@router.post("/toggle_protection/")
async def toggle_protection_for_host(request: WafRequest):
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    if request.host is None:
        raise HTTPException(status_code=400, detail="Host is required.")
    power = True if request.power == "on" else False
    if not waf.toggle_protection_for_host(request.host, power):
        raise HTTPException(status_code=400, detail="Failed to toggle protection for host.")
    return {"status": "success"}

@router.get("/show_audit_logs/")
async def show_audit_logs():
    logs = waf.show_audit_logs()
    if logs is None:
        raise HTTPException(status_code=400, detail="Failed to show audit logs.")
    
    return {"status": "success", "audit_logs": logs}

@router.post("/clear_audit_logs/")
async def clear_audit_logs():
    if not waf.clear_audit_logs():
        raise HTTPException(status_code=400, detail="Failed to clear audit logs.")
    return {"status": "success", "message": "Audit logs cleared successfully."}

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
    
    if not request.rule or not request.body:  # rule is needed instead of title
        raise HTTPException(status_code=400, detail="Both rule and body are required for the rule.")
    
    try:
        print(f"Creating rule with name: {request.rule} and body: {request.body}")
        
        rule_created = waf.create_new_rule(request.rule, request.body)  # use rule instead of title
        
        if not rule_created:
            raise HTTPException(status_code=400, detail="Failed to create new rule.")
        
    except Exception as e:
        print(f"Error during rule creation: {str(e)}")  
        if "already exists" in str(e):
            raise HTTPException(status_code=409, detail=str(e))  
        else:
            raise HTTPException(status_code=500, detail="An unexpected error occurred while creating the rule.")
    
    return {"status": "success", "message": f"Rule '{request.rule}' created successfully."}
