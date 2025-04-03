import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException

from services.auth.verify_token import verify_token
from services.log.nginxLog import nginxLog
from services.system.system_service import get_system_info_service
from services.waf.waf_log import Waf_Log
from services.waf.waf_service import WAF
from services.websocket.websocket_service import WebSocket

waf = WAF()
log_file_path = "/usr/local/nginx/logs/access.log"  
nginx_log_service = nginxLog(log_file_path)

async def websocket_handler(websocket: WebSocket, token: str):
    verify_token(token)
    
    is_sending_info = False
    try:
        await websocket.accept()  
        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            message_type = data.get("type")

            if message_type == "system_info" and not is_sending_info:
                is_sending_info = True
                while is_sending_info:
                    system_info = await get_system_info_service()
                    await websocket.send_text(json.dumps({"type": "system_info", "payload": system_info}))
                    await asyncio.sleep(5)

            elif message_type == "show_logs":
                logs = await show_logs()
                await websocket.send_text(json.dumps({"type": "show_logs", "payload": logs}))

            elif message_type == "show_audit_logs":
                audit_logs = await show_audit_logs()
                await websocket.send_text(json.dumps({"type": "show_audit_logs", "payload": audit_logs}))

            elif message_type == "nginx_log_summary":
                summary = await get_nginx_log_summary()
                await websocket.send_text(json.dumps({"type": "nginx_log_summary", "payload": summary}))

    except WebSocketDisconnect:
        is_sending_info = False

async def get_nginx_log_summary():
    try:
        summary = nginx_log_service.get_summary()
        return {"summary": summary}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

async def show_logs():
    if not waf.check_waf_enabled():
        raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")
    logs = waf.show_logs()  
    if not logs:
        raise HTTPException(status_code=400, detail="Failed to show logs.")
    
    return {"status": "success", "logs": logs}


async def show_audit_logs():
    try:
        log_paths = [
            "/var/log/modsec_audit.log",
            "/usr/local/nginx/logs/modsec_audit.log",
            "/var/log/nginx/modsec_audit.log"
        ]
        
        last_error = None
        
        for path in log_paths:
            try:
                log_parser = Waf_Log(path)
                logs = log_parser.parse_audit_log()
                return {"status": "success", "audit_logs": logs[:10000]}
            except Exception as e:
                last_error = str(e)
                continue
                
        raise Exception(f"Could not find ModSecurity audit log. Last error: {last_error}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
