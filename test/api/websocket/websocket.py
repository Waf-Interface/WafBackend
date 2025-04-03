import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
import json

from services.auth.verify_token import verify_websocket_token  
from services.system.system_service import get_system_info_service
from services.websocket.websocket_service import get_nginx_log_summary, show_logs
from services.waf.waf_log import Waf_Log
websocket_router = APIRouter()

@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()  
    
    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({
            "type": "auth_error",
            "message": "Missing token"
        })
        await websocket.close(code=1008)
        return

    try:
        payload = verify_websocket_token(token)
        await websocket_handler(websocket, payload)
    except HTTPException as e:
        await websocket.send_json({
            "type": "auth_error",
            "message": e.detail
        })
        await websocket.close(code=1008)
    except Exception as e:
        await websocket.send_json({
            "type": "error",
            "message": f"Internal server error: {str(e)}"  
        })
        await websocket.close(code=1011) 

async def websocket_handler(websocket: WebSocket, payload: dict):
    is_sending_info = False
    try:
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
                audit_logs = await Waf_Log.parse_audit_log()
                await websocket.send_text(json.dumps({"type": "show_audit_logs", "payload": audit_logs}))

            elif message_type == "nginx_log_summary":
                summary = await get_nginx_log_summary()
                await websocket.send_text(json.dumps({"type": "nginx_log_summary", "payload": summary}))

    except WebSocketDisconnect:
        is_sending_info = False
