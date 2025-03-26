import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
import json

from services.auth.verify_token import verify_websocket_token  
from services.system.system_service import get_system_info_service
from services.websocket.websocket_service import get_nginx_log_summary, show_audit_logs, show_logs

websocket_router = APIRouter()

@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    
    if not token:
        await websocket.close(code=1008)  
        return

    try:
        payload = verify_websocket_token(token)  
    except HTTPException as e:
        await websocket.close(code=1008)  
        return

    await websocket.accept()
    await websocket_handler(websocket, payload)  

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
                audit_logs = await show_audit_logs()
                await websocket.send_text(json.dumps({"type": "show_audit_logs", "payload": audit_logs}))

            elif message_type == "nginx_log_summary":
                summary = await get_nginx_log_summary()
                await websocket.send_text(json.dumps({"type": "nginx_log_summary", "payload": summary}))

    except WebSocketDisconnect:
        is_sending_info = False
