import json
import asyncio
from fastapi import WebSocketDisconnect

from services.system.system_service import get_system_info_service

async def websocket_handler(websocket):
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
    except WebSocketDisconnect:
        is_sending_info = False
