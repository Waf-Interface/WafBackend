from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from services.auth.jwt import verify_token 
from services.websocket.websocket_service import websocket_handler  

websocket_router = APIRouter()

@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    
    if not token:
        await websocket.close(code=1008)  
        return

    try:
        payload = verify_token(token)
    except HTTPException:
        await websocket.close(code=1008) 
        return

    username = payload.get("sub")
    if username is None:
        await websocket.close(code=1008)  
        return

    await websocket.accept()
    await websocket_handler(websocket)
