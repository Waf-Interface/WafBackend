from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json

from services.websocket.websocket_service import websocket_handler

websocket_router = APIRouter()

@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket_handler(websocket)
