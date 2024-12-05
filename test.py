import asyncio
import json
import secrets
import psutil
import shutil
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()

origins = [
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str

sessions = {}

@app.post("/login")
async def login(request: LoginRequest):
    if request.username == "test" and request.password == "test":
        session_id = secrets.token_hex(16)
        otp = secrets.randbelow(9999)
        sessions[session_id] = otp
        print(f"Generated OTP for session {session_id}: {otp}")
        return {"login_status": "pending", "id": session_id, "message": "OTP sent"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/verify_otp")
async def verify_otp(session_id: str = Body(...), otp: int = Body(...)):
    if session_id in sessions:
        expected_otp = sessions[session_id]
        if expected_otp == otp:
            del sessions[session_id]
            return {"login_status": "success", "message": "Login successful"}
        else:
            raise HTTPException(status_code=401, detail="Invalid OTP")
    else:
        raise HTTPException(status_code=404, detail="Session ID not found")

async def get_system_info():
    cpu_usage = psutil.cpu_percent(interval=1)
    total, used, free = shutil.disk_usage("/")
    cloud_usage_percentage = (used / total) * 100
    memory = psutil.virtual_memory()

    return {
        'cpu_usage': cpu_usage,
        'cloud_usage_total': f"{total / (1024.0 ** 3):.2f} GB",
        'cloud_usage_used': f"{used / (1024.0 ** 3):.2f} GB",
        'cloud_usage_percentage': cloud_usage_percentage,
        'memory_usage_total': f"{memory.total / (1024.0 ** 3):.2f} GB",
        'memory_usage_used': f"{memory.used / (1024.0 ** 3):.2f} GB",
        'memory_usage_percentage': memory.percent,
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    is_sending_info = False
    try:
        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            message_type = data.get("type")
            payload = data.get("payload")

            if message_type == "system_info" and not is_sending_info:
                is_sending_info = True
                while is_sending_info:
                    system_info = await get_system_info()
                    await websocket.send_text(json.dumps({"type": "system_info", "payload": system_info}))
                    await asyncio.sleep(5)

            elif message_type == "user_info":
                user_info = {"username": "test_user", "role": "admin"}
                await websocket.send_text(json.dumps({"type": "user_info", "payload": user_info}))

            elif message_type == "notification":
                notification = {"title": "New message", "content": "You have a new notification."}
                await websocket.send_text(json.dumps({"type": "notification", "payload": notification}))

    except WebSocketDisconnect:
        print("WebSocket connection closed")
        is_sending_info = False

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081)
