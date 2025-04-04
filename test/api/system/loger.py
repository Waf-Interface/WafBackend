from fastapi import APIRouter, HTTPException
import os
import json

router = APIRouter()

LOG_DIRECTORY = os.path.join('logs')
APP_LOG_FILE = os.path.join(LOG_DIRECTORY, 'app_log.json')
LOGIN_LOG_FILE = os.path.join(LOG_DIRECTORY, 'login_log.json')

@router.get("/logs/app")
async def get_app_logs():
    try:
        if not os.path.exists(APP_LOG_FILE):
            raise HTTPException(status_code=404, detail="Application log not found.")
        
        with open(APP_LOG_FILE, 'r') as f:
            logs = f.readlines()
        
        logs = [json.loads(log) for log in logs]
        return {"logs": logs}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving application logs: {str(e)}")

@router.get("/logs/login")
async def get_login_logs():
    try:
        if not os.path.exists(LOGIN_LOG_FILE):
            raise HTTPException(status_code=404, detail="Login log not found.")
        
        with open(LOGIN_LOG_FILE, 'r') as f:
            logs = f.readlines()
        logs = [json.loads(log) for log in logs]
        return {"logs": logs}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving login logs: {str(e)}")