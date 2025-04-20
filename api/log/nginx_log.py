from fastapi import APIRouter, HTTPException
from services.log.nginxLog import nginxLog

router = APIRouter()

@router.post("/nginx_log")
async def convert_nginx_log():
    log_file_path = "/usr/local/nginx/logs/access.log"  
    nginx_log_service = nginxLog(log_file_path)
    
    try:
        logs = nginx_log_service.access_log()
        return {"message": "Nginx access log converted to JSON", "logs": logs}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summery")
async def get_nginx_log_summary():
    log_file_path = "/usr/local/nginx/logs/access.log"  
    nginx_log_service = nginxLog(log_file_path)
    
    try:
        summary = nginx_log_service.get_summary()
        return {"summary": summary}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/traffic")
async def get_daily_traffic():
    log_file_path = "/usr/local/nginx/logs/access.log"  
    nginx_log_service = nginxLog(log_file_path)
    
    try:
        traffic = nginx_log_service.get_daily_traffic()  
        return {"traffic": traffic}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="log not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))