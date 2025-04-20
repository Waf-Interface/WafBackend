import asyncio
import json
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from services.logger.logger_service import app_logger
from services.auth.verify_token import verify_websocket_token  
from services.system.system_service import get_system_info_service
from services.websocket.websocket_service import get_nginx_log_summary, show_logs
from services.waf.waf_log import Waf_Log
from services.waf.waf_service import WAF
from services.log.nginxLog import nginxLog

websocket_router = APIRouter()
waf = WAF()
log_file_path = "/usr/local/nginx/logs/access.log"
nginx_log_service = nginxLog(log_file_path)

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
                    await websocket.send_json({
                        "type": "system_info",
                        "payload": system_info
                    })
                    await asyncio.sleep(5)

            elif message_type == "show_logs":
                logs = await show_logs()
                await websocket.send_json({
                    "type": "show_logs",
                    "payload": logs
                })

            elif message_type == "show_audit_logs":
                try:
                    log_paths = [
                        "/var/log/modsec_audit.log",
                        "/usr/local/nginx/logs/modsec_audit.log",
                        "/var/log/nginx/modsec_audit.log"
                    ]
                    audit_logs = None
                    last_error = None
            
                    for path in log_paths:
                        try:
                            app_logger.info(f"Trying audit log path: {path}")
                            log_parser = Waf_Log(log_path=path)
                            audit_logs = log_parser.parse_audit_log()
                            app_logger.info(f"Successfully parsed {len(audit_logs)} audit logs from {path}")
                            break
                        except Exception as e:
                            last_error = str(e)
                            app_logger.warning(f"Failed to parse audit log at {path}: {last_error}")
                            continue
            
                    if audit_logs is None:
                        app_logger.error(f"Could not find valid audit log. Last error: {last_error}")
                        await websocket.send_json({
                            "type": "error",
                            "message": f"Could not find audit log. Last error: {last_error}"
                        })
                    else:
                        await websocket.send_json({
                            "type": "show_audit_logs",
                            "payload": audit_logs
                        })

                except Exception as e:
                    app_logger.error(f"Unexpected error in show_audit_logs: {str(e)}", exc_info=True)
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Failed to fetch audit logs: {str(e)}"
                    })

            elif message_type == "nginx_log_summary":
                summary = await get_nginx_log_summary()
                await websocket.send_json({
                    "type": "nginx_log_summary",
                    "payload": summary
                })

            elif message_type == "modsecurity_status":
                try:
                    is_enabled = waf.is_mod_security_enabled()
                    await websocket.send_json({
                        "type": "modsecurity_status",
                        "payload": {
                            "status": "success",
                            "mod_security_enabled": is_enabled
                        }
                    })
                except Exception as e:
                    app_logger.error(f"Error checking ModSecurity status: {str(e)}")
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Failed to check ModSecurity status: {str(e)}"
                    })

            # New endpoints
            elif message_type == "nginx_log":
                try:
                    logs = nginx_log_service.access_log()
                    await websocket.send_json({
                        "type": "nginx_log",
                        "payload": {
                            "message": "Nginx access log converted to JSON",
                            "logs": logs
                        }
                    })
                except FileNotFoundError:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Nginx log file not found"
                    })
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Failed to get nginx logs: {str(e)}"
                    })

            elif message_type == "summary":
                try:
                    summary = nginx_log_service.get_summary()
                    await websocket.send_json({
                        "type": "summary",
                        "payload": {
                            "summary": summary
                        }
                    })
                except FileNotFoundError:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Nginx log file not found"
                    })
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Failed to get summary: {str(e)}"
                    })

            elif message_type == "traffic":
                try:
                    traffic = nginx_log_service.get_daily_traffic()
                    await websocket.send_json({
                        "type": "traffic",
                        "payload": {
                            "traffic": traffic
                        }
                    })
                except FileNotFoundError:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Nginx log file not found"
                    })
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Failed to get traffic data: {str(e)}"
                    })

    except WebSocketDisconnect:
        app_logger.info("Client disconnected")
        is_sending_info = False
    except Exception as e:
        app_logger.error(f"WebSocket error: {str(e)}")
        await websocket.send_json({
            "type": "error",
            "message": f"Connection error: {str(e)}"
        })
        await websocket.close(code=1011)