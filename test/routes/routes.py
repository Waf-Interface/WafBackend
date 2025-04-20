from fastapi import APIRouter, Depends
from api.auth.auth import auth_router
from api.site.deploy import deploy_router
from api.system.system_info import system_info_router
from api.websocket.websocket import websocket_router
from api.waf.waf_rule import router as waf_rule_router
from api.system.system import router as system_router
from api.waf.waf_manager import router as waf_manager
from api.system.loger import router as loger_router
from api.waf.waf_crs import router as waf_setup_router
from api.waf.waf_websites import router
from api.log.nginx_log import router as nginx_log
from api.users.users import user_router
from api.interface.interface import interface_router
from api.update.update import router as update_router
from services.auth.verify_token import verify_token

routes = [
    {
        "router": auth_router,
        "prefix": "/api",
        "dependencies": []
    },
    {
        "router": user_router,
        "prefix": "/api",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": deploy_router,
        "prefix": "/api",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": system_info_router,
        "prefix": "/api",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": websocket_router,
        "prefix": ""
    },
    {
        "router": system_router,
        "prefix": "/api/sys",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": waf_manager,
        "prefix": "/api/waf",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": waf_rule_router,
        "prefix": "/api/waf",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": loger_router,
        "prefix": "/api",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": waf_setup_router,
        "prefix": "/api/waf",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": nginx_log,
        "prefix": "/api",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": interface_router,
        "prefix": "/api/interface",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": update_router,
        "prefix": "/api/update",
        "dependencies": [Depends(verify_token)]
    },
    {
        "router": router,
        "prefix": "/api/waf",
        "dependencies": [Depends(verify_token)]
    }
]