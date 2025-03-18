from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
import uvicorn
from api.auth.auth import auth_router
from api.site.deploy import deploy_router
from api.system.system_info import system_info_router
from api.websocket.websocket import websocket_router
from api.waf.waf_rule import router as waf_rule_router  
from api.system.system import router as system_router  
from api.waf.waf_manager import router as waf_manager
from api.system.loger import router as loger_router  
from api.waf.waf_crs import router as waf_setup_router  
from services.auth.generate_secret_key import generate_secret_key  
from services.backup_service import BackupService  
from api.log.nginx_log import router as nginx_log  
from services.database.database import engine
from models.user_model import User
from services.auth.verify_token import verify_token  
from api.users.users import user_router 

User .metadata.create_all(bind=engine)

backup_service = BackupService()

app = FastAPI()

generate_secret_key()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(user_router) 
app.include_router(deploy_router, dependencies=[Depends(verify_token)]) 
app.include_router(system_info_router, dependencies=[Depends(verify_token)])
app.include_router(websocket_router) 
app.include_router(system_router, prefix="/sys", tags=["sys"], dependencies=[Depends(verify_token)]) 
app.include_router(waf_manager, prefix="/waf", tags=["waf"], dependencies=[Depends(verify_token)])  
app.include_router(waf_rule_router, prefix="/waf", tags=["waf"], dependencies=[Depends(verify_token)])  
app.include_router(loger_router, dependencies=[Depends(verify_token)]) 
app.include_router(waf_setup_router, prefix="/waf", tags=["waf"], dependencies=[Depends(verify_token)]) 
app.include_router(nginx_log, dependencies=[Depends(verify_token)]) 

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081)
