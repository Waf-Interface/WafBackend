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
from api.waf.waf_websites import router 
from models.access_model import Access
from services.auth.generate_rsa_keys import generate_rsa_keys  
from services.backup_service import BackupService  
from api.log.nginx_log import router as nginx_log  
from services.database.database import engine, access_engine, Base, AccessBase, SessionLocal,interface_engine,InterfaceBase,WebsiteBase,website_engine
from models.user_model import User
from services.auth.verify_token import verify_token  
from api.users.users import user_router 
from api.interface.interface import interface_router
from services.interface.interface import create_default_vip
from api.update.update import router as update_router 

Base.metadata.create_all(bind=engine)
AccessBase.metadata.create_all(bind=access_engine)
InterfaceBase.metadata.create_all(bind=interface_engine)  
WebsiteBase.metadata.create_all(bind=website_engine)

try:
    create_default_vip()
except Exception as e:
    print(f"VIP Initialization Note: {str(e)}")

backup_service = BackupService()

app = FastAPI()

generate_rsa_keys()

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
app.include_router(interface_router, prefix="/interface", tags=["interface"], dependencies=[Depends(verify_token)])
app.include_router(update_router, prefix="/update",tags=["update"],dependencies=[Depends(verify_token)])
app.include_router(router, prefix="/waf", tags=["waf"], dependencies=[Depends(verify_token)])
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
