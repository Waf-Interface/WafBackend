from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
import uvicorn

from api.auth import auth_router
from api.deploy import deploy_router
from api.system_info import system_info_router
from api.websocket import websocket_router
from api.waf import router as waf_router  

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(deploy_router)
app.include_router(system_info_router)
app.include_router(websocket_router)
app.include_router(waf_router, prefix="/waf", tags=["waf"]) 

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081)
