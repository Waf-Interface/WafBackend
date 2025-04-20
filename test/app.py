from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
import uvicorn
from services.auth.generate_rsa_keys import generate_rsa_keys
from services.backup_service import BackupService
from services.database.database import engine, access_engine, Base, AccessBase, SessionLocal, interface_engine, InterfaceBase, WebsiteBase, website_engine
from models.user_model import User
from services.interface.interface import create_default_vip
from routes.routes import routes

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
    expose_headers=["*"],
)

for route in routes:
    app.include_router(
        route["router"],
        prefix=route.get("prefix", ""),
        tags=route.get("tags", []),
        dependencies=route.get("dependencies", [])
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)