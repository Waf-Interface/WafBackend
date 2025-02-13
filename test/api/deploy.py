from fastapi import APIRouter, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse
import os

from services.file_service import upload_file_service, deploy_file_service

deploy_router = APIRouter()

@deploy_router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    return await upload_file_service(file)

@deploy_router.get("/deploy/{file_name}")
async def deploy_file(file_name: str):
    return await deploy_file_service(file_name)
