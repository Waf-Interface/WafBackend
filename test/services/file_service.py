import os
import shutil
from fastapi import HTTPException
from datetime import datetime

UPLOAD_DIRECTORY = 'uploads'
DEPLOY_DIRECTORY = 'deploy'

async def upload_file_service(file):
    try:
        original_filename = os.path.join(UPLOAD_DIRECTORY, file.filename)
        zip_filename = f"{original_filename}.zip"

        with open(original_filename, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)
        
        os.rename(original_filename, zip_filename)
        return {"message": "Upload completed", "filename": f"{file.filename}.zip"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {e}")

async def deploy_file_service(file_name: str):
    try:
        if not file_name.endswith(".zip"):
            file_name += ".zip"
        
        file_path = os.path.join(UPLOAD_DIRECTORY, file_name)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found in uploads folder")
        
        deployment_folder = os.path.join(DEPLOY_DIRECTORY, file_name.split(".")[0])
        os.makedirs(deployment_folder, exist_ok=True)
        
        shutil.move(file_path, deployment_folder)
        return {"message": "Deployment completed", "file": file_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deployment failed: {e}")
