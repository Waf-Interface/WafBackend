from fastapi import APIRouter, HTTPException, File, UploadFile, Depends
from fastapi.responses import JSONResponse
import os
from sqlalchemy.orm import Session
from services.database.database import WebsiteSessionLocal
from models.website_model import Website
from services.website.website import (
    delete_website_service,
    upload_file_service, 
    deploy_file_service,
    create_website_entry,
    update_website_status,
    get_website_by_name
)

deploy_router = APIRouter()

def get_website_db():
    db = WebsiteSessionLocal()
    try:
        yield db
    finally:
        db.close()

@deploy_router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    return await upload_file_service(file)

@deploy_router.get("/deploy/{file_name}")
async def deploy_file(file_name: str):
    return await deploy_file_service(file_name)

@deploy_router.get("/websites/")
def list_websites(db: Session = Depends(get_website_db)):
    try:
        websites = db.query(Website).all()
        return websites
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@deploy_router.get("/websites/{website_id}")
def get_website(website_id: str, db: Session = Depends(get_website_db)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return website

@deploy_router.put("/websites/{website_id}/status")
def update_website(
    website_id: str, 
    status: str,
    db: Session = Depends(get_website_db)
): 
    website = update_website_status(db, website_id, status)
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return website

@deploy_router.get("/websites/by-name/{name}")
def get_website_by_name_endpoint(name: str, db: Session = Depends(get_website_db)):
    website = get_website_by_name(db, name)
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return website

@deploy_router.delete("/websites/{website_id}")
async def delete_website(website_id: str):
    try:
        result = await delete_website_service(website_id)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))