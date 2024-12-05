from fastapi import Depends, APIRouter, HTTPException, status


from app.schemas import LoginRequest



router = APIRouter()


@router.get("/")
async def get():
    return {"message": "Hello World"}
