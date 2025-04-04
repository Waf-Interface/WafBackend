from fastapi import APIRouter, HTTPException
from services.system.system import get_network_interfaces, get_network_routes, add_gateway, System

router = APIRouter()

@router.get("/network/interfaces")
async def fetch_network_interfaces():
    try:
        interfaces = get_network_interfaces()
        return interfaces
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network/routes")
async def fetch_network_routes():
    try:
        router = get_network_routes()
        return router
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/network/gateway")
async def create_gateway(interface: System):
    try:
        result = add_gateway(interface)
        return {"message": "Gateway added", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))