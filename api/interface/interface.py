from fastapi import APIRouter, HTTPException
from services.interface.interface import add_virtual_ip, list_virtual_ips, delete_virtual_ip, release_vip
from models.interface_model import VirtualIPCreate

interface_router = APIRouter()

@interface_router.post("/vips/add")
def add_vip_endpoint(vip_data: VirtualIPCreate):  # Remove async and await for the bug ..
    try:
        return add_virtual_ip(  
            ip_address=vip_data.ip_address,
            netmask=vip_data.netmask,
            interface=vip_data.interface
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@interface_router.get("/vips/list")
def list_vips_endpoint(): 
    try:
        return list_virtual_ips() 
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@interface_router.delete("/vips/delete/{vip_id}")
def delete_vip_endpoint(vip_id: int):  
    try:
        return delete_virtual_ip(vip_id)  
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@interface_router.post("/vips/release/{vip_id}")
def release_vip_endpoint(vip_id: int): 
    try:
        return release_vip(vip_id) 
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))