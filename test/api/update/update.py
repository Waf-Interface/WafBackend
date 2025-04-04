from fastapi import APIRouter, HTTPException
from services.update.update import check_versions,update_module
from utils.env_manager import get_env_version

router = APIRouter()

@router.get("/api/update/check")
async def version_check():
    try:
        versions = await check_versions()
        return {
            "modules": {
                "crs": {
                    "current": get_env_version("crs") or "v3.3.7",
                    "latest": versions['crs'],
                    "needs_update": versions['crs'] != get_env_version("crs")
                },
                "cli_controller": {
                    "current": get_env_version("cli_controller") or "0.0.12-dev",
                    "latest": versions['cli_controller'],
                    "needs_update": versions['cli_controller'] != get_env_version("cli_controller")
                },
                "installer": {
                    "current": get_env_version("installer"),
                    "latest": versions['installer'],
                    "needs_update": versions['installer'] != get_env_version("installer")
                }
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/update/crs")
async def update_crs():
    try:
        result = await update_module('crs')
        return {"status": "success", "message": "CRS rules updated", "details": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))