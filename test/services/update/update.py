import os
import re
import shutil
import tempfile
import subprocess
from typing import Dict
from utils.env_manager import get_env_version, set_env_version

REPOS = {
    "crs": "https://github.com/coreruleset/coreruleset.git",
    "cli_controller": "https://github.com/Waf-Interface/Cli-Controller.git",
    "installer": "https://github.com/Waf-Interface/Installer.git"
}

async def get_latest_version(repo_url: str) -> str:
    """Get latest version tag from GitHub"""
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "--sort=-v:refname", repo_url],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split('\n'):
            match = re.search(r"refs/tags/(v?\d+\.\d+\.\d+)$", line)
            if match:
                return match.group(1)
        return "unknown"
    except subprocess.CalledProcessError as e:
        return f"Error: {str(e)}"

async def check_versions() -> Dict[str, str]:
    return {
        "crs": await get_latest_version(REPOS["crs"]),
        "cli_controller": await get_latest_version(REPOS["cli_controller"]),
        "installer": await get_latest_version(REPOS["installer"])
    }

async def update_module(module: str) -> Dict:
    if module == "crs":
        return await update_crs_rules()
    raise ValueError(f"Unsupported module: {module}")

async def update_crs_rules() -> Dict:
    temp_dir = tempfile.mkdtemp()
    try:
        repo_path = os.path.join(temp_dir, "coreruleset")
        subprocess.run(["git", "clone", REPOS["crs"], repo_path], check=True)
        
        latest_tag = await get_latest_version(REPOS["crs"])
        subprocess.run(["git", "-C", repo_path, "checkout", latest_tag], check=True)
        
        new_rules_dir = os.path.join(repo_path, "rules")
        existing_rules_dir = "/usr/local/nginx/rules"
        added_files = []
        
        for filename in os.listdir(new_rules_dir):
            src = os.path.join(new_rules_dir, filename)
            dest = os.path.join(existing_rules_dir, filename)
            
            if not os.path.exists(dest):
                subprocess.run(["sudo", "cp", src, dest], check=True)
                added_files.append(filename)
        
        if not verify_crs_update():
            rollback_crs(added_files)
            return {"success": False, "error": "Update verification failed"}
        
        set_env_version("crs", latest_tag)
        
        return {
            "success": True,
            "new_version": latest_tag,
            "added_files": added_files,
            "message": "New rules added without modifying existing files"
        }
    except subprocess.CalledProcessError as e:
        rollback_crs(added_files)
        return {"success": False, "error": str(e)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def verify_crs_update() -> bool:
    rules_dir = "/usr/local/nginx/rules"
    return os.path.exists(rules_dir) and len(os.listdir(rules_dir)) > 0

def rollback_crs(added_files: list):
    for filename in added_files:
        file_path = os.path.join("/usr/local/nginx/rules", filename)
        if os.path.exists(file_path):
            subprocess.run(["sudo", "rm", "-f", file_path])