import os
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

def get_env_version(module: str) -> Optional[str]:
    """Get version from .env file"""
    version = os.getenv(f"{module.upper()}_VERSION")
    return version if version != "null" else None

def set_env_version(module: str, version: str) -> None:
    """Update version in .env file"""
    env_file = ".env"
    lines = []
    
    # Read existing file
    with open(env_file, "r") as f:
        lines = f.readlines()
    
    # Find and update the version line
    found = False
    for i, line in enumerate(lines):
        if line.startswith(f"{module.upper()}_VERSION="):
            lines[i] = f"{module.upper()}_VERSION={version}\n"
            found = True
            break
    
    # Add new entry if not found
    if not found:
        lines.append(f"{module.upper()}_VERSION={version}\n")
    
    # Write back to file
    with open(env_file, "w") as f:
        f.writelines(lines)