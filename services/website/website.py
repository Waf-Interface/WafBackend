from datetime import datetime
import glob
import ipaddress
import os
import secrets
import socket
import zipfile
import re
import asyncio
import subprocess
import shutil
from sqlalchemy.orm import Session 
from fastapi import HTTPException
from services.database.database import WebsiteSessionLocal
from models.interface_model import VirtualIP
from models.website_model import Website
from services.interface.interface import (
    get_db,
    get_server_ip,
    calculate_netmask,
    create_default_vip,
    release_vip
)
from services.logger.logger_service import app_logger
from services.waf.waf_website import WAFWebsiteManager

UPLOAD_DIRECTORY = 'uploads'
NGINX_CONF_DIRECTORY = '/usr/local/nginx/conf'
NGINX_HTML_DIRECTORY = '/usr/local/nginx/html'
NGINX_BIN = '/usr/local/nginx/sbin/nginx'
APACHE_CONF_DIRECTORY = '/etc/apache2/sites-available' # این متغیر همچنان برای cleanup لازم است
APACHE_PORTS_FILE = '/etc/apache2/ports.conf' # این متغیر دیگر لازم نیست
DEFAULT_PORT = 8080 # این متغیر دیگر لازم نیست
APACHE_PORTS_CONF_PATH = "/etc/apache2/ports.conf" # این متغیر دیگر لازم نیست

os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

async def upload_file_service(file):
    try:
        filename = file.filename
        if not filename.lower().endswith('.zip'):
            filename += '.zip'

        file_path = os.path.join(UPLOAD_DIRECTORY, filename)
        app_logger.info(f"Starting file upload: {filename}")

        with open(file_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)

        app_logger.info(f"Upload completed: {filename}")
        return {"message": "Upload completed", "filename": filename}
    
    except Exception as e:
        app_logger.error(f"Error during upload: {e}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {e}")

# تابع get_available_port حذف می‌شود چون دیگر به آن نیازی نیست

# تابع configure_apache_port حذف می‌شود چون دیگر به آن نیازی نیست

# تابع create_simple_apache_config حذف می‌شود چون دیگر به آن نیازی نیست

# تابع create_nginx_config به‌روزرسانی شده برای سرویس‌دهی مستقیم از Nginx
def create_nginx_config(vip: str, domain: str, backend_port: int, doc_root: str, website_id: str = None):
    """
    Creates Nginx configuration to serve a website and proxy API/WebSocket requests
    directly to the FastAPI backend, bypassing Apache.
    """
    waf_config = ""
    if website_id:
        waf_manager = WAFWebsiteManager(website_id)
        waf_config = f"""
    # WAF configuration
    modsecurity on;
    modsecurity_rules_file {waf_manager.modsec_include};
"""
    
    config = f"""
# {domain} configuration
server {{
    listen {vip}:80;
    listen {vip}:443 ssl;
    server_name {domain};
    
    # SSL Configuration - Use your own certificates here for a production setup
    ssl_certificate /etc/waf-ssl/waf.crt;
    ssl_certificate_key /etc/waf-ssl/waf.key;
    
    # Document root for static files
    root {doc_root};
    index index.html index.htm;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    {waf_config}
    # Pass API and WebSocket requests to the FastAPI backend
    location /api/ {{
        proxy_pass http://127.0.0.1:8081; # Assuming FastAPI is on port 8081
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}

    location /ws {{
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }}

    # Serve static files from the document root
    location / {{
        try_files $uri $uri/ /index.html;
    }}
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {{
        root html;
    }}
}}
"""
    return config

def create_website_entry(db: Session, name: str, real_web_s: str):
    name_without_extension = name.split('.')[0]  
    website = Website(
        id=secrets.token_hex(8),
        name=name_without_extension,
        application=f"www.{name_without_extension}",  
        listen_to="127.0.0.1:8081",  
        real_web_s=real_web_s,
        status="Waiting for zip",
        init_status=True,
        mode="disabled",
    )
    
    db.add(website)
    db.commit()
    db.refresh(website)
    return website

def update_website_status(db: Session, website_id: str, status: str):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        return None
    
    website.status = status
    db.commit()
    db.refresh(website)
    return website

def get_website_by_name(db: Session, name: str):
    return db.query(Website).filter(Website.name == name).first()


async def _check_and_manage_vip(ip_address: str, netmask: str, interface: str, action: str):
    """
    تابع کمکی برای بررسی و مدیریت VIP (اضافه کردن یا حذف کردن).
    action می‌تواند 'add' یا 'del' باشد.
    """
    full_ip = f"{ip_address}/{netmask}"
    try:
        if action == 'del':
            # ابتدا بررسی کنید که IP موجود است یا خیر
            check_cmd = ["sudo", "ip", "addr", "show", "dev", interface]
            check_result = await asyncio.create_subprocess_exec(
                *check_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await check_result.communicate()
            
            if check_result.returncode != 0:
                # اگر دستور check خودش خطا داد، آن را گزارش می‌کنیم
                raise Exception(f"Failed to check IP existence: {stderr.decode()}")
            
            # اگر IP در خروجی 'ip addr show' پیدا نشد
            if not re.search(r'\binet\s+' + re.escape(ip_address) + r'\b', stdout.decode()):
                print(f"VIP {full_ip} not found on {interface}. No deletion needed.")
                return True # IP موجود نیست، پس نیازی به حذف نیست و موفقیت آمیز تلقی می‌شود
        
            print(f"VIP {full_ip} found on {interface}. Attempting to delete...")
            cmd = ["sudo", "ip", "addr", "del", full_ip, "dev", interface]
        
        elif action == 'add':
            print(f"Attempting to add VIP {full_ip} to {interface}...")
            cmd = ["sudo", "ip", "addr", "add", full_ip, "dev", interface]
        else:
            raise ValueError("Action must be 'add' or 'del'")

        # اجرای دستور نهایی (add یا del)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode().strip()
            print(f"Command failed (exit code {process.returncode}): {cmd}, Error: {error_message}")
            raise HTTPException(status_code=500, detail=f"VIP network configuration failed: {error_message}")
        else:
            print(f"VIP {full_ip} {action}ed successfully {'from' if action == 'del' else 'to'} {interface}.")
            return True

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Networking commands ('sudo' or 'ip') not found. Ensure iproute2 is installed.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during VIP management: {e}")
def _validate_existing_configs():
    try:
        result = subprocess.run(
            [NGINX_BIN, '-t'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return True
            
        if "modsecurity_rules_file" in result.stderr:
            app_logger.warning("Nginx config test failed due to WAF rules, attempting to repair")
            _repair_broken_configs()
            
            result = subprocess.run(
                [NGINX_BIN, '-t'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return True
                
        app_logger.error(f"Existing Nginx config is invalid: {result.stderr}")
        _repair_broken_configs()
        raise RuntimeError("Existing Nginx configuration is invalid")
        
    except Exception as e:
        app_logger.error(f"Config validation failed: {str(e)}")
        raise

def _repair_broken_configs():
    sites_enabled = '/usr/local/nginx/conf/sites-enabled'
    if not os.path.exists(sites_enabled):
        return
    
    for config_file in os.listdir(sites_enabled):
        full_path = os.path.join(sites_enabled, config_file)
        try:
            # Test each config file
            result = subprocess.run(
                [NGINX_BIN, '-t', '-c', full_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                app_logger.warning(f"Found broken config: {config_file}")
                # Disable broken config
                os.rename(full_path, f"{full_path}.broken")
        except Exception as e:
            app_logger.error(f"Error checking config {config_file}: {str(e)}")

def _ensure_nginx_structure():
    nginx_conf_path = '/usr/local/nginx/conf/nginx.conf'
    include_line = 'include /usr/local/nginx/conf/sites-enabled/*.conf;'
    
    try:
        # Create required directories if they don't exist
        os.makedirs('/usr/local/nginx/conf/sites-available', exist_ok=True)
        os.makedirs('/usr/local/nginx/conf/sites-enabled', exist_ok=True)
        
        with open(nginx_conf_path, 'r') as f:
            config_lines = f.readlines()
        
        if not config_lines:
            config_lines = [
                "user www-data;\n",
                "worker_processes auto;\n",
                "pid /run/nginx.pid;\n\n",
                "events {\n",
                "    worker_connections 768;\n",
                "}\n\n",
                "http {\n",
                "    include /etc/nginx/mime.types;\n",
                "    default_type application/octet-stream;\n\n",
                "    access_log /var/log/nginx/access.log;\n",
                "    error_log /var/log/nginx/error.log;\n\n",
                "    sendfile on;\n",
                "    keepalive_timeout 65;\n\n",
                f"    {include_line}\n",
                "}\n",
            ]
            needs_update = True
        else:
            needs_update = False
            in_http = False
            has_include = False
            
            # First pass to analyze structure
            for i, line in enumerate(config_lines):
                stripped = line.strip()
                if 'http {' in stripped:
                    in_http = True
                elif in_http and '}' in stripped:
                    in_http = False
                elif in_http and include_line in stripped:
                    has_include = True
            
            # Second pass to fix issues
            if not has_include:
                for i, line in enumerate(config_lines):
                    if 'http {' in line.strip():
                        # Insert include after http block opens
                        config_lines.insert(i+1, f"    {include_line}\n")
                        needs_update = True
                        break
            
            # Clean up any bad includes outside http block
            new_lines = []
            in_http = False
            for line in config_lines:
                stripped = line.strip()
                if 'http {' in stripped:
                    in_http = True
                elif in_http and '}' in stripped:
                    in_http = False
                
                if include_line in stripped and not in_http:
                    continue  # Skip bad includes
                new_lines.append(line)
            
            if len(new_lines) != len(config_lines):
                config_lines = new_lines
                needs_update = True
        
        if needs_update:
            # Create backup
            backup_path = f"{nginx_conf_path}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            shutil.copy2(nginx_conf_path, backup_path)
            
            # Write new config
            with open(nginx_conf_path, 'w') as f:
                f.writelines(config_lines)
            
            # Verify config
            result = subprocess.run([NGINX_BIN, '-t'], capture_output=True, text=True)
            if result.returncode != 0:
                shutil.copy2(backup_path, nginx_conf_path)
                app_logger.error(f"nginx config test failed: {result.stderr}")
                _repair_broken_configs()
                raise RuntimeError(f"Invalid nginx configuration: {result.stderr}")
            
            return True
        
        return False
    
    except Exception as e:
        app_logger.error(f"Error ensuring nginx structure: {str(e)}")
        raise RuntimeError(f"Failed to ensure proper nginx.conf structure: {str(e)}")


async def deploy_file_service(
    file_name: str,
    # این پارامترها اکنون اختیاری هستند و اگر None باشند، از DB استفاده می‌شود
    vip_address: str = None,
    vip_netmask: str = None,
    network_interface: str = None
):
    interface_db = next(get_db())
    website_db = WebsiteSessionLocal()
    vip = None
    deployment_folder = None
    nginx_conf_path = None
    apache_conf_path = None
    website = None
    domain_name = None
    apache_port = None # برای اطمینان از تعریف شدن در بخش Finalize

    try:
        app_logger.info(f"Starting deployment for file: {file_name}")
        
        # Validate existing configs before proceeding
        app_logger.info("Validating existing Nginx configuration")
        _validate_existing_configs() # این تابع باید همگام باشد یا تبدیل به async شود
        
        # Ensure Nginx is running properly before starting
        app_logger.info("Ensuring Nginx service is ready")
        await _ensure_nginx_running_async()
        
        if not file_name.lower().endswith('.zip'):
            file_name += '.zip'
        
        file_path = os.path.join(UPLOAD_DIRECTORY, file_name)
        app_logger.info(f"Looking for file at: {file_path}")
        
        if not os.path.exists(file_path):
            error_msg = f"File not found at {file_path}"
            app_logger.error(error_msg)
            raise HTTPException(status_code=404, detail=error_msg)

        # Create website entry
        try:
            server_ip = get_server_ip()
            app_logger.info(f"Creating website entry for {file_name} with server IP: {server_ip}")
            website = create_website_entry(website_db, file_name, server_ip)
            app_logger.info(f"Created website entry with ID: {website.id}")
            update_website_status(website_db, website.id, "Acquiring VIP")
        except Exception as e:
            app_logger.error(f"Failed to create website entry: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Failed to create website entry: {str(e)}")

        # --- شروع بخش به‌روزرسانی مدیریت VIP ---
        _vip_address = vip_address
        _vip_netmask = vip_netmask
        _network_interface = network_interface

        # اگر پارامترهای VIP توسط کاربر ارائه نشده‌اند، از DB استفاده کن
        if not _vip_address or not _vip_netmask or not _network_interface:
            app_logger.info("VIP parameters not provided by user. Searching for available VIP in database.")
            found_vip = interface_db.query(VirtualIP).filter(VirtualIP.status == "available").first()
            
            if found_vip:
                app_logger.info(f"Found available VIP in DB: {found_vip.ip_address}")
                _vip_address = found_vip.ip_address
                _vip_netmask = found_vip.netmask
                _network_interface = found_vip.interface
                vip = found_vip
            else:
                app_logger.info("No available VIP found in database. Attempting to create a new one.")
                netmask = calculate_netmask(server_ip)
                try:
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                except ValueError as e:
                    app_logger.error(f"Invalid network {server_ip}/{netmask}: {e}")
                    netmask = '255.255.255.0'
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                
                hosts = list(network.hosts())
                new_ip = str(hosts[-1]) if hosts else None

                if not new_ip:
                    error_msg = "Could not find a suitable new IP within the network for VIP."
                    app_logger.error(error_msg)
                    update_website_status(website_db, website.id, "No Suitable VIP IP")
                    raise HTTPException(status_code=503, detail=error_msg)

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.bind((new_ip, 80))
                        s.close()
                except socket.error:
                    app_logger.warning(f"IP {new_ip} appears to be in use, trying next if available")
                    if len(hosts) > 1:
                        new_ip = str(hosts[-2])
                    else:
                        error_msg = f"Generated IP {new_ip} is in use and no alternative available."
                        app_logger.error(error_msg)
                        update_website_status(website_db, website.id, "Generated VIP In Use")
                        raise HTTPException(status_code=503, detail=error_msg)
                
                _vip_address = new_ip
                _vip_netmask = netmask
                _network_interface = os.getenv("DEFAULT_INTERFACE", "ens33")
                
                app_logger.info(f"Creating new VIP record in database for {_vip_address}")
                vip = VirtualIP(
                    ip_address=_vip_address,
                    netmask=_vip_netmask,
                    interface=_network_interface,
                    status="available",
                )
                interface_db.add(vip)
                interface_db.commit()
                interface_db.refresh(vip)
                app_logger.info(f"New VIP record created: {vip.ip_address}")
        
        if not _vip_address:
            error_msg = "No VIP available and creation failed."
            app_logger.error(error_msg)
            update_website_status(website_db, website.id, "No VIP Available Final")
            raise HTTPException(status_code=503, detail=error_msg)

        try:
            app_logger.info(f"Attempting to ensure VIP {_vip_address} is removed from network interface before usage.")
            await _check_and_manage_vip(_vip_address, _vip_netmask, _network_interface, "del")
            
            app_logger.info(f"Configuring VIP network for {_vip_address}")
            await _check_and_manage_vip(_vip_address, _vip_netmask, _network_interface, "add")
            
            app_logger.info("Killing any processes using port 80 (if any)")
            proc_fuser = await asyncio.create_subprocess_exec(
                'sudo', 'fuser', '-k', '80/tcp',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_fuser, stderr_fuser = await proc_fuser.communicate()
            if proc_fuser.returncode != 0 and b'No process found' not in stderr_fuser:
                app_logger.warning(f"fuser command output: {stderr_fuser.decode().strip()}")
            else:
                app_logger.info("Processes on port 80 cleared.")

        except HTTPException as http_exc_vip:
            error_msg = f"VIP acquisition failed: {http_exc_vip.detail}"
            update_website_status(website_db, website.id, f"VIP Acquisition Failed: {http_exc_vip.detail}")
            app_logger.error(error_msg, exc_info=True)
            raise http_exc_vip
        except Exception as e:
            error_msg = f"VIP acquisition failed: {str(e)}"
            update_website_status(website_db, website.id, f"VIP Acquisition Failed: {str(e)}")
            app_logger.error(error_msg, exc_info=True)
            raise HTTPException(status_code=503, detail=error_msg)
        # --- پایان بخش به‌روزرسانی مدیریت VIP ---

        # Deployment Preparation
        update_website_status(website_db, website.id, "Preparing Deployment")
        domain_name = os.path.splitext(file_name)[0]
        deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, domain_name)
        app_logger.info(f"Setting up deployment folder at: {deployment_folder}")
        
        if os.path.exists(deployment_folder):
            app_logger.info(f"Removing existing deployment folder: {deployment_folder}")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: shutil.rmtree(deployment_folder, ignore_errors=True))
        
        app_logger.info(f"Creating new deployment folder: {deployment_folder}")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: os.makedirs(deployment_folder, exist_ok=True))

        # Extract files and set permissions
        app_logger.info(f"Extracting zip file: {file_path}")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: (
                lambda: (zip_ref := zipfile.ZipFile(file_path, 'r'), zip_ref.extractall(deployment_folder), len(zip_ref.filelist), zip_ref.close())
            )())
            app_logger.info(f"Extracted files to {deployment_folder}")
        except Exception as e:
            error_msg = f"Failed to extract zip file: {str(e)}"
            app_logger.error(error_msg, exc_info=True)
            raise HTTPException(status_code=500, detail=error_msg)
        
        # Set proper permissions
        try:
            app_logger.info(f"Setting permissions for {deployment_folder}")
            proc_chown = await asyncio.create_subprocess_exec(
                'sudo', 'chown', '-R', 'www-data:www-data', deployment_folder,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_chown, stderr_chown = await proc_chown.communicate()
            if proc_chown.returncode != 0:
                raise RuntimeError(f"chown failed: {stderr_chown.decode()}")

            proc_chmod = await asyncio.create_subprocess_exec(
                'sudo', 'chmod', '-R', '755', deployment_folder,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_chmod, stderr_chmod = await proc_chmod.communicate()
            if proc_chmod.returncode != 0:
                raise RuntimeError(f"chmod failed: {stderr_chmod.decode()}")

        except Exception as e:
            error_detail = f"Permission setup failed: {str(e)}"
            app_logger.error(error_detail)
            raise HTTPException(status_code=500, detail=error_detail)

        # Apache Configuration
        try:
            apache_port = get_available_port()
            app_logger.info(f"Configuring Apache port: {apache_port}")
            configure_apache_port(apache_port)
            
            apache_conf = create_simple_apache_config(
                domain_name,
                apache_port,
                deployment_folder
            )
            apache_conf_path = os.path.join(APACHE_CONF_DIRECTORY, f"{domain_name}.conf")
            app_logger.info(f"Creating Apache config at: {apache_conf_path}")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: open(apache_conf_path, 'w').write(apache_conf))
            
        except Exception as e:
            error_msg = f"Apache configuration failed: {str(e)}"
            app_logger.error(error_msg, exc_info=True)
            raise HTTPException(status_code=500, detail=error_msg)

        # Nginx Configuration
        try:
            app_logger.info("Ensuring Nginx includes are configured")
            _ensure_nginx_structure()
            
            sites_available = os.path.join(NGINX_CONF_DIRECTORY, "sites-available")
            sites_enabled = os.path.join(NGINX_CONF_DIRECTORY, "sites-enabled")
            app_logger.info(f"Creating sites-available and sites-enabled directories if needed")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: os.makedirs(sites_available, exist_ok=True))
            await loop.run_in_executor(None, lambda: os.makedirs(sites_enabled, exist_ok=True))

            nginx_conf = create_nginx_config(
                _vip_address, # استفاده از VIP تعیین شده
                domain_name,
                apache_port,
                deployment_folder,
                website.id
            )
            
            nginx_available_path = os.path.join(sites_available, f"{domain_name}.conf")
            app_logger.info(f"Creating Nginx config at: {nginx_available_path}")
            await loop.run_in_executor(None, lambda: open(nginx_available_path, 'w').write(nginx_conf))

            nginx_enabled_path = os.path.join(sites_enabled, f"{domain_name}.conf")
            if await loop.run_in_executor(None, lambda: os.path.exists(nginx_enabled_path)):
                app_logger.info(f"Removing existing symlink: {nginx_enabled_path}")
                await loop.run_in_executor(None, lambda: os.remove(nginx_enabled_path))
            app_logger.info(f"Creating symlink from {nginx_available_path} to {nginx_enabled_path}")
            await loop.run_in_executor(None, lambda: os.symlink(nginx_available_path, nginx_enabled_path))

        except Exception as e:
            error_detail = f"Nginx configuration failed: {str(e)}"
            app_logger.error(error_detail, exc_info=True)
            raise HTTPException(status_code=500, detail=error_detail)

        # WAF Configuration
        try:
            app_logger.info("Configuring WAF")
            waf_manager = WAFWebsiteManager(website.id)
            crs_dir = "/usr/local/nginx/rules/"
            
            if not os.path.exists(crs_dir):
                error_msg = f"CRS directory not found: {crs_dir}"
                app_logger.error(error_msg)
                raise HTTPException(status_code=500, detail=error_msg)
            
            if not os.path.exists(waf_manager.rules_dir):
                error_msg = f"WAF rules directory not found: {waf_manager.rules_dir}"
                app_logger.error(error_msg)
                raise HTTPException(status_code=500, detail=error_msg)
            
            app_logger.info(f"Copying CRS files from {crs_dir} to {waf_manager.rules_dir}")
            
            files_to_copy = []
            loop = asyncio.get_event_loop()
            for root, _, files in await loop.run_in_executor(None, lambda: os.walk(crs_dir)):
                for file in files:
                    if file.endswith(('.conf', '.data')):
                        files_to_copy.append(os.path.join(root, file))
            
            app_logger.info(f"Found {len(files_to_copy)} CRS files to copy")
            
            for source_file in files_to_copy:
                file_name_ = os.path.basename(source_file) # از file_name_ برای جلوگیری از تداخل استفاده شد
                dest_path = os.path.join(waf_manager.rules_dir, file_name_)
                
                try:
                    if not await loop.run_in_executor(None, lambda: os.access(source_file, os.R_OK)):
                        app_logger.error(f"Source file not readable: {source_file}")
                        continue
                    
                    await loop.run_in_executor(None, lambda: shutil.copy2(source_file, dest_path))
                    app_logger.debug(f"Copied CRS file: {file_name_}")
                except Exception as e:
                    app_logger.error(f"Failed to copy file {file_name_}: {str(e)}")
                    continue

            app_logger.info(f"Creating ModSecurity include file at {waf_manager.modsec_include}")
            await loop.run_in_executor(None, lambda: open(waf_manager.modsec_include, 'w').write(
                f"SecAuditEngine On\n"
                f"SecAuditLog {os.path.join(waf_manager.base_dir, 'audit.log')}\n"
                f"SecAuditLogParts ABIJDEFHZ\n"
                f"SecAuditLogType Serial\n"
                f"SecDebugLog {os.path.join(waf_manager.base_dir, 'debug.log')}\n"
                f"SecDebugLogLevel 0\n"
                f"Include {waf_manager.rules_dir}/*.conf\n"
            ))
            
            proc_chown_waf = await asyncio.create_subprocess_exec(
                'sudo', 'chown', '-R', 'www-data:www-data', waf_manager.base_dir,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_chown_waf, stderr_chown_waf = await proc_chown_waf.communicate()
            if proc_chown_waf.returncode != 0:
                raise RuntimeError(f"chown for WAF failed: {stderr_chown_waf.decode()}")

            proc_chmod_waf = await asyncio.create_subprocess_exec(
                'sudo', 'chmod', '-R', '755', waf_manager.base_dir,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_chmod_waf, stderr_chmod_waf = await proc_chmod_waf.communicate()
            if proc_chmod_waf.returncode != 0:
                raise RuntimeError(f"chmod for WAF failed: {stderr_chmod_waf.decode()}")
        
        except Exception as e:
            error_msg = f"WAF configuration failed: {str(e)}"
            app_logger.error(error_msg, exc_info=True)
            raise HTTPException(status_code=500, detail=error_msg)

        update_website_status(website_db, website.id, "Enabling Services")
        try:
            # Apache activation
            app_logger.info(f"Enabling Apache site: {os.path.basename(apache_conf_path)}")
            proc_a2ensite = await asyncio.create_subprocess_exec(
                'sudo', 'a2ensite', os.path.basename(apache_conf_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_a2ensite, stderr_a2ensite = await proc_a2ensite.communicate()
            app_logger.debug(f"a2ensite output: {stdout_a2ensite.decode()}")
            if proc_a2ensite.returncode != 0:
                error_detail = f"Apache enable failed: {stderr_a2ensite.decode()}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            app_logger.info("Testing Apache configuration")
            proc_apache_test = await asyncio.create_subprocess_exec(
                'sudo', 'apache2ctl', 'configtest',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_apache_test, stderr_apache_test = await proc_apache_test.communicate()
            app_logger.info(f"Apache configtest output: {stdout_apache_test.decode().strip()}")
            if proc_apache_test.returncode != 0:
                error_detail = f"Apache config error: {stderr_apache_test.decode()}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            app_logger.info("Reloading Apache")
            proc_apache_reload = await asyncio.create_subprocess_exec(
                'sudo', 'systemctl', 'reload', 'apache2',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_apache_reload, stderr_apache_reload = await proc_apache_reload.communicate()
            if proc_apache_reload.returncode != 0:
                error_detail = f"Apache reload failed: {stderr_apache_reload.decode()}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            # Nginx validation
            app_logger.info("Testing Nginx configuration")
            proc_nginx_test = await asyncio.create_subprocess_exec(
                NGINX_BIN, '-t',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_nginx_test, stderr_nginx_test = await proc_nginx_test.communicate()
            app_logger.info(f"Nginx test output: {stdout_nginx_test.decode().strip()}")
            if proc_nginx_test.returncode != 0:
                error_detail = f"Nginx config error: {stderr_nginx_test.decode()}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            # Improved Nginx reload handling
            app_logger.info("Ensuring Nginx is running before reload")
            await _ensure_nginx_running_async()

            app_logger.info("Reloading Nginx")
            try:
                proc_nginx_reload_soft = await asyncio.create_subprocess_exec(
                    NGINX_BIN, '-s', 'reload',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout_nginx_reload_soft, stderr_nginx_reload_soft = await proc_nginx_reload_soft.communicate()
                
                if proc_nginx_reload_soft.returncode != 0:
                    app_logger.warning("Normal Nginx reload failed, attempting full restart")
                    proc_nginx_restart = await asyncio.create_subprocess_exec(
                        'sudo', 'systemctl', 'restart', 'nginx',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout_nginx_restart, stderr_nginx_restart = await proc_nginx_restart.communicate()
                    if proc_nginx_restart.returncode != 0:
                        raise RuntimeError(f"Full Nginx restart failed: {stderr_nginx_restart.decode()}")
                    app_logger.info("Nginx restarted successfully.")
                else:
                    app_logger.info("Nginx reloaded successfully (soft reload).")

            except Exception as e:
                error_detail = f"Nginx reload/restart failed: {str(e)}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            error_detail = f"Service enabling error: {str(e)}"
            app_logger.error(error_detail, exc_info=True)
            raise HTTPException(status_code=500, detail=error_detail)

        # Finalize deployment
        app_logger.info("Finalizing deployment")
        if vip:
            vip.status = "in_use"
            vip.domain = domain_name
            vip.last_updated = datetime.utcnow()
            interface_db.commit()

        if website:
            website.listen_to = f"127.0.0.1:{apache_port}"
            website.status = "Active"
            website.mode = "enabled"
            website.waf_enabled = True
            website_db.commit()

        app_logger.info(f"Successfully deployed {domain_name} with VIP {_vip_address}")
        return {
            "status": "success",
            "domain": domain_name,
            "vip": _vip_address,
            "apache_port": apache_port,
            "deployment_folder": deployment_folder,
            "website_id": website.id,
            "waf_enabled": True,
            "rules_copied": len(glob.glob(os.path.join(waf_manager.rules_dir, "*.conf")))
        }

    except HTTPException as http_exc:
        app_logger.error(f"HTTPException during deployment: {str(http_exc.detail)}")
        await _perform_cleanup_on_failure(
            website_db, interface_db, website, vip, deployment_folder, nginx_conf_path, apache_conf_path, app_logger,
            _vip_address, _vip_netmask, _network_interface # VIP details for cleanup
        )
        raise http_exc
    except Exception as exc:
        error_detail = f"Deployment failed: {str(exc)}"
        app_logger.error(error_detail, exc_info=True)
        await _perform_cleanup_on_failure(
            website_db, interface_db, website, vip, deployment_folder, nginx_conf_path, apache_conf_path, app_logger,
            _vip_address, _vip_netmask, _network_interface # VIP details for cleanup
        )
        raise HTTPException(status_code=500, detail=error_detail)


async def _perform_cleanup_on_failure(
    website_db, interface_db, website, vip, deployment_folder, nginx_conf_path, apache_conf_path, app_logger,
    vip_address_cleanup: str = None, vip_netmask_cleanup: str = None, network_interface_cleanup: str = None
):
    app_logger.info("Starting cleanup after failed deployment")
    loop = asyncio.get_event_loop() # گرفتن loop برای اجرای همگام در executor

    # حذف فولدر دیپلوی
    if deployment_folder and await loop.run_in_executor(None, lambda: os.path.exists(deployment_folder)):
        app_logger.info(f"Removing deployment folder: {deployment_folder}")
        await loop.run_in_executor(None, lambda: shutil.rmtree(deployment_folder, ignore_errors=True))
        
    # حذف پیکربندی Nginx
    if nginx_conf_path and await loop.run_in_executor(None, lambda: os.path.exists(nginx_conf_path)):
        try:
            app_logger.info(f"Removing Nginx config: {nginx_conf_path}")
            await loop.run_in_executor(None, lambda: os.remove(nginx_conf_path))
        except Exception as e:
            app_logger.error(f"Error removing Nginx config during cleanup: {str(e)}")
            
    # حذف پیکربندی Apache
    if apache_conf_path and await loop.run_in_executor(None, lambda: os.path.exists(apache_conf_path)):
        try:
            app_logger.info(f"Disabling Apache site: {os.path.basename(apache_conf_path)}")
            proc_a2dissite = await asyncio.create_subprocess_exec(
                'sudo', 'a2dissite', os.path.basename(apache_conf_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc_a2dissite.communicate()
            
            app_logger.info(f"Removing Apache config: {apache_conf_path}")
            await loop.run_in_executor(None, lambda: os.remove(apache_conf_path))
            
            app_logger.info("Reloading Apache after cleanup")
            proc_apache_reload = await asyncio.create_subprocess_exec(
                'sudo', 'systemctl', 'reload', 'apache2',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc_apache_reload.communicate()
        except Exception as e:
            app_logger.error(f"Apache cleanup error: {str(e)}")
            
    # آزاد کردن VIP
    # استفاده از پارامترهای cleanup اگر در زمان خطا VIP مقداردهی شده باشد
    if vip_address_cleanup and vip_netmask_cleanup and network_interface_cleanup:
        try:
            app_logger.info(f"Removing IP address {vip_address_cleanup}/{vip_netmask_cleanup} from interface {network_interface_cleanup} during cleanup.")
            # استفاده از _check_and_manage_vip برای حذف IP در زمان cleanup
            await _check_and_manage_vip(vip_address_cleanup, vip_netmask_cleanup, network_interface_cleanup, "del")
            
            if vip: # اگر آبجکت VIP موجود است، وضعیت آن را در DB هم آزاد کن
                app_logger.info(f"Releasing VIP {vip.ip_address} from database during cleanup.")
                release_vip(vip.id)
        except Exception as e:
            app_logger.error(f"VIP cleanup error: {str(e)}")
            
    # اطمینان از اجرای Nginx پس از cleanup
    try:
        app_logger.info("Ensuring Nginx is running after cleanup")
        await _ensure_nginx_running_async()
    except Exception as e:
        app_logger.error(f"Failed to ensure Nginx is running during cleanup: {str(e)}")
                
    # به‌روزرسانی وضعیت وب‌سایت در دیتابیس
    if website:
        app_logger.info(f"Updating website status to failed.")
        update_website_status(website_db, website.id, f"Failed: Cleanup performed.")

def create_website_entry(db: Session, name: str, real_web_s: str):
    name_without_extension = name.split('.')[0]  
    website = Website(
        id=secrets.token_hex(8),
        name=name_without_extension,
        application=f"www.{name_without_extension}",  
        listen_to="127.0.0.1:8081",  
        real_web_s=real_web_s,
        status="Waiting for zip",
        init_status=True,
        mode="disabled"
    )
    
    db.add(website)
    db.commit()
    db.refresh(website)
    return website

def update_website_status(db: Session, website_id: str, status: str):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        return None
    
    website.status = status
    db.commit()
    db.refresh(website)
    return website

def get_website_by_name(db: Session, name: str):
    return db.query(Website).filter(Website.name == name).first()


def _configure_vip_network(vip_ip: str, netmask: str = "255.255.255.0", interface: str = "ens33"):
    try:
        # First, check if the IP is actually assigned to the interface
        result = subprocess.run(
            ['ip', '-br', 'addr', 'show', 'dev', interface],
            capture_output=True,
            text=True
        )
        
        # If IP exists but isn't properly configured
        if vip_ip in result.stdout:
            app_logger.warning(f"VIP {vip_ip} exists but may not be properly configured")
            # Remove the existing IP
            subprocess.run(
                ['sudo', 'ip', 'addr', 'del', f'{vip_ip}/{netmask}', 'dev', interface],
                check=True
            )
        
        # Configure ARP settings
        subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.conf.all.arp_ignore=1'], check=True)
        subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.conf.all.arp_announce=2'], check=True)
        
        # Add the IP address
        subprocess.run(
            ['sudo', 'ip', 'addr', 'add', f'{vip_ip}/{netmask}', 'dev', interface, 'label', f'{interface}:0'],
            check=True
        )
        
        # Verify the IP was added
        result = subprocess.run(
            ['ip', '-br', 'addr', 'show', 'dev', interface],
            capture_output=True,
            text=True
        )
        if vip_ip not in result.stdout:
            raise RuntimeError(f"Failed to assign VIP {vip_ip} to interface {interface}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        error_msg = f"VIP network configuration failed: {e.stderr.decode() if e.stderr else str(e)}"
        app_logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        app_logger.error(f"VIP network configuration error: {str(e)}", exc_info=True)
        raise RuntimeError(f"VIP network configuration failed: {str(e)}")
    
def _validate_vip_binding(vip_ip: str, port: int = 80):
    try:
        # First verify the IP is assigned
        result = subprocess.run(
            ['ip', '-br', 'addr', 'show', 'to', vip_ip],
            capture_output=True, 
            text=True
        )
        if vip_ip not in result.stdout:
            raise ValueError(f"VIP {vip_ip} not assigned to any interface")
        
        # Then check if something is listening
        result = subprocess.run(
            ['ss', '-tulnp'],
            capture_output=True,
            text=True
        )
        
        # If nothing is listening, that's okay at this stage
        if f"{vip_ip}:{port}" not in result.stdout:
            app_logger.warning(f"Nothing listening on {vip_ip}:{port} yet")
            
        return True
        
    except Exception as e:
        app_logger.error(f"VIP validation failed: {str(e)}")
        raise RuntimeError(f"VIP validation failed: {str(e)}")
    
def _update_nginx_config_with_waf(db: Session, website_id: str, domain_name: str):
    waf_manager = WAFWebsiteManager(website_id)
    config_path = os.path.join(NGINX_CONF_DIRECTORY, f"{domain_name}.conf")
    
    if not os.path.exists(config_path):
        return False
    
    with open(config_path, 'r') as f:
        config = f.read()
    
    if "modsecurity_rules_file" not in config:
        config = config.replace(
            "modsecurity on;",
            f"modsecurity on;\n    modsecurity_rules_file {waf_manager.modsec_include};"
        )
    else:
        config = config.replace(
            "modsecurity_rules_file",
            f"modsecurity_rules_file {waf_manager.modsec_include}\n    modsecurity_rules_file"
        )
    
    with open(config_path, 'w') as f:
        f.write(config)
    
    return True

async def delete_website_service(website_id: str):
    interface_db = next(get_db())
    website_db = WebsiteSessionLocal()
    
    try:
        website = website_db.query(Website).filter(Website.id == website_id).first()
        if not website:
            raise HTTPException(status_code=404, detail="Website not found")
        
        domain_name = website.name
        app_logger.info(f"Starting cleanup for {domain_name}")

        vip = interface_db.query(VirtualIP).filter(VirtualIP.domain == domain_name).first()
        
        # Cleanup paths
        deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, domain_name)
        apache_conf_path = os.path.join(APACHE_CONF_DIRECTORY, f"{domain_name}.conf")
        
        # Nginx config paths
        nginx_available = os.path.join(NGINX_CONF_DIRECTORY, "sites-available", f"{domain_name}.conf")
        nginx_enabled = os.path.join(NGINX_CONF_DIRECTORY, "sites-enabled", f"{domain_name}.conf")

        # Remove Apache config
        if os.path.exists(apache_conf_path):
            try:
                subprocess.run(['a2dissite', os.path.basename(apache_conf_path)], check=False)
                os.remove(apache_conf_path)
                subprocess.run(['systemctl', 'reload', 'apache2'], check=False)
            except Exception as e:
                app_logger.error(f"Error removing Apache config: {e}")

        try:
            if os.path.exists(nginx_enabled):
                os.remove(nginx_enabled)
            if os.path.exists(nginx_available):
                os.remove(nginx_available)
            subprocess.run([NGINX_BIN, '-s', 'reload'], check=False)
        except Exception as e:
            app_logger.error(f"Error removing Nginx config: {e}")

        if os.path.exists(deployment_folder):
            try:
                shutil.rmtree(deployment_folder)
            except Exception as e:
                app_logger.error(f"Error removing deployment folder: {e}")

        if vip:
            try:
                release_vip(vip.id)
                subprocess.run(['ip', 'addr', 'del', f'{vip.ip_address}/{vip.netmask}', 'dev', vip.interface], check=False)
            except Exception as e:
                app_logger.error(f"Error releasing VIP: {e}")

        try:
            waf_dir = f"/usr/local/nginx/website_waf/{website_id}"
            if os.path.exists(waf_dir):
                shutil.rmtree(waf_dir)
        except Exception as e:
            app_logger.error(f"Error removing WAF rules: {e}")

        website_db.delete(website)
        website_db.commit()

        return {"status": "success", "message": f"Website {domain_name} removed"}

    except Exception as e:
        website_db.rollback()
        interface_db.rollback()
        app_logger.error(f"Cleanup failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")
    
    
async def _ensure_nginx_running_async():
    try:
        # Check if Nginx is running
        proc_check = await asyncio.create_subprocess_exec(
            'pgrep', '-f', 'nginx',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc_check.communicate()
        
        # If Nginx isn't running, start it
        if proc_check.returncode != 0:
            app_logger.info("Nginx not running, attempting to start")
            proc_start = await asyncio.create_subprocess_exec(
                NGINX_BIN,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_start, stderr_start = await proc_start.communicate()
            if proc_start.returncode != 0:
                raise RuntimeError(f"Failed to start Nginx: {stderr_start.decode()}")
            app_logger.info(f"Nginx started. Output: {stdout_start.decode()}")
            await asyncio.sleep(2) # Wait a moment for Nginx to start (async version)
        
        # Ensure pid file exists and has content
        pid_file = '/usr/local/nginx/logs/nginx.pid' # این مسیر را بررسی کنید که در سرور شما صحیح باشد
        if not os.path.exists(pid_file) or os.path.getsize(pid_file) == 0:
            app_logger.info("Regenerating Nginx pid file")
            # Get the main Nginx process ID
            proc_pid = await asyncio.create_subprocess_exec(
                'pgrep', '-o', '-f', 'nginx',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_pid, stderr_pid = await proc_pid.communicate()
            if proc_pid.returncode != 0:
                raise RuntimeError(f"Failed to get Nginx PID: {stderr_pid.decode()}")
            
            # نوشتن به فایل به صورت همگام است، اما برای فایل‌های کوچک معمولاً مشکلی ایجاد نمی‌کند.
            # اگر نیاز به async I/O کامل دارید، می‌توانید از loop.run_in_executor استفاده کنید:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: open(pid_file, 'w').write(stdout_pid.decode().strip()))
        
        return True
    except Exception as e:
        app_logger.error(f"Error ensuring Nginx is running: {str(e)}", exc_info=True)
        raise RuntimeError(f"Failed to ensure Nginx is running: {str(e)}")

def update_existing_nginx_configs_with_waf():
    """Update all existing Nginx configs to use website-specific WAF rules"""
    sites_enabled = '/usr/local/nginx/conf/sites-enabled'
    if not os.path.exists(sites_enabled):
        return
    
    for config_file in os.listdir(sites_enabled):
        if not config_file.endswith('.conf'):
            continue
            
        try:
            # Extract website name from config filename
            website_name = os.path.splitext(config_file)[0]
            
            # Find website in database
            db = WebsiteSessionLocal()
            website = db.query(Website).filter(Website.name == website_name).first()
            if not website:
                continue
                
            # Get WAF manager for this website
            waf_manager = WAFWebsiteManager(website.id)
            
            # Read current config
            config_path = os.path.join(sites_enabled, config_file)
            with open(config_path, 'r') as f:
                config = f.read()
            
            # Update WAF configuration
            new_config = config.replace(
                "modsecurity_rules_file /usr/local/nginx/conf/modsec_includes.conf;",
                f"modsecurity_rules_file {waf_manager.modsec_include};"
            )
            
            # Write updated config if changed
            if new_config != config:
                with open(config_path, 'w') as f:
                    f.write(new_config)
                app_logger.info(f"Updated WAF config for {website_name}")
                
        except Exception as e:
            app_logger.error(f"Failed to update WAF config for {config_file}: {str(e)}")
