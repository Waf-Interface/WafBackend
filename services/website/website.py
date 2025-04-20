from datetime import datetime
import glob
import ipaddress
import os
import secrets
import socket
import zipfile
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
APACHE_CONF_DIRECTORY = '/etc/apache2/sites-available'
APACHE_PORTS_FILE = '/etc/apache2/ports.conf'
DEFAULT_PORT = 8080

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

def get_available_port():
    port = DEFAULT_PORT
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except socket.error:
                port += 1
    raise HTTPException(status_code=500, detail="No available ports found")

def configure_apache_port(port: int):
    try:
        with open(APACHE_PORTS_FILE, 'r') as f:
            if f"Listen {port}" in f.read():
                return port
        
        with open(APACHE_PORTS_FILE, 'a') as f:
            f.write(f"\nListen {port}\n")
        
        subprocess.run(['sudo', 'apache2ctl', 'configtest'], check=True)
        subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
        return port
    except subprocess.CalledProcessError as e:
        app_logger.error(f"Apache configuration failed: {e.stderr.decode() if e.stderr else str(e)}")
        raise HTTPException(status_code=500, detail="Apache port configuration failed")
    except Exception as e:
        app_logger.error(f"Error configuring Apache: {e}")
        raise HTTPException(status_code=500, detail="Apache configuration error")

def create_simple_apache_config(domain: str, port: int, doc_root: str):
    return f"""
<VirtualHost 127.0.0.1:{port}>
    ServerName {domain}
    DocumentRoot {doc_root}
    
    <Directory {doc_root}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${{APACHE_LOG_DIR}}/{domain}_error.log
    CustomLog ${{APACHE_LOG_DIR}}/{domain}_access.log combined
</VirtualHost>
"""

def create_nginx_config(vip: str, domain: str, backend_port: int, doc_root: str, website_id: str = None):
    """
    Creates proper Nginx configuration for a website with VIP listening
    Includes website-specific WAF configuration when website_id is provided
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
    server_name {domain};
    
    root {doc_root};
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    {waf_config}
    location / {{
        try_files $uri $uri/ /index.html;
    }}
    
    location /api/ {{
        proxy_pass http://127.0.0.1:{backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
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
    """Ensures nginx.conf has proper http block structure with includes"""
    nginx_conf_path = '/usr/local/nginx/conf/nginx.conf'
    include_line = 'include /usr/local/nginx/conf/sites-enabled/*.conf;'
    
    try:
        # Create required directories if they don't exist
        os.makedirs('/usr/local/nginx/conf/sites-available', exist_ok=True)
        os.makedirs('/usr/local/nginx/conf/sites-enabled', exist_ok=True)
        
        # Read current config
        with open(nginx_conf_path, 'r') as f:
            config_lines = f.readlines()
        
        # If config is empty, create a basic one
        if not config_lines:
            config_lines = [
                "user www-data;\n",
                "worker_processes auto;\n",
                "pid /run/nginx.pid;\n\n",
                "events {\n",
                "    worker_connections 768;\n",
                "}\n\n",
                "http {\n",
                "    include /etc/nginx/mime.types;\n",
                "    default_type application/octet-stream;\n\n",
                "    access_log /var/log/nginx/access.log;\n",
                "    error_log /var/log/nginx/error.log;\n\n",
                "    sendfile on;\n",
                "    keepalive_timeout 65;\n\n",
                f"    {include_line}\n",
                "}\n"
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
                        config_lines.insert(i+1, f"    {include_line}\n")
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
                    continue  # Skip bad includes
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

async def deploy_file_service(file_name: str):
    interface_db = next(get_db())  
    website_db = WebsiteSessionLocal()  
    vip = None
    deployment_folder = None
    nginx_conf_path = None
    apache_conf_path = None
    website = None
    
    def _ensure_nginx_running():
        """Ensure Nginx is running and has a valid pid file"""
        try:
            # Check if Nginx is running
            result = subprocess.run(
                ['pgrep', '-f', 'nginx'],
                capture_output=True,
                text=True
            )
            
            # If Nginx isn't running, start it
            if result.returncode != 0:
                app_logger.info("Nginx not running, attempting to start")
                subprocess.run([NGINX_BIN], check=True)
                # Wait a moment for Nginx to start
                import time
                time.sleep(2)
            
            # Ensure pid file exists and has content
            pid_file = '/usr/local/nginx/logs/nginx.pid'
            if not os.path.exists(pid_file) or os.path.getsize(pid_file) == 0:
                app_logger.info("Regenerating Nginx pid file")
                # Get the main Nginx process ID
                result = subprocess.run(
                    ['pgrep', '-o', '-f', 'nginx'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                with open(pid_file, 'w') as f:
                    f.write(result.stdout.strip())
            
            return True
        except subprocess.CalledProcessError as e:
            app_logger.error(f"Failed to ensure Nginx is running: {e.stderr}")
            raise RuntimeError(f"Nginx process management failed: {e.stderr}")
        except Exception as e:
            app_logger.error(f"Error ensuring Nginx is running: {str(e)}")
            raise RuntimeError(f"Failed to ensure Nginx is running: {str(e)}")

    try:
        app_logger.info(f"Starting deployment for file: {file_name}")
        
        # Validate existing configs before proceeding
        app_logger.info("Validating existing Nginx configuration")
        _validate_existing_configs()
        
        # Ensure Nginx is running properly before starting
        app_logger.info("Ensuring Nginx service is ready")
        _ensure_nginx_running()
        
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
            raise

        # VIP Acquisition and Configuration
        try:
            app_logger.info("Checking for available VIP")
            vip = interface_db.query(VirtualIP).filter(VirtualIP.status == "available").first()
            
            if not vip:
                app_logger.info("No available VIP found, creating new one")
                netmask = calculate_netmask(server_ip)
                
                try:
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                except ValueError as e:
                    app_logger.error(f"Invalid network {server_ip}/{netmask}: {e}")
                    netmask = '255.255.255.0'
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                
                hosts = list(network.hosts())
                # Try the last available IP first
                new_ip = str(hosts[-1])
                
                # Check if this IP is actually available
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.bind((new_ip, 80))
                        s.close()
                except socket.error:
                    app_logger.warning(f"IP {new_ip} appears to be in use, trying next")
                    new_ip = str(hosts[-2]) if len(hosts) > 1 else str(hosts[0])
                
                existing_vip = interface_db.query(VirtualIP).filter(VirtualIP.ip_address == new_ip).first()
                if existing_vip:
                    if existing_vip.status == "in_use":
                        app_logger.info(f"Releasing in-use VIP {existing_vip.ip_address}")
                        release_vip(existing_vip.id)
                    vip = existing_vip
                else:
                    vip = VirtualIP(
                        ip_address=new_ip,
                        netmask=netmask,
                        interface=os.getenv("DEFAULT_INTERFACE", "ens33"),
                        status="available"
                    )
                    interface_db.add(vip)
                    interface_db.commit()
                    app_logger.info(f"Created new VIP: {vip.ip_address}")
                
                interface_db.refresh(vip)

            # Now configure the VIP
            app_logger.info(f"Configuring VIP network for {vip.ip_address}")
            _configure_vip_network(vip.ip_address, vip.netmask, vip.interface)
            _validate_vip_binding(vip.ip_address)
            app_logger.info("Killing any processes using port 80")
            subprocess.run(['fuser', '-k', '80/tcp'], stderr=subprocess.DEVNULL)

            if not vip:
                error_msg = "No VIP available and creation failed"
                update_website_status(website_db, website.id, "No VIP Available")
                app_logger.error(error_msg)
                raise HTTPException(status_code=503, detail=error_msg)
                
        except Exception as e:
            error_msg = f"VIP acquisition failed: {str(e)}"
            update_website_status(website_db, website.id, f"VIP Acquisition Failed: {str(e)}")
            app_logger.error(error_msg, exc_info=True)
            raise HTTPException(status_code=503, detail=error_msg)

        # Deployment Preparation
        update_website_status(website_db, website.id, "Preparing Deployment")
        domain_name = os.path.splitext(file_name)[0]
        deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, domain_name)
        app_logger.info(f"Setting up deployment folder at: {deployment_folder}")
        
        # Clean and create deployment directory
        if os.path.exists(deployment_folder):
            app_logger.info(f"Removing existing deployment folder: {deployment_folder}")
            shutil.rmtree(deployment_folder)
        
        app_logger.info(f"Creating new deployment folder: {deployment_folder}")
        os.makedirs(deployment_folder, exist_ok=True)

        # Extract files and set permissions
        app_logger.info(f"Extracting zip file: {file_path}")
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(deployment_folder)
            app_logger.info(f"Extracted {len(zip_ref.filelist)} files to {deployment_folder}")
        except Exception as e:
            error_msg = f"Failed to extract zip file: {str(e)}"
            app_logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg)
        
        # Set proper permissions
        try:
            app_logger.info(f"Setting permissions for {deployment_folder}")
            subprocess.run(['sudo', 'chown', '-R', 'www-data:www-data', deployment_folder], check=True)
            subprocess.run(['sudo', 'chmod', '-R', '755', deployment_folder], check=True)
        except subprocess.CalledProcessError as e:
            error_detail = f"Permission setup failed: {e.stderr.decode()}"
            app_logger.error(error_detail)
            raise RuntimeError(error_detail)

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
            with open(apache_conf_path, 'w') as f:
                f.write(apache_conf)
        except Exception as e:
            error_msg = f"Apache configuration failed: {str(e)}"
            app_logger.error(error_msg, exc_info=True)
            raise

        # Nginx Configuration
        try:
            app_logger.info("Ensuring Nginx includes are configured")
            _ensure_nginx_structure()
            
            sites_available = os.path.join(NGINX_CONF_DIRECTORY, "sites-available")
            sites_enabled = os.path.join(NGINX_CONF_DIRECTORY, "sites-enabled")
            app_logger.info(f"Creating sites-available and sites-enabled directories if needed")
            os.makedirs(sites_available, exist_ok=True)
            os.makedirs(sites_enabled, exist_ok=True)

            nginx_conf = create_nginx_config(
                vip.ip_address,
                domain_name,
                apache_port,
                deployment_folder,
                website.id  # Pass website ID for WAF config
            )
            
            nginx_available_path = os.path.join(sites_available, f"{domain_name}.conf")
            app_logger.info(f"Creating Nginx config at: {nginx_available_path}")
            with open(nginx_available_path, 'w') as f:
                f.write(nginx_conf)

            nginx_enabled_path = os.path.join(sites_enabled, f"{domain_name}.conf")
            if os.path.exists(nginx_enabled_path):
                app_logger.info(f"Removing existing symlink: {nginx_enabled_path}")
                os.remove(nginx_enabled_path)
            app_logger.info(f"Creating symlink from {nginx_available_path} to {nginx_enabled_path}")
            os.symlink(nginx_available_path, nginx_enabled_path)

        except Exception as e:
            error_detail = f"Nginx configuration failed: {str(e)}"
            app_logger.error(error_detail, exc_info=True)
            raise

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
        
        # Copy ALL CRS files (both .conf and .data)
         app_logger.info(f"Copying CRS files from {crs_dir} to {waf_manager.rules_dir}")
        
        # Create list of all files to copy
         files_to_copy = []
         for root, _, files in os.walk(crs_dir):
             for file in files:
                 if file.endswith(('.conf', '.data')):
                     files_to_copy.append(os.path.join(root, file))
        
         app_logger.info(f"Found {len(files_to_copy)} CRS files to copy")
        
         for source_file in files_to_copy:
             file_name = os.path.basename(source_file)
             dest_path = os.path.join(waf_manager.rules_dir, file_name)
            
             try:
                 if not os.access(source_file, os.R_OK):
                     app_logger.error(f"Source file not readable: {source_file}")
                     continue
                 
                 shutil.copy2(source_file, dest_path)
                 app_logger.debug(f"Copied CRS file: {file_name}")
             except Exception as e:
                 app_logger.error(f"Failed to copy file {file_name}: {str(e)}")
                 continue

         app_logger.info(f"Creating ModSecurity include file at {waf_manager.modsec_include}")
         with open(waf_manager.modsec_include, 'w') as f:
             f.write(
                 f"SecAuditEngine On\n"
                 f"SecAuditLog {os.path.join(waf_manager.base_dir, 'audit.log')}\n"
                 f"SecAuditLogParts ABIJDEFHZ\n"
                 f"SecAuditLogType Serial\n"
                 f"SecDebugLog {os.path.join(waf_manager.base_dir, 'debug.log')}\n"
                 f"SecDebugLogLevel 0\n"
                 f"Include {waf_manager.rules_dir}/*.conf\n"
             )
        
         subprocess.run(['sudo', 'chown', '-R', 'www-data:www-data', waf_manager.base_dir], check=True)
         subprocess.run(['sudo', 'chmod', '-R', '755', waf_manager.base_dir], check=True)
        
        except Exception as e:
         error_msg = f"WAF configuration failed: {str(e)}"
         app_logger.error(error_msg, exc_info=True)
         raise

        update_website_status(website_db, website.id, "Enabling Services")
        try:
            # Apache activation
            app_logger.info(f"Enabling Apache site: {os.path.basename(apache_conf_path)}")
            a2ensite_result = subprocess.run(
                ['sudo', 'a2ensite', os.path.basename(apache_conf_path)], 
                capture_output=True,
                text=True
            )
            app_logger.debug(f"a2ensite output: {a2ensite_result.stdout}")
            if a2ensite_result.returncode != 0:
                error_detail = f"Apache enable failed: {a2ensite_result.stderr}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            app_logger.info("Testing Apache configuration")
            apache_test = subprocess.run(
                ['sudo', 'apache2ctl', 'configtest'], 
                capture_output=True,
                text=True
            )
            app_logger.info(f"Apache configtest output: {apache_test.stdout.strip()}")
            if apache_test.returncode != 0:
                error_detail = f"Apache config error: {apache_test.stderr}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            app_logger.info("Reloading Apache")
            apache_reload = subprocess.run(
                ['sudo', 'systemctl', 'reload', 'apache2'],
                capture_output=True,
                text=True
            )
            if apache_reload.returncode != 0:
                error_detail = f"Apache reload failed: {apache_reload.stderr}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            # Nginx validation
            app_logger.info("Testing Nginx configuration")
            nginx_test = subprocess.run(
                [NGINX_BIN, '-t'],
                capture_output=True,
                text=True
            )
            app_logger.info(f"Nginx test output: {nginx_test.stdout.strip()}")
            if nginx_test.returncode != 0:
                error_detail = f"Nginx config error: {nginx_test.stderr}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

            # Improved Nginx reload handling
            app_logger.info("Ensuring Nginx is running before reload")
            _ensure_nginx_running()

            app_logger.info("Reloading Nginx")
            try:
                # First try normal reload
                nginx_reload = subprocess.run(
                    [NGINX_BIN, '-s', 'reload'],
                    capture_output=True,
                    text=True
                )
                if nginx_reload.returncode != 0:
                    app_logger.warning("Normal reload failed, attempting full restart")
                    # If reload fails, try full restart
                    subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], check=True)
            except subprocess.CalledProcessError as e:
                error_detail = f"Nginx reload failed: {e.stderr.decode() if e.stderr else str(e)}"
                app_logger.error(error_detail)
                raise RuntimeError(error_detail)

        except subprocess.CalledProcessError as e:
            error_detail = f"Service error: {e.stderr.decode() if e.stderr else str(e)}"
            app_logger.error(error_detail)
            raise HTTPException(status_code=500, detail=error_detail)

        # Finalize deployment
        app_logger.info("Finalizing deployment")
        vip.status = "in_use"
        vip.domain = domain_name
        vip.last_updated = datetime.utcnow()
        interface_db.commit()

        website.listen_to = f"127.0.0.1:{apache_port}"
        website.status = "Active"
        website.mode = "enabled"
        website.waf_enabled = True
        website_db.commit()

        app_logger.info(f"Successfully deployed {domain_name} with VIP {vip.ip_address}")
        return {
            "status": "success",
            "domain": domain_name,
            "vip": vip.ip_address,
            "apache_port": apache_port,
            "deployment_folder": deployment_folder,
            "website_id": website.id,
            "waf_enabled": True,
            "rules_copied": len(glob.glob(os.path.join(waf_manager.rules_dir, "*.conf")))
        }

    except HTTPException as http_exc:
        app_logger.error(f"HTTPException during deployment: {str(http_exc.detail)}")
        raise http_exc
    except Exception as exc:
        error_detail = f"Deployment failed: {str(exc)}"
        app_logger.error(error_detail, exc_info=True)
        
        try:
            app_logger.info("Starting cleanup after failed deployment")
            if deployment_folder and os.path.exists(deployment_folder):
                app_logger.info(f"Removing deployment folder: {deployment_folder}")
                shutil.rmtree(deployment_folder, ignore_errors=True)
                
            if nginx_conf_path and os.path.exists(nginx_conf_path):
                try:
                    app_logger.info(f"Removing Nginx config: {nginx_conf_path}")
                    os.remove(nginx_conf_path)
                except Exception as e:
                    app_logger.error(f"Error removing Nginx config: {str(e)}")
                    
            if apache_conf_path and os.path.exists(apache_conf_path):
                try:
                    app_logger.info(f"Disabling Apache site: {os.path.basename(apache_conf_path)}")
                    a2dissite_result = subprocess.run(
                        ['sudo', 'a2dissite', os.path.basename(apache_conf_path)], 
                        capture_output=True,
                        text=True
                    )
                    if a2dissite_result.returncode != 0:
                        app_logger.error(f"a2dissite failed: {a2dissite_result.stderr}")
                    app_logger.info(f"Removing Apache config: {apache_conf_path}")
                    os.remove(apache_conf_path)
                    app_logger.info("Reloading Apache after cleanup")
                    apache_reload = subprocess.run(
                        ['sudo', 'systemctl', 'reload', 'apache2'],
                        capture_output=True,
                        text=True
                    )
                    if apache_reload.returncode != 0:
                        app_logger.error(f"Apache reload failed during cleanup: {apache_reload.stderr}")
                except Exception as e:
                    app_logger.error(f"Apache cleanup error: {str(e)}")
                    
            if vip:
                try:
                    app_logger.info(f"Releasing VIP: {vip.ip_address}")
                    release_vip(vip.id)
                    app_logger.info(f"Removing IP address {vip.ip_address}/{vip.netmask}")
                    ip_del_result = subprocess.run(
                        ['sudo', 'ip', 'addr', 'del', f'{vip.ip_address}/{vip.netmask}', 'dev', vip.interface],
                        capture_output=True,
                        text=True
                    )
                    if ip_del_result.returncode != 0:
                        app_logger.error(f"IP deletion failed: {ip_del_result.stderr}")
                except Exception as e:
                    app_logger.error(f"VIP cleanup error: {str(e)}")
                    
            # Ensure Nginx is running after cleanup
            try:
                app_logger.info("Ensuring Nginx is running after cleanup")
                _ensure_nginx_running()
            except Exception as e:
                app_logger.error(f"Failed to ensure Nginx is running during cleanup: {str(e)}")
                    
            if website:
                app_logger.info(f"Updating website status to failed: {str(exc)}")
                update_website_status(website_db, website.id, f"Failed: {str(exc)}")
                
        except Exception as cleanup_error:
            app_logger.error(f"Cleanup failed: {cleanup_error}", exc_info=True)

        raise HTTPException(status_code=500, detail=error_detail)

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
            f"modsecurity on;\n    modsecurity_rules_file {waf_manager.modsec_include};"
        )
    else:
        config = config.replace(
            "modsecurity_rules_file",
            f"modsecurity_rules_file {waf_manager.modsec_include}\n    modsecurity_rules_file"
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
    
    
def _ensure_nginx_running():
    try:
        result = subprocess.run(
            ['pgrep', '-f', 'nginx'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            app_logger.info("Nginx not running, attempting to start")
            subprocess.run([NGINX_BIN], check=True)
            import time
            time.sleep(2)
        
        pid_file = '/usr/local/nginx/logs/nginx.pid'
        if not os.path.exists(pid_file) or os.path.getsize(pid_file) == 0:
            app_logger.info("Regenerating Nginx pid file")
            result = subprocess.run(
                ['pgrep', '-o', '-f', 'nginx'],
                capture_output=True,
                text=True,
                check=True
            )
            with open(pid_file, 'w') as f:
                f.write(result.stdout.strip())
        
        return True
    except subprocess.CalledProcessError as e:
        app_logger.error(f"Failed to ensure Nginx is running: {e.stderr}")
        raise RuntimeError(f"Nginx process management failed: {e.stderr}")
    except Exception as e:
        app_logger.error(f"Error ensuring Nginx is running: {str(e)}")
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