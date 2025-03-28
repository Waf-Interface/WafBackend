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
    """Create minimal Apache config without security headers (handled by Nginx)"""
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

def create_nginx_config(vip: str, domain: str, backend_port: int, doc_root: str):
    return f"""
server {{
    listen {vip}:80;
    server_name {domain};
    
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";
    
    modsecurity on;
    modsecurity_rules_file /usr/local/nginx/conf/modsec_includes.conf;
    
    location / {{
        root {doc_root};
        try_files $uri $uri/ /index.html;
    }}
    
    location /api/ {{
        proxy_pass http://127.0.0.1:{backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

async def deploy_file_service(file_name: str):
    interface_db = next(get_db())  
    website_db = WebsiteSessionLocal()  
    vip = None
    deployment_folder = None
    nginx_conf_path = None
    apache_conf_path = None
    
    try:
        if not file_name.lower().endswith('.zip'):
            file_name += '.zip'
        
        file_path = os.path.join(UPLOAD_DIRECTORY, file_name)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")

        server_ip = get_server_ip()
        website = create_website_entry(website_db, file_name, server_ip)
        app_logger.info(f"Created website entry with ID: {website.id}")

        update_website_status(website_db, website.id, "Acquiring VIP")

        try:
            vip = interface_db.query(VirtualIP).filter(VirtualIP.status == "available").first()
            
            if not vip:
                netmask = calculate_netmask(server_ip)
                
                try:
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                except ValueError as e:
                    app_logger.error(f"Invalid network {server_ip}/{netmask}: {e}")
                    netmask = '255.255.255.0'
                    network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
                
                hosts = list(network.hosts())
                new_ip = str(hosts[1]) if len(hosts) > 1 else str(hosts[0])
                
                existing_vip = interface_db.query(VirtualIP).filter(VirtualIP.ip_address == new_ip).first()
                if existing_vip:
                    if existing_vip.status == "in_use":
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
                
                interface_db.refresh(vip)
                
                try:
                    result = subprocess.run(
                        ['ip', 'addr', 'show', vip.interface],
                        capture_output=True, text=True
                    )
                    if vip.ip_address not in result.stdout:
                        subprocess.run([
                            'sudo', 'ip', 'addr', 'add', 
                            f'{vip.ip_address}/{vip.netmask}', 
                            'dev', vip.interface
                        ], check=True)
                except subprocess.CalledProcessError as e:
                    app_logger.warning(f"IP configuration issue: {e}")
            
            if not vip:
                update_website_status(website_db, website.id, "No VIP Available")
                raise HTTPException(status_code=503, detail="No VIP available and creation failed")
                
        except Exception as e:
            update_website_status(website_db, website.id, f"VIP Acquisition Failed: {str(e)}")
            app_logger.error(f"VIP acquisition failed: {e}")
            raise HTTPException(status_code=503, detail=f"VIP acquisition failed: {str(e)}")

        try:
            ipaddress.IPv4Address(vip.ip_address)
            network = ipaddress.IPv4Network(f"{vip.ip_address}/{vip.netmask}", strict=False)
            if not network.is_private:
                app_logger.warning(f"Using public IP address {vip.ip_address}")
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            update_website_status(website_db, website.id, "Invalid VIP Configuration")
            app_logger.error(f"Invalid VIP configuration: {e}")
            raise HTTPException(status_code=500, detail="Invalid VIP configuration")

        update_website_status(website_db, website.id, "Preparing Deployment")

        domain_name = os.path.splitext(file_name)[0]
        deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, domain_name)
        
        if os.path.exists(deployment_folder):
            shutil.rmtree(deployment_folder)
        os.makedirs(deployment_folder, exist_ok=True)

        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(deployment_folder)

        apache_port = get_available_port()
        configure_apache_port(apache_port)
        
        apache_conf = create_simple_apache_config(
            domain_name,
            apache_port,
            deployment_folder
        )
        apache_conf_path = os.path.join(APACHE_CONF_DIRECTORY, f"{domain_name}.conf")
        with open(apache_conf_path, 'w') as f:
            f.write(apache_conf)

        nginx_conf = create_nginx_config(
            vip.ip_address,
            domain_name,
            apache_port,
            deployment_folder
        )
        nginx_conf_path = os.path.join(NGINX_CONF_DIRECTORY, f"{domain_name}.conf")
        with open(nginx_conf_path, 'w') as f:
            f.write(nginx_conf)

        waf_manager = _setup_website_waf(website.id, domain_name)
        
        _update_nginx_config_with_waf(website.id, domain_name)

        update_website_status(website_db, website.id, "Enabling Services")

        try:
            subprocess.run(['sudo', 'a2ensite', os.path.basename(apache_conf_path)], check=True)
            subprocess.run(['sudo', 'apache2ctl', 'configtest'], check=True)
            subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
            
            subprocess.run(['sudo', NGINX_BIN, '-t'], check=True)
            subprocess.run(['sudo', NGINX_BIN, '-s', 'reload'], check=True)
        except subprocess.CalledProcessError as e:
            update_website_status(website_db, website.id, "Service Configuration Failed")
            raise HTTPException(
                status_code=500,
                detail=f"Service configuration failed: {e.stderr.decode() if e.stderr else str(e)}"
            )

        vip.status = "in_use"
        vip.domain = domain_name
        vip.last_updated = datetime.utcnow()
        interface_db.commit()

        website.listen_to = f"127.0.0.1:{apache_port}"
        website.status = "Active"
        website.mode = "enabled"
        website.waf_enabled = True
        website_db.commit()

        return {
            "status": "success",
            "domain": domain_name,
            "vip": vip.ip_address,
            "apache_port": apache_port,
            "deployment_folder": deployment_folder,
            "website_id": website.id,
            "waf_enabled": True
        }

    except HTTPException:
        raise  
    
    except Exception as e:
        interface_db.rollback()
        website_db.rollback()
        app_logger.error(f"Deployment failed: {str(e)}", exc_info=True)
        
        try:
            if deployment_folder and os.path.exists(deployment_folder):
                shutil.rmtree(deployment_folder)
            if nginx_conf_path and os.path.exists(nginx_conf_path):
                os.remove(nginx_conf_path)
            if apache_conf_path and os.path.exists(apache_conf_path):
                os.remove(apache_conf_path)
                subprocess.run(['sudo', 'a2dissite', os.path.basename(apache_conf_path)], check=False)
            if vip:
                try:
                    release_vip(vip.id)
                except HTTPException as e:
                    if "VIP is already available" not in str(e.detail):
                        app_logger.error(f"VIP release failed: {e}")
            if 'website' in locals():
                update_website_status(website_db, website.id, f"Failed: {str(e)}")
        except Exception as cleanup_error:
            app_logger.error(f"Cleanup failed: {cleanup_error}")
        
        raise HTTPException(
            status_code=500,
            detail=f"Deployment failed: {str(e)}"
        )
    
    finally:
        interface_db.close()
        website_db.close()

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


def _update_nginx_config_with_waf(website_id: str, domain_name: str):
    """Update Nginx config to include website-specific WAF rules"""
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

def _setup_website_waf(website_id: str, domain_name: str):
    """Setup WAF structure for new website"""
    waf_manager = WAFWebsiteManager(website_id)
    
    global_rules_dir = "/usr/local/nginx/rules/"
    for rule_file in glob.glob(os.path.join(global_rules_dir, "*.conf")):
        shutil.copy(
            rule_file,
            os.path.join(waf_manager.rules_dir, os.path.basename(rule_file)))
    
    with WebsiteSessionLocal() as db:
        website = db.query(Website).filter(Website.id == website_id).first()
        if website:
            website.modsec_audit_log = f"/var/log/modsec_audit_{domain_name}.log"
            website.modsec_debug_log = f"/var/log/modsec_debug_{domain_name}.log"
            db.commit()
    
    _update_nginx_config_with_waf(website_id, domain_name)
    
    return waf_manager

