from datetime import datetime, timedelta
import subprocess
import ipaddress
import os
from sqlalchemy.orm import Session
from models.interface_model import VirtualIP
from services.database.database import InterfaceSessionLocal 
from fastapi import HTTPException
from services.logger.logger_service import app_logger

NGINX_CONF_DIRECTORY = '/usr/local/nginx/conf'
NGINX_HTML_DIRECTORY = '/usr/local/nginx/html'
APACHE_CONF_DIRECTORY = '/etc/apache2/sites-available'

def get_db():
    db = InterfaceSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_server_ip():
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, check=True)
        ips = result.stdout.strip().split()
        for ip in ips:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    return ip
            except ValueError:
                continue
        raise RuntimeError("No valid IPv4 address found")
    except (subprocess.CalledProcessError, IndexError) as e:
        raise RuntimeError(f"Failed to get server IP: {str(e)}")

def calculate_netmask(ip: str):
    """Calculate proper netmask for the given IP"""
    try:
        # Try to get netmask from system first
        result = subprocess.run(
            ['ip', '-o', '-f', 'inet', 'addr', 'show'],
            capture_output=True, text=True, check=True
        )
        
        for line in result.stdout.splitlines():
            if ip in line:
                parts = line.split()
                netmask = parts[6]
                # Validate the netmask format
                try:
                    ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return netmask
                except ValueError:
                    continue
        
        # Fallback to common private network netmasks
        if ipaddress.IPv4Address(ip).is_private:
            if ip.startswith('10.'):
                return '255.0.0.0'
            elif ip.startswith('172.16.'):
                return '255.240.0.0'
            elif ip.startswith('192.168.'):
                return '255.255.255.0'
        
        # Default netmask for public IPs
        return '255.255.255.0'
        
    except Exception as e:
        app_logger.error(f"Error calculating netmask: {e}")
        return '255.255.255.0'


def create_default_vip():
    db = InterfaceSessionLocal()
    try:
        if not db.query(VirtualIP).first():
            server_ip = get_server_ip()
            netmask = calculate_netmask(server_ip)
            network = ipaddress.IPv4Network(f"{server_ip}/{netmask}", strict=False)
            
            vip_ip = str(list(network.hosts())[0]) if network.num_addresses > 2 else server_ip
            
            default_vip = VirtualIP(
                ip_address=vip_ip,
                netmask=netmask,
                interface=os.getenv("DEFAULT_INTERFACE", "ens33"),
                status="available"
            )
            
            db.add(default_vip)
            db.commit()
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"Failed to create default VIP: {str(e)}")
    finally:
        db.close()

def add_virtual_ip(ip_address: str, netmask: str, interface: str = "ens33"):
    db = InterfaceSessionLocal()
    try:
        existing_vip = db.query(VirtualIP).filter(VirtualIP.ip_address == ip_address).first()
        if existing_vip:
            raise HTTPException(status_code=400, detail="IP address already exists")
        
        new_vip = VirtualIP(
            ip_address=ip_address,
            netmask=netmask,
            interface=interface,
            status="available"
        )
        
        db.add(new_vip)
        db.commit()
        return new_vip
    finally:
        db.close()

def list_virtual_ips():
    db = InterfaceSessionLocal()
    try:
        return db.query(VirtualIP).all()
    finally:
        db.close()

def delete_virtual_ip(vip_id: int):
    db = InterfaceSessionLocal()
    try:
        vip = db.query(VirtualIP).filter(VirtualIP.id == vip_id).first()
        if not vip:
            raise HTTPException(status_code=404, detail="Virtual IP not found")
        
        if vip.status == "in_use":
            release_vip(vip_id)
        
        db.delete(vip)
        db.commit()
        return {"message": "Virtual IP permanently deleted"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")
    finally:
        db.close()

def release_vip(vip_id: int):
    db = InterfaceSessionLocal()
    try:
        vip = db.query(VirtualIP).filter(VirtualIP.id == vip_id).first()
        if not vip:
            raise HTTPException(status_code=404, detail="Virtual IP not found")
        
        if vip.status == "available":
            raise HTTPException(status_code=400, detail="VIP is already available")
        
        if vip.domain:
            domain = vip.domain
            nginx_conf = os.path.join(NGINX_CONF_DIRECTORY, f"{domain}.conf")
            if os.path.exists(nginx_conf):
                os.remove(nginx_conf)
            
            apache_conf = os.path.join(APACHE_CONF_DIRECTORY, f"{domain}.conf")
            if os.path.exists(apache_conf):
                os.remove(apache_conf)
            
            subprocess.run(f'sudo a2dissite {domain}', shell=True)
            
            deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, domain)
            subprocess.run(f'sudo rm -rf {deployment_folder}', shell=True)
            
            subprocess.run('sudo systemctl reload apache2', shell=True)
            subprocess.run('sudo /usr/local/nginx/sbin/nginx -s reload', shell=True)

        vip.status = "available"
        vip.domain = None
        db.commit()
        return {"message": "VIP released and resources cleaned"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"VIP release failed: {str(e)}")
    finally:
        db.close()

def check_vip_usage():
    db = InterfaceSessionLocal()
    try:
        total = db.query(VirtualIP).count()
        available = db.query(VirtualIP).filter(VirtualIP.status == "available").count()
        return {
            "total_vips": total,
            "available_vips": available,
            "usage_percentage": ((total - available) / total) * 100 if total > 0 else 0
        }
    finally:
        db.close()

def cleanup_stale_deployments():
    db = InterfaceSessionLocal()
    try:
        stale_days = 7  
        stale = db.query(VirtualIP).filter(
            VirtualIP.status == "in_use",
            VirtualIP.last_updated < datetime.now() - timedelta(days=stale_days)
        ).all()
        
        for vip in stale:
            release_vip(vip.id)
            
        return {"released": len(stale)}
    finally:
        db.close()