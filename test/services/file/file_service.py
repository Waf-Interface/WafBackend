import os
import zipfile
import subprocess
from fastapi import HTTPException
from services.logger.logger_service import app_logger 

UPLOAD_DIRECTORY = 'uploads'
DEPLOY_DIRECTORY = 'deploy'
NGINX_CONF_DIRECTORY = '/usr/local/nginx/conf'  
NGINX_HTML_DIRECTORY = '/usr/local/nginx/html'  
APACHE_CONF_DIRECTORY = '/etc/apache2/sites-available' 

os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
os.makedirs(DEPLOY_DIRECTORY, exist_ok=True)

async def upload_file_service(file):
    try:
        original_filename = os.path.join(UPLOAD_DIRECTORY, file.filename)
        zip_filename = f"{original_filename}.zip"

        app_logger.info(f"Starting file upload: {file.filename}")  

        with open(original_filename, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)

        if os.path.exists(zip_filename):
            raise HTTPException(status_code=400, detail="File already exists")

        app_logger.info(f"Renaming file {original_filename} to {zip_filename}")
        os.rename(original_filename, zip_filename)

        app_logger.info(f"Upload completed: {file.filename}.zip")
        return {"message": "Upload completed", "filename": f"{file.filename}.zip"}
    
    except Exception as e:
        app_logger.error(f"Error during upload: {e}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {e}")

def get_apache_log_dir():
    with open('/etc/apache2/envvars', 'r') as f:
        for line in f:
            if line.startswith('export APACHE_LOG_DIR'):
                return line.split('=')[1].strip().strip('"')
    return '/var/log/apache2'  

def get_apache_listen_info():
    try:
        result = subprocess.run(['/usr/sbin/apache2ctl', '-S'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            app_logger.error(f"Error retrieving Apache configuration: {result.stderr}")
            raise Exception("Could not retrieve Apache configuration.")

        app_logger.info(f"Apache configuration output: {result.stdout}")

        for line in result.stdout.splitlines():
            if line.startswith(" *"):
                parts = line.split()
                if len(parts) >= 4:
                    ip_port = parts[1]  
                    return ip_port.split(':')  
        app_logger.error("No valid IP and port found in Apache configuration.")
        raise Exception("No valid IP and port found.")
    except Exception as e:
        app_logger.error(f"Error getting Apache listen info: {e}")
        raise
    
async def deploy_file_service(file_name: str):
    try:
        if not file_name.endswith(".zip"):
            file_name += ".zip"

        file_path = os.path.join(UPLOAD_DIRECTORY, file_name)
        app_logger.info(f"Deploying file {file_name} from {file_path}")  

        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found in uploads folder")

        deployment_folder = os.path.join(NGINX_HTML_DIRECTORY, file_name.split(".")[0])
        os.makedirs(deployment_folder, exist_ok=True)

        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(deployment_folder)
        app_logger.info(f"Unzipped {file_name} to {deployment_folder}")

        domain_name = file_name.split(".")[0]  
        
        # Get Apache listening information
        apache_ip, apache_port = get_apache_listen_info()
        app_logger.info(f"Apache is listening on {apache_ip}:{apache_port}")

        # Nginx configuration as a reverse proxy
        nginx_conf_content = f"""
        server {{
            listen 80;
            server_name {domain_name};

            location / {{
                proxy_pass http://{apache_ip}:{apache_port};  
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            }}

            modsecurity on;
            modsecurity_rules_file /usr/local/nginx/conf/modsec_includes.conf;
        }}
        """

        nginx_conf_path = os.path.join(NGINX_CONF_DIRECTORY, f"{domain_name}.conf")
        with open(nginx_conf_path, 'w') as conf_file:
            conf_file.write(nginx_conf_content)
        app_logger.info(f"Created Nginx configuration for {domain_name}")

        apache_log_dir = get_apache_log_dir()
        app_logger.info (f"Apache log directory: {apache_log_dir}")

        apache_conf_content = f"""
        <VirtualHost *:{apache_port}>
            ServerName {domain_name}
            DocumentRoot {deployment_folder}

            <Directory {deployment_folder}>
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
            </Directory>

            ErrorLog {apache_log_dir}/{domain_name}_error.log
            CustomLog {apache_log_dir}/{domain_name}_access.log combined
        </VirtualHost>
        """

        apache_conf_path = os.path.join(APACHE_CONF_DIRECTORY, f"{domain_name}.conf")
        with open(apache_conf_path, 'w') as conf_file:
            conf_file.write(apache_conf_content)
        app_logger.info(f"Created Apache configuration for {domain_name}")

        # Check if the Apache configuration file was created successfully
        if not os.path.exists(apache_conf_path):
            app_logger.error(f"Apache configuration file was not created: {apache_conf_path}")
            raise HTTPException(status_code=500, detail="Apache configuration file was not created.")

        # Enable the new site and reload Apache
        enable_site_command = f'sudo a2ensite {domain_name}'
        app_logger.info(f"Enabling Apache site with command: {enable_site_command}")
        enable_result = subprocess.run(enable_site_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app_logger.info(f"Enable site output: {enable_result.stdout.decode()}")
        app_logger.error(f"Enable site error: {enable_result.stderr.decode()}")

        reload_apache_command = 'sudo systemctl reload apache2'
        app_logger.info(f"Reloading Apache with command: {reload_apache_command}")
        reload_result = subprocess.run(reload_apache_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app_logger.info(f"Reload Apache output: {reload_result.stdout.decode()}")
        app_logger.error(f"Reload Apache error: {reload_result.stderr.decode()}")

        reload_nginx_command = 'sudo /usr/local/nginx/sbin/nginx -s reload'
        app_logger.info(f"Reloading Nginx with command: {reload_nginx_command}")
        nginx_reload_result = subprocess.run(reload_nginx_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app_logger.info(f"Reload Nginx output: {nginx_reload_result.stdout.decode()}")
        app_logger.error(f"Reload Nginx error: {nginx_reload_result.stderr.decode()}")

        app_logger.info("Nginx reloaded successfully")

        return {"message": "Deployment completed", "file": file_name}
    except Exception as e:
        app_logger.error(f"Error during deployment: {e}")
        raise HTTPException(status_code=500, detail=f"Deployment failed: {e}") 