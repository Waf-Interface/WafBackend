import os
import re
import subprocess

def colorize(text, color):
    colors = {
        'green': '\033[92m',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'reset': '\033[0m',
    }
    return f"{colors.get(color, '')}{text}{colors.get('reset', '')}"

nginx_version = "1.23.0"
modsecurity_nginx_repo = "https://github.com/owasp-modsecurity/ModSecurity-nginx.git"
owasp_crs_repo = "https://github.com/coreruleset/coreruleset.git"

def remove_existing():
    print(colorize("Removing existing Nginx installation and related configurations...", 'yellow'))

    subprocess.run(["sudo", "rm", "-rf", "/usr/local/nginx"])  
    subprocess.run(["sudo", "rm", "-rf", "/etc/nginx"])  
    subprocess.run(["sudo", "rm", "-rf", "/var/log/nginx"])  
    subprocess.run(["sudo", "rm", "-rf", "/var/run/nginx"])  
    subprocess.run(["sudo", "rm", "-rf", "/usr/local/nginx"])  

    subprocess.run(["sudo", "pkill", "nginx"])  

    subprocess.run(["sudo", "rm", "-f", "/etc/systemd/system/nginx.service"])
    subprocess.run(["sudo", "rm", "-f", "/etc/init.d/nginx"])

    subprocess.run(["sudo", "systemctl", "stop", "nginx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(colorize("Existing Nginx installation and configurations removed.", 'green'))

def install_dependencies():
    print(colorize("Installing dependencies...", 'yellow'))
    subprocess.run(["sudo", "apt-get", "update"])
    subprocess.run(["sudo", "apt-get", "install", "-y", "build-essential", "libpcre3", "libpcre3-dev", "libssl-dev", "zlib1g-dev", "git", "apache2"])

def check_apache():
    print(colorize("\nChecking Apache installation and configuration...", 'yellow'))
    
    apache_status = subprocess.run(["systemctl", "status", "apache2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if apache_status.returncode == 0:
        print(colorize("Apache service is running.", 'green'))
    else:
        print(colorize("Apache service is not running.", 'red'))
        return False

    ss_cmd = subprocess.run(["ss", "-tuln"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ss_cmd.returncode == 0:
        listen_output = ss_cmd.stdout.decode()
        apache_listen_ports = []
        for line in listen_output.splitlines():
            if 'apache2' in line or 'LISTEN' in line:  # Match lines with LISTEN or apache2
                match = re.search(r"(\S+):(\d+)", line)
                if match:
                    apache_ip = match.group(1)
                    apache_port = match.group(2)
                    apache_listen_ports.append(f"{apache_ip}:{apache_port}")
        
        if apache_listen_ports:
            print(colorize(f"Apache is listening on: {', '.join(apache_listen_ports)}.", 'green'))
            return apache_listen_ports
        else:
            print(colorize("Unable to determine Apache Listen address from socket information.", 'red'))
            return False
    else:
        print(colorize(f"Failed to retrieve Apache listen configuration: {ss_cmd.stderr.decode()}", 'red'))
        return False

    return True

def configure_nginx_as_reverse_proxy(apache_ip, apache_port):
    print(colorize("\nConfiguring Nginx as reverse proxy for Apache...", 'yellow'))

    nginx_conf_path = "/usr/local/nginx/conf/nginx.conf"
    
    with open(nginx_conf_path, "r") as nginx_conf_file:
        nginx_conf_content = nginx_conf_file.readlines()

    server_block_found = False
    location_block_found = False

    for i, line in enumerate(nginx_conf_content):
        if "server {" in line:
            server_block_found = True
            if "location / {" in nginx_conf_content[i + 1]:
                location_block_found = True
                nginx_conf_content[i + 2] = f"            proxy_pass http://{apache_ip}:{apache_port};\n"
                nginx_conf_content[i + 3] = "            proxy_set_header Host $host;\n"
                nginx_conf_content[i + 4] = "            proxy_set_header X-Real-IP $remote_addr;\n"
                nginx_conf_content[i + 5] = "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                print(colorize(f"Modified existing location block to proxy to Apache at {apache_ip}:{apache_port}.", 'green'))
                break
            else:
                for j, inner_line in enumerate(nginx_conf_content[i:]):
                    if "location / {" in inner_line:
                        location_block_found = True
                        break
                if not location_block_found:
                    nginx_conf_content.insert(i + 1, "        location / {\n")
                    nginx_conf_content.insert(i + 2, f"            proxy_pass http://{apache_ip}:{apache_port};\n")
                    nginx_conf_content.insert(i + 3, "            proxy_set_header Host $host;\n")
                    nginx_conf_content.insert(i + 4, "            proxy_set_header X-Real-IP $remote_addr;\n")
                    nginx_conf_content.insert(i + 5, "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
                    nginx_conf_content.insert(i + 6, "        }\n")
                    print(colorize(f"Nginx configured as reverse proxy to Apache at {apache_ip}:{apache_port}.", 'green'))
                    break

    if not server_block_found:
        print(colorize("No server block found in Nginx configuration. Cannot configure reverse proxy.", 'red'))
        return

    with open(nginx_conf_path, "w") as nginx_conf_file:
        nginx_conf_file.writelines(nginx_conf_content)


def create_nginx_service():
    print(colorize("\nCreating Nginx systemd service...", 'yellow'))
    service_file_content = """
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target

[Service]
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/usr/local/nginx/sbin/nginx -s stop
PIDFile=/usr/local/nginx/logs/nginx.pid
Type=forking

[Install]
WantedBy=multi-user.target
"""
    with open('/etc/systemd/system/nginx.service', 'w') as f:
        f.write(service_file_content)
    
    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    subprocess.run(["sudo", "systemctl", "enable", "nginx"])
    subprocess.run(["sudo", "systemctl", "start", "nginx"])

def install_nginx():
    print(f"Downloading Nginx {nginx_version}...")
    subprocess.run(["wget", f"http://nginx.org/download/nginx-{nginx_version}.tar.gz"])
    subprocess.run(["tar", "-xzvf", f"nginx-{nginx_version}.tar.gz"])
    os.chdir(f"nginx-{nginx_version}")
    print("Configuring Nginx with ModSecurity connector...")
    subprocess.run(["./configure", "--prefix=/usr/local/nginx", "--add-dynamic-module=../ModSecurity-nginx"])  
    print("Compiling Nginx...")
    subprocess.run(["make"])
    print("Installing Nginx...")
    subprocess.run(["sudo", "make", "install"])
    os.chdir("..")  


def install_modsecurity():
    print("Cloning ModSecurity-nginx repository...")
    subprocess.run(["git", "clone", modsecurity_nginx_repo])
    os.chdir("ModSecurity-nginx")

    print("Fetching latest release tag...")
    tags = subprocess.check_output(["git", "tag"]).decode().strip().split("\n")
    latest_tag = sorted(tags, key=lambda s: list(map(int, s.strip("v").split("."))))[-1]
    print(f"Checking out the latest version: {latest_tag}")
    
    subprocess.run(["git", "checkout", latest_tag])

    print("Configuring Nginx with ModSecurity connector...")
    os.chdir(f"../nginx-{nginx_version}")
    subprocess.run(["./configure", "--prefix=/usr/local/nginx", "--add-dynamic-module=../ModSecurity-nginx"])
    subprocess.run(["make"])
    subprocess.run(["sudo", "make", "install"])
    if not os.path.exists("/usr/local/nginx/modules/ngx_http_modsecurity_module.so"):
        print(colorize("Error: ModSecurity connector not found!", 'red'))
    else:
        print(colorize("ModSecurity connector installed successfully.", 'green'))

def install_owasp_crs():
    print(colorize("\nDownloading and Installing OWASP Core Rule Set (CRS)...", 'yellow'))
    subprocess.run(["git", "clone", owasp_crs_repo])
    os.chdir("coreruleset")
    
    print("Fetching latest CRS release tag...")
    tags = subprocess.check_output(["git", "tag"]).decode().strip().split("\n")

    numeric_tags = [tag for tag in tags if re.match(r"^v?\d+(\.\d+)+$", tag)]

    if not numeric_tags:
        print(colorize("No valid version tags found!", 'red'))
        return

    latest_crs_tag = sorted(numeric_tags, key=lambda s: list(map(int, s.strip("v").split("."))))[-1]
    print(f"Checking out the latest CRS version: {latest_crs_tag}")
    
    subprocess.run(["git", "checkout", latest_crs_tag])

    print(colorize("Configuring ModSecurity to use CRS...", 'yellow'))
    subprocess.run(["sudo", "cp", "-r", "./crs-setup.conf.example", "/usr/local/nginx/conf/"])
    subprocess.run(["sudo", "cp", "-r", "./rules/", "/usr/local/nginx/"])

    modsec_conf_path = "/usr/local/nginx/conf/modsec_includes.conf"
    with open(modsec_conf_path, "a") as modsec_conf:
        modsec_conf.write("\nInclude /usr/local/nginx/rules/*.conf")

    print(colorize("OWASP Core Rule Set (CRS) installed and configured!", 'green'))

def enable_modsecurity():
    print("Enabling ModSecurity in nginx configuration...")

    nginx_conf_path = "/usr/local/nginx/conf/nginx.conf"
    with open(nginx_conf_path, "r") as nginx_conf_file:
        nginx_conf_content = nginx_conf_file.readlines()

    if not any("load_module" in line for line in nginx_conf_content):
        nginx_conf_content.insert(0, 'load_module /usr/local/nginx/modules/ngx_http_modsecurity_module.so;\n')
    server_block_found = False
    for i, line in enumerate(nginx_conf_content):
        if "server {" in line:
            server_block_found = True
            nginx_conf_content.insert(i + 1, "    modsecurity on;\n")
            nginx_conf_content.insert(i + 2, "    modsecurity_rules_file /usr/local/nginx/conf/modsec_includes.conf;\n")
            break

    if not server_block_found:
        print("Server block not found in nginx.conf. ModSecurity could not be enabled.")
        return

    with open(nginx_conf_path, "w") as nginx_conf_file:
        nginx_conf_file.writelines(nginx_conf_content)
    
    print("Configuring ModSecurity Audit log...")
    modsec_conf_path = "/usr/local/nginx/conf/modsec_includes.conf"
    
    with open(modsec_conf_path, "a") as modsec_conf_file:
        modsec_conf_file.write("""
# ModSecurity Audit Log configuration
SecAuditEngine On
SecAuditLog /var/log/modsec_audit.log
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
""")
    
    print("ModSecurity enabled and audit logging configured successfully.")


def grant_permision():
    return 
def test_installation():
    print(colorize("\nTesting the Nginx & ModSecurity Installation...", 'green'))

    print(colorize("\n1. Testing Nginx configuration...", 'yellow'))
    result = subprocess.run(["sudo", "/usr/local/nginx/sbin/nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(colorize("Nginx configuration test PASSED", 'green'))
    else:
        print(colorize(f"Nginx configuration test FAILED: {result.stderr.decode()}", 'red'))

    print(colorize("\n2. Checking Nginx service status...", 'yellow'))
    result = subprocess.run(["sudo", "systemctl", "status", "nginx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(colorize("Nginx service is running", 'green'))
    else:
        print(colorize("Nginx service is not running", 'red'))

    print(colorize("\n3. Testing ModSecurity status...", 'yellow'))
    result = subprocess.run(["curl", "http://localhost"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "Welcome to nginx!" in result.stdout.decode():
        print(colorize("ModSecurity is likely not blocking anything yet.", 'red'))
    else:
        print(colorize("ModSecurity might be blocking requests.", 'green'))


def setup_modsecurity_config():
    print(colorize("\nSetting up ModSecurity configuration file...", 'yellow'))
    
    config_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended"
    config_path = "/usr/local/nginx/conf/modsecurity.conf"
    
    try:
        os.makedirs("/usr/local/nginx/conf", exist_ok=True)
        
        print("Downloading modsecurity.conf-recommended...")
        subprocess.run(["wget", "-O", "/tmp/modsecurity.conf-recommended", config_url], check=True)
        
        print("Moving to correct location...")
        subprocess.run(["sudo", "mv", "/tmp/modsecurity.conf-recommended", config_path], check=True)
        
        subprocess.run(["sudo", "chmod", "644", config_path], check=True)
        
        includes_path = "/usr/local/nginx/conf/modsec_includes.conf"
        with open(includes_path, "a") as f:
            f.write("\nInclude /usr/local/nginx/conf/modsecurity.conf\n")
        
        print(colorize("ModSecurity configuration file setup complete!", 'green'))
        return True
        
    except subprocess.CalledProcessError as e:
        print(colorize(f"Failed to setup ModSecurity config: {str(e)}", 'red'))
        return False
    except Exception as e:
        print(colorize(f"Error setting up ModSecurity config: {str(e)}", 'red'))
        return False
def setup_unicode_mapping():
    print(colorize("\nSetting up Unicode mapping file for ModSecurity...", 'yellow'))
    
    unicode_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/49495f1925a14f74f93cb0ef01172e5abc3e4c55/unicode.mapping"
    mapping_path = "/usr/local/nginx/conf/unicode.mapping"
    
    try:
        os.makedirs("/usr/local/nginx/conf", exist_ok=True)
        
        print("Downloading unicode.mapping...")
        subprocess.run(["wget", "-O", "/tmp/unicode.mapping", unicode_url], check=True)
        
        print("Moving to correct location...")
        subprocess.run(["sudo", "mv", "/tmp/unicode.mapping", mapping_path], check=True)
        
        subprocess.run(["sudo", "chmod", "644", mapping_path], check=True)
        
        print(colorize("Unicode mapping file setup complete!", 'green'))
        return True
        
    except subprocess.CalledProcessError as e:
        print(colorize(f"Failed to setup Unicode mapping file: {str(e)}", 'red'))
        return False
    except Exception as e:
        print(colorize(f"Error setting up Unicode mapping file: {str(e)}", 'red'))
        return False
def configure_crs_setup():
    print(colorize("\nConfiguring CRS setup file...", 'yellow'))
    
    try:
        crs_setup_example = "/usr/local/nginx/conf/crs-setup.conf.example"
        crs_setup_active = "/usr/local/nginx/conf/crs-setup.conf"
        crs_setup_url = "https://raw.githubusercontent.com/coreruleset/coreruleset/main/crs-setup.conf.example"
        
        if not os.path.exists(crs_setup_example):
            print(colorize("crs-setup.conf.example not found, downloading from GitHub...", 'yellow'))
            try:
                subprocess.run([
                    "sudo", "wget", "-O", crs_setup_example, 
                    crs_setup_url
                ], check=True)
                print(colorize("Successfully downloaded crs-setup.conf.example", 'green'))
            except subprocess.CalledProcessError as e:
                print(colorize(f"Failed to download crs-setup.conf.example: {str(e)}", 'red'))
                return False
        
        # Copy the example file to active configuration
        if os.path.exists(crs_setup_example):
            subprocess.run(["sudo", "cp", crs_setup_example, crs_setup_active], check=True)
            print(colorize("Copied crs-setup.conf.example to crs-setup.conf", 'green'))
        else:
            print(colorize("Failed to obtain crs-setup.conf.example", 'red'))
            return False
        
        # Add include to modsec_includes.conf
        modsec_includes_path = "/usr/local/nginx/conf/modsec_includes.conf"
        include_line = "Include /usr/local/nginx/conf/crs-setup.conf\n"
        
        # Check if the include already exists
        if os.path.exists(modsec_includes_path):
            with open(modsec_includes_path, 'r') as f:
                if include_line in f.read():
                    print(colorize("CRS setup already included in modsec_includes.conf", 'yellow'))
                    return True
        
        # Add the include line
        with open(modsec_includes_path, 'a') as f:
            f.write(include_line)
        
        print(colorize("Added CRS setup include to modsec_includes.conf", 'green'))
        return True
        
    except subprocess.CalledProcessError as e:
        print(colorize(f"Failed to configure CRS setup: {str(e)}", 'red'))
        return False
    except Exception as e:
        print(colorize(f"Error configuring CRS setup: {str(e)}", 'red'))
        return False
def main():
    os.chdir("/tmp")
    
    if not check_apache():  
        return

    remove_existing()  

    install_dependencies()  
    install_nginx()  
    install_modsecurity()  
    install_owasp_crs() 

    enable_modsecurity()
    setup_modsecurity_config()
    setup_unicode_mapping()
    configure_crs_setup()  
    
    apache_listen_ports = check_apache()
    if apache_listen_ports:
        apache_ip, apache_port = apache_listen_ports[0].split(":")
        configure_nginx_as_reverse_proxy(apache_ip, apache_port) 
    else:
        print(colorize("Apache is not running or misconfigured. Cannot proceed.", 'red'))
        return
    
    print(colorize("Installation completed successfully!", 'green'))
    create_nginx_service()
    test_installation()


if __name__ == "__main__":
    main()
