import subprocess
import os

def check_nginx_running():
    result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if 'nginx' in result.stdout.decode():
        print("NGINX is running.")
    else:
        print("NGINX is NOT running.")


def check_modsecurity_in_nginx_conf():
    config_path = "/etc/nginx/nginx.conf"
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_content = f.read()
            if 'modsec' in config_content.lower():
                print("ModSecurity is included in the NGINX configuration.")
            else:
                print("ModSecurity is NOT included in the NGINX configuration.")
    else:
        print("NGINX config file not found.")

def check_modsecurity_conf():
    modsec_config_path = "/etc/nginx/modsecurity.conf"
    if os.path.exists(modsec_config_path):
        with open(modsec_config_path, 'r') as f:
            config_content = f.read()
            if 'SecRuleEngine' in config_content:
                if 'On' in config_content:
                    print("ModSecurity is enabled.")
                else:
                    print("ModSecurity is in detection-only mode.")
            else:
                print("SecRuleEngine setting not found in ModSecurity config.")
    else:
        print("ModSecurity config file not found.")

def check_modsecurity_logs():
    log_path = "/var/log/nginx/modsec_audit.log"
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = f.read()
            if 'XSS' in logs:
                print("XSS attack detected in ModSecurity logs.")
            else:
                print("No XSS attacks found in logs.")
    else:
        print("ModSecurity logs not found.")

def main():
    print("Checking NGINX status...")
    check_nginx_running()

    print("\nChecking ModSecurity configuration...")
    check_modsecurity_in_nginx_conf()
    check_modsecurity_conf()

    print("\nChecking ModSecurity logs...")
    check_modsecurity_logs()

if __name__ == "__main__":
    main()
