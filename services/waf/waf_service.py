import os
import re
import json
import subprocess
from datetime import datetime, timedelta
import logging
from fastapi import HTTPException

USER_ACCESS_LOG_FILE = "user_access.log"
logging.basicConfig(filename=USER_ACCESS_LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(message)s')

NGINX_CONFIG_PATH = "/etc/nginx/nginx.conf"
MODSECURITY_CONFIG_PATH = "/etc/nginx/modsecurity.conf"
MODSEC_AUDIT_LOG_PATH = "/var/log/modsec_audit.log"
MODSEC_RULES_DIR = "/usr/local/nginx/rules"

class WAF:
    def __init__(self):
        print("WAF initialized successfully (Python native)!")
        self.host_protection_map = {}

    def _update_config_file(self, file_path, search_pattern, enable_line, disable_line, enable, append_if_not_found=False):
        """
        Helper function to safely update configuration files.
        Addresses the bug of incorrect line modification/deletion.
        The 'enable' parameter now explicitly controls which line to write.
        """
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()

            new_lines = []
            modified = False
            target_line = enable_line if enable else disable_line

            for line in lines:
                if re.search(search_pattern, line, re.IGNORECASE):
                    if target_line in line and line.strip().startswith(target_line):
                        new_lines.append(line) 
                    else:
                        new_lines.append(target_line + '\n')
                        modified = True
                else:
                    new_lines.append(line)

            if not modified and append_if_not_found:
                new_lines.append(target_line + '\n')
                modified = True

            temp_file_path = file_path + ".temp"
            with open(temp_file_path, 'w') as f:
                f.writelines(new_lines)

            os.replace(temp_file_path, file_path)
            return True, modified
        except Exception as e:
            print(f"Error updating config file {file_path}: {e}")
            return False, False

    def _check_modsecurity_in_nginx_conf(self):
        """Checks if ModSecurity is included in the Nginx configuration."""
        try:
            with open(NGINX_CONFIG_PATH, 'r') as f:
                for line in f:
                    if re.search(r'modsecurity\s+(on|off)\s*;', line, re.IGNORECASE):
                        print("ModSecurity is included in the NGINX configuration.")
                        return True
            print("ModSecurity is NOT included in the NGINX configuration.")
            return False
        except FileNotFoundError:
            print(f"NGINX config file not found: {NGINX_CONFIG_PATH}")
            return False
        except Exception as e:
            print(f"Error checking Nginx config: {e}")
            return False

    def _check_modsecurity_conf(self):
        """Checks if SecRuleEngine is On in modsecurity.conf."""
        try:
            with open(MODSECURITY_CONFIG_PATH, 'r') as f:
                is_sec_rule_engine_found = False
                for line in f:
                    if re.search(r'SecRuleEngine\s+(On|Off|DetectionOnly)', line):
                        is_sec_rule_engine_found = True
                        if re.search(r'SecRuleEngine\s+On', line):
                            print("ModSecurity is enabled.")
                            return True
                        elif re.search(r'SecRuleEngine\s+DetectionOnly', line):
                            print("ModSecurity is in detection-only mode.")
                            return False # Or handle as a specific state if needed
                if not is_sec_rule_engine_found:
                    print("SecRuleEngine setting not found in ModSecurity config.")
                return False
        except FileNotFoundError:
            print(f"ModSecurity config file not found: {MODSECURITY_CONFIG_PATH}")
            return False
        except Exception as e:
            print(f"Error checking ModSecurity config: {e}")
            return False

    def is_mod_security_enabled(self):
        """Checks if ModSecurity is enabled by looking at both Nginx and ModSecurity config files."""
        is_modsecurity_included = self._check_modsecurity_in_nginx_conf()
        is_modsecurity_enabled_in_config = self._check_modsecurity_conf()
        return is_modsecurity_included and is_modsecurity_enabled_in_config

    def check_waf_enabled(self):
        return self.is_mod_security_enabled()

    def load_rule(self, rule_content, rule_title="custom_rule"):
        """
        Loads a rule by writing it to a file and suggesting Nginx reload.
        Since there's no direct ModSecurity API binding, "loading" means
        making the rule available in the file system for ModSecurity to pick up.
        """
        if not self.check_waf_enabled():
            raise HTTPException(status_code=400, detail="WAF is offline. Please enable ModSecurity first.")

        # Determine a unique filename for the rule
        file_path = os.path.join(MODSEC_RULES_DIR, f"{rule_title}.conf")
        if os.path.exists(file_path):
            # Append a timestamp or counter to make it unique if the title exists
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            file_path = os.path.join(MODSEC_RULES_DIR, f"{rule_title}_{timestamp}.conf")

        try:
            os.makedirs(MODSEC_RULES_DIR, exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(rule_content)
            print(f"Rule saved to {file_path}. Please reload Nginx for changes to take effect.")
            # For this implementation, we just save the file. Actual loading requires Nginx reload.
            # You might want to automatically reload Nginx here if appropriate for your system.
            # self._reload_nginx()
            return True
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save rule: {e}")

    def authenticate(self, username, password):
        # This authentication is still hardcoded as in the C++ example
        return username == "test" and password == "test"

    def shutdown(self):
        print("WAF shutdown (Python native) - no active components to unload.")

    def _reload_nginx(self):
        """Reloads Nginx configuration."""
        try:
            print("Attempting to reload Nginx...")
            result = subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True, capture_output=True, text=True)
            print(f"Nginx reload stdout: {result.stdout}")
            if result.stderr:
                print(f"Nginx reload stderr: {result.stderr}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to reload Nginx. Exit code: {e.returncode}, Error: {e.stderr}")
            return False
        except FileNotFoundError:
            print("Error: 'sudo' or 'systemctl' command not found. Ensure Nginx is installed and systemctl is available.")
            return False
        except Exception as e:
            print(f"An unexpected error occurred during Nginx reload: {e}")
            return False

    def set_mod_security_power(self, enable: bool):
        """Enables or disables ModSecurity by modifying Nginx and ModSecurity config files."""
        nginx_update_success, nginx_modified = self._update_config_file(
            NGINX_CONFIG_PATH,
            r'^\s*modsecurity\s+(on|off)\s*;', # Regex to match 'modsecurity on;' or 'modsecurity off;' exactly
            "modsecurity on;",
            "modsecurity off;",
            enable, # Pass 'enable' argument
            append_if_not_found=True # Append if 'modsecurity' directive is not found
        )

        modsec_update_success, modsec_modified = self._update_config_file(
            MODSECURITY_CONFIG_PATH,
            r'^\s*SecRuleEngine\s+(On|Off|DetectionOnly)', # Regex for SecRuleEngine
            "SecRuleEngine On",
            "SecRuleEngine Off",
            enable, # Pass 'enable' argument
            append_if_not_found=False # Don't append if SecRuleEngine is not found, it implies config issue
        )

        if not nginx_update_success or not modsec_update_success:
            raise HTTPException(status_code=500, detail="Failed to update ModSecurity configuration files.")

        # Only reload Nginx if any of the configurations were actually modified
        if nginx_modified or modsec_modified:
            if not self._reload_nginx():
                raise HTTPException(status_code=500, detail="Failed to reload Nginx after configuration change.")
        else:
            print("No configuration changes detected, Nginx not reloaded.")

        print(f"ModSecurity {'enabled' if enable else 'disabled'} successfully.")
        return True

    def log_user_access(self, username):
        """Logs user access to a file using Python's logging module."""
        # No need to check WAF enabled, as this is application-level logging
        try:
            logging.info(f"User: {username} Accessed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            return True
        except Exception as e:
            print(f"Error logging user access: {str(e)}")
            return False

    def show_logs(self):
        """Displays user access logs from the Python log file."""
        try:
            if not os.path.exists(USER_ACCESS_LOG_FILE):
                print("User access log file not found.")
                return []
            with open(USER_ACCESS_LOG_FILE, 'r') as f:
                return f.readlines()
        except Exception as e:
            print(f"Failed to show user logs: {e}")
            return []

    def toggle_protection_for_host(self, host, enable):
        """Toggles protection for a host (in-memory map)."""
        # This is an in-memory map, so it's not persistent across restarts.
        # For persistence, you'd need to save/load this map to a file or database.
        self.host_protection_map[host] = enable
        print(f"Protection for host '{host}' {'enabled' if enable else 'disabled'}.")
        return True

    def parse_log_line(self, line):
        # This helper function for parsing ModSecurity audit logs is already in Python and looks fine.
        log_entry = {}
        if line.startswith('ModSecurity: Warning'):
            parts = line.split('[', 1)
            if len(parts) > 1:
                log_entry['message'] = parts[0].strip()
                details = parts[1].strip(']').split("] [")
                for detail in details:
                    key_value = detail.split(":", 1)
                    if len(key_value) == 2:
                        log_entry[key_value[0].strip()] = key_value[1].strip()
            return log_entry
        return None # Return None if the line doesn't match expected warning format

    def show_audit_logs(self, minutes_ago=30):
        """
        Shows ModSecurity audit logs, filtering by entries within the last `minutes_ago`.
        Parses log entries for better readability.
        """
        logs_data = []
        try:
            if not os.path.exists(MODSEC_AUDIT_LOG_PATH):
                print(f"ModSecurity audit log file not found: {MODSEC_AUDIT_LOG_PATH}")
                return json.dumps([], indent=4)

            cutoff_time = datetime.now() - timedelta(minutes=minutes_ago)

            with open(MODSEC_AUDIT_LOG_PATH, 'r') as log_file:
                content = log_file.read()

            # Split content into individual log segments using the unique separator
            log_segments = re.split(r'---[A-Za-z0-9]+---[A-Z]--', content)

            for segment in log_segments:
                segment = segment.strip()
                if not segment:
                    continue

                log_info = {}
                lines = segment.splitlines()

                # Extract timestamp and IP from the first part of the segment
                if lines:
                    first_line = lines[0]
                    timestamp_match = re.search(r'\[([^\]]+)\]', first_line)
                    if timestamp_match:
                        try:
                            # Attempt to parse the timestamp to filter by time
                            log_timestamp_str = timestamp_match.group(1)
                            # Remove timezone info if present, as datetime.strptime doesn't handle all formats easily
                            if ' +0000' in log_timestamp_str:
                                log_timestamp_str = log_timestamp_str.replace(' +0000', '')
                            # Example format: '11/Jul/2025:13:40:20'
                            # Adjust format string based on actual log format if needed
                            log_timestamp = datetime.strptime(log_timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
                            if log_timestamp < cutoff_time:
                                continue # Skip logs older than cutoff_time
                            log_info['timestamp'] = log_timestamp_str
                        except ValueError:
                            log_info['timestamp'] = timestamp_match.group(1) # Keep original if parsing fails

                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', first_line)
                    if ip_match:
                        log_info['ip'] = ip_match.group(1)

                modsec_warnings = []
                for line in lines:
                    warning = self.parse_log_line(line)
                    if warning:
                        modsec_warnings.append(warning)

                if modsec_warnings:
                    log_info['modsecurity_warnings'] = modsec_warnings

                if log_info:
                    logs_data.append(log_info)

            return json.dumps(logs_data, indent=4)

        except Exception as e:
            print(f"Error reading or processing ModSecurity audit log file: {e}")
            return None

    def clear_audit_logs(self):
        """Clears the ModSecurity audit logs by truncating the file."""
        try:
            # Using 'sudo' is often required for /var/log files
            result = subprocess.run(["sudo", "truncate", "-s", "0", MODSEC_AUDIT_LOG_PATH], check=True, capture_output=True, text=True)
            print(f"Audit logs cleared successfully. Output: {result.stdout}")
            if result.stderr:
                print(f"Audit logs clear stderr: {result.stderr}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to clear ModSecurity audit logs. Exit code: {e.returncode}, Error: {e.stderr}")
            raise HTTPException(status_code=500, detail=f"Failed to clear audit logs: {e.stderr}")
        except FileNotFoundError:
            print(f"Error: 'truncate' command not found or log file path is incorrect: {MODSEC_AUDIT_LOG_PATH}")
            raise HTTPException(status_code=500, detail="Required command/file not found to clear audit logs.")
        except Exception as e:
            print(f"An unexpected error occurred while clearing audit logs: {e}")
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

    def show_modsec_rules(self):
        """Lists ModSecurity rule files (.conf) in the rules directory."""
        try:
            if not os.path.exists(MODSEC_RULES_DIR):
                print(f"Rules directory not found: {MODSEC_RULES_DIR}")
                return []
            rules = [f for f in os.listdir(MODSEC_RULES_DIR) if f.endswith('.conf')]
            return rules
        except Exception as e:
            print(f"Failed to show ModSecurity rules: {e}")
            return []

    def create_new_rule(self, title, body):
        """Creates a new ModSecurity rule file."""
        if not title or not body:
            raise HTTPException(status_code=400, detail="Rule title and body cannot be empty.")

        os.makedirs(MODSEC_RULES_DIR, exist_ok=True)
        file_path = os.path.join(MODSEC_RULES_DIR, f"{title}.conf")

        if os.path.exists(file_path):
            raise HTTPException(status_code=409, detail=f"Rule '{title}.conf' already exists. Please choose a different title.")

        try:
            with open(file_path, 'w') as rule_file:
                rule_file.write(body)
            print(f"Rule '{title}.conf' created successfully at {file_path}")
            return True
        except Exception as e:
            print(f"Failed to create rule: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to create new rule: {e}")
