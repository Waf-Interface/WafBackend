import ctypes
import os
import re
import json
from ctypes import c_bool, c_char_p
from fastapi import HTTPException

backend_root_dir = os.path.dirname(__file__)  
backend_disabled_directory = os.path.join(backend_root_dir, 'rules_disabled')
two_levels_up = os.path.join(backend_root_dir, os.pardir, os.pardir)
two_levels_up = os.path.normpath(two_levels_up)

lib_path = os.path.join(two_levels_up, 'static', 'waf-ghm.so')
print("Library path:", lib_path)

lib = ctypes.CDLL(lib_path)
lib = ctypes.CDLL(lib_path)

lib.initialize.argtypes = []
lib.initialize.restype = c_bool

lib.loadRule.argtypes = [c_char_p]
lib.loadRule.restype = c_bool

lib.authenticate.argtypes = [c_char_p, c_char_p]
lib.authenticate.restype = c_bool

lib.shutdown.argtypes = []
lib.shutdown.restype = None

lib.setModSecurityPower.argtypes = [c_bool]
lib.setModSecurityPower.restype = c_bool

lib.logUserAccess.argtypes = [c_char_p]
lib.logUserAccess.restype = c_bool

lib.showLogs.argtypes = []
lib.showLogs.restype = c_bool

lib.toggleProtectionForHost.argtypes = [c_char_p, c_bool]
lib.toggleProtectionForHost.restype = c_bool

lib.isModSecurityEnabled.argtypes = []
lib.isModSecurityEnabled.restype = c_bool



class WAF:
    def __init__(self):
        if not lib.initialize():
            raise Exception("Failed to initialize WAF.")
        print("WAF initialized successfully!")

    def is_mod_security_enabled(self):
        result = lib.isModSecurityEnabled()
        print(f"ModSecurity Enabled (raw result): {result}")  # Debug log
        if not result:
            print("ModSecurity is not enabled. Please ensure it is correctly configured.")
        return result

    def check_waf_enabled(self):
        return self.is_mod_security_enabled()

    def load_rule(self, rule):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        result = lib.loadRule(rule.encode('utf-8'))
        if not result:
            raise Exception(f"Failed to load rule: {rule}")
        return result

    def authenticate(self, username, password):
        if username == "test" and password == "test":
            return True
        return False

    def shutdown(self):
        print("Shutting down WAF...")
        lib.shutdown()

    def set_mod_security_power(self, enable):
        result = lib.setModSecurityPower(enable)
        if not result:
            raise Exception("Failed to set ModSecurity power.")
        return result

    def log_user_access(self, username):
        try:
            if not self.check_waf_enabled():
                raise Exception("WAF is offline. Please enable ModSecurity first.")
            result = lib.logUserAccess(username.encode('utf-8'))
            if not result:
                raise Exception(f"Failed to log user access for {username}.")
            return result
        except Exception as e:
            print(f"Error logging user access: {str(e)}")
            return False

  #  def show_logs(self):
   #     if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
    #    result = lib.showLogs()
     #   if not result:
      #      raise Exception("Failed to show logs.")
       # return result

    def toggle_protection_for_host(self, host, enable):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        result = lib.toggleProtectionForHost(host.encode('utf-8'), enable)
        if not result:
            raise Exception(f"Failed to toggle protection for host: {host}")
        return result
    
    def parse_log_line(self, line):
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

    # def show_audit_logs(self):
    #     log_file_path = '/var/log/modsec_audit.log'  
    #     logs_data = []

    #     try:
    #         with open(log_file_path, 'r') as log_file:
    #             content = log_file.read()

    #             log_segments = re.split(r'---[A-Za-z0-9]+---[A-Z]--', content)

    #             for segment in log_segments:
    #                 segment = segment.strip()
    #                 if segment:
    #                     log_info = {}

    #                     lines = segment.splitlines()
    #                     if len(lines) > 0:
    #                         timestamp_and_ip = lines[0]
    #                         timestamp_match = re.search(r'\[([^\]]+)\]', timestamp_and_ip)
    #                         if timestamp_match:
    #                             log_info['timestamp'] = timestamp_match.group(1)
    #                         ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', timestamp_and_ip)
    #                         if ip_match:
    #                             log_info['ip'] = ip_match.group(1)

    #                     modsec_warnings = []
    #                     for line in lines:
    #                         warning = self.parse_log_line(line)
    #                         if warning:
    #                             modsec_warnings.append(warning)

    #                     if modsec_warnings:
    #                         log_info['modsecurity_warnings'] = modsec_warnings

    #                     if log_info:
    #                         logs_data.append(log_info)

    #         return json.dumps(logs_data, indent=4)

    #     except Exception as e:
    #         print(f"Error reading or processing log file: {e}")
    #         return None

    def clear_audit_logs(self):
        result = lib.clearAuditLogs()
        return result

    def show_modsec_rules(self):
        result = lib.showModSecRules()  

        if not result:
            print("Failed to fetch ModSecurity rules.")
            return None

        rules = ctypes.cast(result, ctypes.c_char_p).value.decode('utf-8')  

        rule_list = rules.splitlines()

        lib.free(result)

        return rule_list

    def create_new_rule(self, title, body):
        rules_directory = "/usr/local/nginx/rules/"

        if not os.path.exists(rules_directory):
            raise Exception(f"Directory does not exist: {rules_directory}")

        file_path = os.path.join(rules_directory, f"{title}.conf")

        if os.path.exists(file_path):
            raise Exception(f"Rule '{title}' already exists. Please choose a different title.")

        try:
            with open(file_path, 'w') as rule_file:
                rule_file.write(body)

            print(f"Rule {title} created successfully at {file_path}")

        except Exception as e:
            print(f"Failed to create rule: {e}")
            raise Exception(f"Failed to create new rule: {e}")

        return True
