import ctypes
import os
from ctypes import c_bool, c_char_p

lib_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'waf-ghm.so')  # For Linux

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

lib.showAuditLogs.argtypes = []
lib.showAuditLogs.restype = c_bool

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

    def show_logs(self):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        result = lib.showLogs()
        if not result:
            raise Exception("Failed to show logs.")
        return result

    def toggle_protection_for_host(self, host, enable):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        result = lib.toggleProtectionForHost(host.encode('utf-8'), enable)
        if not result:
            raise Exception(f"Failed to toggle protection for host: {host}")
        return result
    
    def show_audit_logs(self):
        buffer_size = 1024 * 1024  # 1 MB
        logs_buffer = ctypes.create_string_buffer(buffer_size)

        result = lib.showAuditLogs(logs_buffer, buffer_size)

        if result:
            return logs_buffer.value.decode('utf-8')
        else:
            return None

    def clear_audit_logs(self):
        result = lib.clearAuditLogs()
        return result
   
    def show_modsec_rules(self):
        result = lib.showModSecRules()  
        
        if not result:
            print("Failed to fetch ModSecurity rules.")
            return None
        
        rules = ctypes.cast(result, ctypes.c_char_p).value.decode('utf-8')  # Decode the C string to Python string
        
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
