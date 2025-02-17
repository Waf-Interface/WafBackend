import os
import shutil
import ctypes

lib_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'waf-ghm.so')  # For Linux
lib = ctypes.CDLL(lib_path)

class WAFRules:
    def __init__(self):
        if not lib.initialize():
            raise Exception("Failed to initialize WAF.")
        print("WAF initialized successfully!")

    def is_mod_security_enabled(self):
        result = lib.isModSecurityEnabled()
        if not result:
            print("ModSecurity is not enabled. Please ensure it is correctly configured.")
        return result

    def check_waf_enabled(self):
        return self.is_mod_security_enabled()

    def load_rule(self, rule_name):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        
        rules_directory = "/usr/local/nginx/rules/"
        disabled_directory = "/usr/local/nginx/rules_disabled/"

        rule_file_path = os.path.join(rules_directory, rule_name)
        disabled_file_path = os.path.join(disabled_directory, rule_name)

        if os.path.exists(rule_file_path):
            rule_file_path = rule_file_path
        elif os.path.exists(disabled_file_path):
            rule_file_path = disabled_file_path
        else:
            return {"status": "error", "message": f"Rule file {rule_name} not found in any folder."}

        try:
            with open(rule_file_path, 'r') as rule_file:
                rule_content = rule_file.read()
            return {
                "status": "success", 
                "message": f"Rule {rule_name} loaded successfully.", 
                "rule_content": rule_content
            }
        except Exception as e:
            return {
                "status": "error", 
                "message": f"Error loading rule {rule_name}: {str(e)}"
            }

    def update_rule(self, rule_name, new_content):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        
        rules_directory = "/usr/local/nginx/rules/"
        disabled_directory = "/usr/local/nginx/rules_disabled/"

        rule_file_path = os.path.join(rules_directory, rule_name)
        disabled_file_path = os.path.join(disabled_directory, rule_name)

        if os.path.exists(rule_file_path):
            file_to_update = rule_file_path
        elif os.path.exists(disabled_file_path):
            file_to_update = disabled_file_path
        else:
            return {"status": "error", "message": f"Rule file {rule_name} not found in any folder."}

        try:
            with open(file_to_update, 'w') as rule_file:
                rule_file.write(new_content)
            return {
                "status": "success",
                "message": f"Rule {rule_name} updated successfully.",
                "rule_content": new_content
            }
        except Exception as e:
            return {
                "status": "error", 
                "message": f"Error updating rule {rule_name}: {str(e)}"
            }

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
            raise Exception(f"Failed to create new rule: {e}")
        
        return True

    def disable_rule(self, rule_name: str):
        rules_dir = "/usr/local/nginx/rules/"
        disabled_dir = "/usr/local/nginx/rules_disabled/"
        
        rule_file_path = os.path.join(rules_dir, rule_name)
        disabled_file_path = os.path.join(disabled_dir, rule_name)
        
        if not os.path.exists(rule_file_path):
            return {"status": "error", "message": f"Rule file {rule_name} not found in active rules."}
        
        try:
            if not os.path.exists(disabled_dir):
                os.makedirs(disabled_dir)

            shutil.move(rule_file_path, disabled_file_path)
            return {"status": "success", "message": f"Rule {rule_name} disabled successfully."}
        
        except Exception as e:
            return {"status": "error", "message": f"Error disabling rule {rule_name}: {str(e)}"}

    def enable_rule(self, rule_name: str):
        rules_dir = "/usr/local/nginx/rules/"
        disabled_dir = "/usr/local/nginx/rules_disabled/"
        
        disabled_file_path = os.path.join(disabled_dir, rule_name)
        rule_file_path = os.path.join(rules_dir, rule_name)

        if not os.path.exists(disabled_file_path):
            return {"status": "error", "message": f"Rule file {rule_name} not found in disabled rules."}
        
        try:
            shutil.move(disabled_file_path, rule_file_path)
            return {"status": "success", "message": f"Rule {rule_name} enabled successfully."}
        
        except Exception as e:
            return {"status": "error", "message": f"Error enabling rule {rule_name}: {str(e)}"}

    def rules_status(self):
        rules_directory = "/usr/local/nginx/rules/"
        disabled_directory = "/usr/local/nginx/rules_disabled/"
        
        rule_status = []

        for rule in os.listdir(rules_directory):
            if rule.endswith(".conf"):
                rule_status.append({"name": rule, "status": "enabled"})

        for rule in os.listdir(disabled_directory):
            if rule.endswith(".conf"):
                rule_status.append({"name": rule, "status": "disabled"})

        return {"status": "success", "rules": rule_status}
