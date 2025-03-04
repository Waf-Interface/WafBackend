import os
import shutil
import ctypes
import zipfile
import subprocess

nginx_rules_directory = "/usr/local/nginx/rules/"
backend_root_dir = os.path.dirname(__file__)  
backend_disabled_directory = os.path.join(backend_root_dir, 'rules_disabled')
two_levels_up = os.path.join(backend_root_dir, os.pardir, os.pardir)
two_levels_up = os.path.normpath(two_levels_up)

lib_path = os.path.join(two_levels_up, 'static', 'waf-ghm.so')
print("Library path:", lib_path)

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

        rule_file_path = os.path.join(nginx_rules_directory, rule_name)
        disabled_file_path = os.path.join(backend_disabled_directory, rule_name)

        if not os.path.exists(nginx_rules_directory):
            os.makedirs(nginx_rules_directory)  
        if not os.path.exists(backend_disabled_directory):
            os.makedirs(backend_disabled_directory)  
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

        rule_file_path = os.path.join(nginx_rules_directory, rule_name)
        disabled_file_path = os.path.join(backend_disabled_directory, rule_name)

        if not os.path.exists(nginx_rules_directory):
            os.makedirs(nginx_rules_directory)  
        if not os.path.exists(backend_disabled_directory):
            os.makedirs(backend_disabled_directory)  

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
        if not os.path.exists(nginx_rules_directory):
            os.makedirs(nginx_rules_directory)  

        file_path = os.path.join(nginx_rules_directory, f"{title}.conf")

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
        if not os.path.exists(backend_disabled_directory):
            os.makedirs(backend_disabled_directory)  

        rule_file_path = os.path.join(nginx_rules_directory, rule_name)
        disabled_file_path = os.path.join(backend_disabled_directory, rule_name)

        if not os.path.exists(rule_file_path):
            return {"status": "error", "message": f"Rule file {rule_name} not found in active rules."}

        try:
            shutil.move(rule_file_path, disabled_file_path)
            return {"status": "success", "message": f"Rule {rule_name} disabled successfully."}
        except Exception as e:
            return {"status": "error", "message": f"Error disabling rule {rule_name}: {str(e)}"}

    def enable_rule(self, rule_name: str):
        rule_file_path = os.path.join(nginx_rules_directory, rule_name)
        disabled_file_path = os.path.join(backend_disabled_directory, rule_name)

        if not os.path.exists(nginx_rules_directory):
            os.makedirs(nginx_rules_directory)  
        if not os.path.exists(backend_disabled_directory):
            os.makedirs(backend_disabled_directory)  

        if not os.path.exists(disabled_file_path):
            return {"status": "error", "message": f"Rule file {rule_name} not found in disabled rules."}

        try:
            shutil.move(disabled_file_path, rule_file_path)
            return {"status": "success", "message": f"Rule {rule_name} enabled successfully."}
        except Exception as e:
            return {"status": "error", "message": f"Error enabling rule {rule_name}: {str(e)}"}

    def rules_status(self):
        rule_status = []

        if not os.path.exists(nginx_rules_directory):
            os.makedirs(nginx_rules_directory)
        if not os.path.exists(backend_disabled_directory):
            os.makedirs(backend_disabled_directory)

        for rule in os.listdir(nginx_rules_directory):
            if rule.endswith(".conf"):
                rule_status.append({"name": rule, "status": "enabled"})

        for rule in os.listdir(backend_disabled_directory):
            if rule.endswith(".conf"):
                rule_status.append({"name": rule, "status": "disabled"})

        return {"status": "success", "rules": rule_status}
    
    def backup_rules_to_zip(self):
        rules_folder = os.path.join(backend_root_dir, 'rules')
        if not os.path.exists(rules_folder):
            os.makedirs(rules_folder)
        try:
            for filename in os.listdir(nginx_rules_directory):
                if filename.endswith(".conf"):  
                    src_path = os.path.join(nginx_rules_directory, filename)
                    dst_path = os.path.join(rules_folder, filename)
                    shutil.copy(src_path, dst_path)

            zip_file_path = os.path.join(backend_root_dir, 'rule.zip')
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(rules_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, rules_folder))

            return zip_file_path
        except Exception as e:
            raise Exception(f"Error while backing up rules: {str(e)}")
        
    def delete_rule(self, rule_name):
     rule_file_path = os.path.join(nginx_rules_directory, rule_name)
     disabled_file_path = os.path.join(backend_disabled_directory, rule_name)

     if os.path.exists(rule_file_path):
        try:
            os.remove(rule_file_path)
            self.reload_nginx()
            return {"status": "success", "message": f"Rule {rule_name} deleted successfully from active directory."}
        except Exception as e:
            return {"status": "error", "message": f"Error deleting rule {rule_name} from active directory: {str(e)}"}
    
     elif os.path.exists(disabled_file_path):
        try:
            os.remove(disabled_file_path)
            self.reload_nginx()
            return {"status": "success", "message": f"Rule {rule_name} deleted successfully from disabled directory."}
        except Exception as e:
            return {"status": "error", "message": f"Error deleting rule {rule_name} from disabled directory: {str(e)}"}

     else:
        return {"status": "error", "message": f"Rule {rule_name} not found in either the active or disabled directories."}


    def reload_nginx(self):
        try:
            reload_command = "/usr/local/nginx/sbin/nginx -s reload"
            subprocess.run(reload_command, shell=True, check=True)
            print("Nginx reloaded successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to reload Nginx: {e}")
            raise Exception("Failed to reload Nginx.")