import shutil
import os
import re

class WAFService:
    def __init__(self):
        self.config_files = {
            "crs_setup": "/usr/local/nginx/conf/crs-setup.conf",
            "modsecurity": "/usr/local/nginx/conf/modsecurity.conf",
            "modsec_includes": "/usr/local/nginx/conf/modsec_includes.conf",
            "nginx": "/usr/local/nginx/conf/nginx.conf"
        }
        self.backup_dir = os.path.join(os.path.dirname(__file__), "backup")
        os.makedirs(self.backup_dir, exist_ok=True)

        self.backup_all_files()
        self.config_cache = self.load_configurations()

    def backup_all_files(self):
        for file_key, file_path in self.config_files.items():
            if os.path.exists(file_path):
                backup_path = os.path.join(self.backup_dir, os.path.basename(file_path))
                shutil.copy(file_path, backup_path)

    def load_configurations(self):
        config_cache = {}
        file_path = self.config_files["modsecurity"]
        with open(file_path, 'r') as file:
            content = file.read()
            matches = re.findall(r'(\S+)\s+(.+)', content)
            for key, value in matches:
                config_cache[key.strip()] = value.strip()
        return config_cache

    def get_file_contents(self, file_key):
        if file_key not in self.config_files:
            raise ValueError("Invalid file key provided.")
        
        file_path = self.config_files[file_key]
        with open(file_path, 'r') as file:
            return file.read()

    def replace_file_contents(self, file_key, new_contents):
        if file_key not in self.config_files:
            raise ValueError("Invalid file key provided.")
        
        file_path = self.config_files[file_key]
        with open(file_path, 'w') as file:
            file.write(new_contents)

    def set_sec_rule_engine(self, value):
        self._set_config_value("SecRuleEngine", value)

    def set_sec_response_body_access(self, value):
        self._set_config_value("SecResponseBodyAccess", "On" if value else "Off")

    def get_sec_audit_log(self):
        return self._get_config_value("SecAuditLog")

    def _set_config_value(self, directive, value):
        file_path = self.config_files["modsecurity"]
        with open(file_path, 'r') as file:
            contents = file.readlines()

        with open(file_path, 'w') as file:
            for line in contents:
                if line.startswith(directive):
                    line = f"{directive} {value}\n"
                file.write(line)
        
        self.config_cache[directive] = value

    def _get_config_value(self, directive):
        return self.config_cache.get(directive, "Not found")

    def restore_config_file(self, file_key):
        if file_key not in self.config_files:
            raise ValueError("Invalid file key provided.")
        
        backup_path = os.path.join(self.backup_dir, os.path.basename(self.config_files[file_key]))
        if os.path.exists(backup_path):
            shutil.copy(backup_path, self.config_files[file_key])
            self.config_cache = self.load_configurations()  
        else:
            raise FileNotFoundError("Backup file not found.")

    def restore_all_config_files(self):
        for file_key in self.config_files.keys():
            self.restore_config_file(file_key)  

#Explanation of Search between large modsecurty.conf and crs-setup.conf :
# The load_configurations method reads the entire modsecurity.conf file once and uses a regular expression to extract key-value pairs. This allows for efficient lookups later.
#Getting Configuration Values: The _get_config_value method retrieves values from the cached dictionary, which is much faster than reading the file line by line.
#Backup Functionality: The backup_all_files method remains unchanged, ensuring that the original configuration files are backed up before any modifications.