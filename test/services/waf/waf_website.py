from datetime import datetime
import json
import os
import shutil
import glob
from typing import List, Dict
import zipfile
from models.website_model import Website
from services.database.database import WebsiteSessionLocal
import subprocess
from services.logger.logger_service import app_logger
from services.waf.waf_log import Waf_Log

class WAFWebsiteManager:
    def __init__(self, website_identifier: str):
        with WebsiteSessionLocal() as db:
            website = db.query(Website).filter(
                (Website.id == website_identifier) | 
                (Website.application == website_identifier)
            ).first()
            
            if not website:
                raise ValueError(f"Website not found: {website_identifier}")
            
            self.website_id = website.id
            self.application_name = website.application  
        
        self.base_dir = f"/usr/local/nginx/website_waf/{self.website_id}"
        self.rules_dir = os.path.join(self.base_dir, "rules")
        self.disabled_rules_dir = os.path.join(self.base_dir, "disabled_rules")
        self.backup_dir = os.path.join(self.base_dir, "backups")
        self.modsec_include = os.path.join(self.base_dir, "modsec_includes.conf")
        self.NGINX_CONF_DIRECTORY = "/usr/local/nginx/conf"


        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.disabled_rules_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        if not os.path.exists(self.modsec_include):
            with open(self.modsec_include, 'w') as f:
                f.write(
                    f"SecAuditEngine On\n"
                    f"SecAuditLog {os.path.join(self.base_dir, 'audit.log')}\n"
                    f"SecAuditLogParts ABIJDEFHZ\n"
                    f"SecAuditLogType Serial\n"
                    f"SecDebugLog {os.path.join(self.base_dir, 'debug.log')}\n"
                    f"SecDebugLogLevel 0\n"
                    f"Include {self.rules_dir}/*.conf\n"
                )

    def get_website(self) -> Website:
        with WebsiteSessionLocal() as db:
            return db.query(Website).filter(Website.id == self.website_id).first()

    def update_website_config(self, config: Dict):
        with WebsiteSessionLocal() as db:
            website = db.query(Website).filter(Website.id == self.website_id).first()
            if not website:
                raise ValueError("Website not found")
            
            for key, value in config.items():
                setattr(website, key, value)
            db.commit()
            return website

    def create_rule(self, rule_name: str, rule_content: str) -> str:
        rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
        
        if os.path.exists(rule_path):
            raise FileExistsError(f"Rule {rule_name} already exists")
        
        with open(rule_path, 'w') as f:
            f.write(rule_content)
        
        self._update_website_rules()
        self.reload_nginx()
        return rule_path

    def update_rule(self, rule_name: str, rule_content: str) -> str:
     if not rule_name.endswith('.conf'):
         rule_name += '.conf'
        
     rule_path = os.path.join(self.rules_dir, rule_name)
    
     if not os.path.exists(rule_path):
         raise FileNotFoundError(f"Rule {rule_name} not found at path {rule_path}")
    
     try:
         with open(rule_path, 'w') as f:
            f.write(rule_content)
         self.reload_nginx()
         return rule_path
     except Exception as e:
        raise Exception(f"Failed to update rule: {str(e)}")
    
    def delete_rule(self, rule_name: str) -> bool:
        rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
        
        if os.path.exists(rule_path):
            os.remove(rule_path)
            self._update_website_rules()
            self.reload_nginx()
            return True
        return False

    def disable_rule(self, rule_name: str) -> bool:
        src = os.path.join(self.rules_dir, f"{rule_name}.conf")
        dst = os.path.join(self.disabled_rules_dir, f"{rule_name}.conf")
        
        if os.path.exists(src):
            shutil.move(src, dst)
            self._update_website_rules()
            self.reload_nginx()
            return True
        return False

    def enable_rule(self, rule_name: str) -> bool:
        src = os.path.join(self.disabled_rules_dir, f"{rule_name}.conf")
        dst = os.path.join(self.rules_dir, f"{rule_name}.conf")
        
        if os.path.exists(src):
            shutil.move(src, dst)
            self._update_website_rules()
            self.reload_nginx()
            return True
        return False

    def get_rules(self) -> List[Dict]:
     rules = []
    
     app_logger.info(f"Checking rules directory: {self.rules_dir}")
     if not os.path.exists(self.rules_dir):
         app_logger.error(f"Rules directory does not exist: {self.rules_dir}")
         return rules
     else:
         app_logger.info(f"Rules directory exists. Contents: {os.listdir(self.rules_dir)}")
 
     try:
         rule_files = sorted(glob.glob(os.path.join(self.rules_dir, "*.conf")))
         app_logger.info(f"Found {len(rule_files)} active rule files to process")
          
         for rule_file in rule_files:
             try:
                 app_logger.debug(f"Attempting to read rule file: {rule_file}")
                 
                 if not os.access(rule_file, os.R_OK):
                      app_logger.error(f"Rule file not readable (permissions): {rule_file}")
                      continue
                
                 with open(rule_file, 'r') as f:
                     rule_content = f.read()
                     if not rule_content.strip():
                         app_logger.warning(f"Rule file is empty: {rule_file}")
                     
                     rules.append({
                         "name": os.path.basename(rule_file),
                         "status": "active",
                         "content": rule_content
                     })
                     app_logger.debug(f"Successfully loaded rule: {os.path.basename(rule_file)}")
                    
             except PermissionError as e:
                   app_logger.error(f"Permission denied reading rule file {rule_file}: {e}")
                   continue
             except Exception as e:
                  app_logger.error(f"Error reading rule file {rule_file}: {e}")
                  continue
     except Exception as e:
          app_logger.error(f"Error listing rule files: {e}")
     
     app_logger.info(f"Checking disabled rules directory: {self.disabled_rules_dir}")
     if os.path.exists(self.disabled_rules_dir):
          try:
              disabled_rule_files = sorted(glob.glob(os.path.join(self.disabled_rules_dir, "*.conf")))
              app_logger.info(f"Found {len(disabled_rule_files)} disabled rule files to process")
             
              for rule_file in disabled_rule_files:
                  try:
                      app_logger.debug(f"Attempting to read disabled rule file: {rule_file}")
                     
                      if not os.access(rule_file, os.R_OK):
                          app_logger.error(f"Disabled rule file not readable (permissions): {rule_file}")
                          continue
                     
                      with open(rule_file, 'r') as f:
                         rule_content = f.read()
                         if not rule_content.strip():
                              app_logger.warning(f"Disabled rule file is empty: {rule_file}")
                          
                         rules.append({
                              "name": os.path.basename(rule_file),
                              "status": "disabled",
                              "content": rule_content
                           })
                         app_logger.debug(f"Successfully loaded disabled rule: {os.path.basename(rule_file)}")
                         
                  except PermissionError as e:
                      app_logger.error(f"Permission denied reading disabled rule file {rule_file}: {e}")
                      continue
                  except Exception as e:
                      app_logger.error(f"Error reading disabled rule file {rule_file}: {e}")
                      continue
          except Exception as e:
              app_logger.error(f"Error listing disabled rule files: {e}")
     else:
         app_logger.info("Disabled rules directory does not exist")
    
     app_logger.info(f"Total rules loaded: {len(rules)} for website {self.website_id}")
     for rule in rules:
        app_logger.debug(f"Rule: {rule['name']} (Status: {rule['status']}, Content length: {len(rule['content'])} chars)")
     
     return rules

    def backup_rules(self, backup_name: str) -> str:
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        with zipfile.ZipFile(backup_path, 'w') as zipf:
            for root, _, files in os.walk(self.rules_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, self.rules_dir))
        
        with WebsiteSessionLocal() as db:
            website = db.query(Website).filter(Website.id == self.website_id).first()
            if website:
                website.rule_backups = (website.rule_backups or []) + [backup_name]
                db.commit()
        
        return backup_path

    def restore_backup(self, backup_name: str) -> bool:
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        if not os.path.exists(backup_path):
            return False
        
        for rule_file in glob.glob(os.path.join(self.rules_dir, "*.conf")):
            os.remove(rule_file)
        
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            zipf.extractall(self.rules_dir)
        
        self._update_website_rules()
        self.reload_nginx()
        return True

    def reload_nginx(self):
        try:
            subprocess.run(["/usr/local/nginx/sbin/nginx", "-s", "reload"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _update_website_rules(self):
        active_rules = [os.path.basename(f) for f in glob.glob(os.path.join(self.rules_dir, "*.conf"))]
        
        with WebsiteSessionLocal() as db:
            website = db.query(Website).filter(Website.id == self.website_id).first()
            if website:
                website.custom_rules = active_rules
                db.commit()
    def get_nginx_config(self) -> str:
     config_path = os.path.join(self.NGINX_CONF_DIRECTORY, f"{self.application_name}.conf")
    
     if not os.path.exists(config_path) and self.application_name.startswith('www.'):
         base_name = self.application_name[4:]  
         config_path = os.path.join(self.NGINX_CONF_DIRECTORY, f"{base_name}.conf")
    
     if not os.path.exists(config_path):
         config_path = os.path.join(self.NGINX_CONF_DIRECTORY, f"{self.website_id}.conf")
    
     if not os.path.exists(config_path):
         raise FileNotFoundError(
             f"Nginx config not found for website {self.application_name} (ID: {self.website_id}). "
             f"Tried paths: {self.application_name}.conf, {self.application_name[4:] if self.application_name.startswith('www.') else ''}.conf, {self.website_id}.conf"
         )
    
     with open(config_path, 'r') as f:
         return f.read()

    def update_nginx_config(self, new_config: str) -> bool:
        config_path = os.path.join(self.NGINX_CONF_DIRECTORY, f"{self.application_name}.conf")
        
        backup_path = os.path.join(self.backup_dir, f"nginx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.conf.bak")
        if os.path.exists(config_path):
            shutil.copy2(config_path, backup_path)
        
        with open(config_path, 'w') as f:
            f.write(new_config)
        
        try:
            subprocess.run(["/usr/local/nginx/sbin/nginx", "-t"], check=True)
            self.reload_nginx()
            return True
        except subprocess.CalledProcessError as e:
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, config_path)
            raise ValueError(f"Invalid nginx configuration: {str(e)}")
        
    def get_modsec_main_config(self) -> str:
        config_path = "/usr/local/nginx/conf/modsec_includes.conf"
        if not os.path.exists(config_path):
            raise FileNotFoundError("Main ModSecurity config not found")
        
        with open(config_path, 'r') as f:
            return f.read()

    def get_audit_log(self) -> dict:
     log_path = os.path.join(self.base_dir, "audit.log")
    
     if not os.path.exists(log_path):
         return {
             "status": "error",
             "message": "Audit log file not found",
             "path": log_path
         }
    
     try:
         waf_log = Waf_Log(log_path=log_path)
         
         parsed_logs = waf_log.parse_audit_log()
         
         metadata = waf_log.get_log_metadata()
        
         return {
             "status": "success",
             "file_status": metadata,
             "count": len(parsed_logs),
             "logs": parsed_logs[:10000]  
         }
     except Exception as e:
         error_info = {
             "error": str(e),
            "type": type(e).__name__,
             "log_path": log_path,
             "file_exists": os.path.exists(log_path),
             "file_size": os.path.getsize(log_path) if os.path.exists(log_path) else 0
         }
         raise RuntimeError(json.dumps(error_info)) from e

    def get_debug_log(self) -> str:
        log_path = os.path.join(self.base_dir, "debug.log")
        if not os.path.exists(log_path):
            return ""
        
        with open(log_path, 'r') as f:
            return f.read()

    def reset_audit_log(self) -> bool:
        log_path = os.path.join(self.base_dir, "audit.log")
        if os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write("")
            return True
        return False

    def reset_debug_log(self) -> bool:
        log_path = os.path.join(self.base_dir, "debug.log")
        if os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write("")
            return True
        return False
        

        
