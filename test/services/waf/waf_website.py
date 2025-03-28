import os
import shutil
import glob
from typing import List, Dict
import zipfile
from models.website_model import Website
from services.database.database import WebsiteSessionLocal
import subprocess

class WAFWebsiteManager:
    def __init__(self, website_id: str):
        self.website_id = website_id
        self.base_dir = f"/usr/local/nginx/website_waf/{website_id}"
        self.rules_dir = os.path.join(self.base_dir, "rules")
        self.disabled_rules_dir = os.path.join(self.base_dir, "disabled_rules")
        self.backup_dir = os.path.join(self.base_dir, "backups")
        self.modsec_include = os.path.join(self.base_dir, "modsec_includes.conf")
        
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
        rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
        
        if not os.path.exists(rule_path):
            raise FileNotFoundError(f"Rule {rule_name} not found")
        
        with open(rule_path, 'w') as f:
            f.write(rule_content)
        
        self.reload_nginx()
        return rule_path

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
        
        for rule_file in glob.glob(os.path.join(self.rules_dir, "*.conf")):
            with open(rule_file, 'r') as f:
                rules.append({
                    "name": os.path.basename(rule_file),
                    "status": "active",
                    "content": f.read()
                })
        
        for rule_file in glob.glob(os.path.join(self.disabled_rules_dir, "*.conf")):
            with open(rule_file, 'r') as f:
                rules.append({
                    "name": os.path.basename(rule_file),
                    "status": "disabled",
                    "content": f.read()
                })
        
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
        """Update website record with current rule list"""
        active_rules = [os.path.basename(f) for f in glob.glob(os.path.join(self.rules_dir, "*.conf"))]
        
        with WebsiteSessionLocal() as db:
            website = db.query(Website).filter(Website.id == self.website_id).first()
            if website:
                website.custom_rules = active_rules
                db.commit()