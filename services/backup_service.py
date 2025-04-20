import shutil
import os

class BackupService:
    def __init__(self):
        self.backup_rules()

    def backup_rules(self):
        rules_dir = "/usr/local/nginx/rules/"
        backup_dir = "/usr/local/nginx/rules_backup/"
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_files = [f for f in os.listdir(backup_dir) if f.endswith(".conf")]
        if backup_files:  
            print("Backup already exists. Skipping backup process.")
            return

        try:
            rule_files = [f for f in os.listdir(rules_dir) if f.endswith(".conf")]
            
            for rule_file in rule_files:
                rule_file_path = os.path.join(rules_dir, rule_file)
                backup_file_path = os.path.join(backup_dir, rule_file)
                
                shutil.copy(rule_file_path, backup_file_path)

            print(f"Backup of rules completed. {len(rule_files)} rule(s) backed up.")
        except Exception as e:
            print(f"Error while backing up rules: {str(e)}")

    def restore_backup_rules(self):
        rules_dir = "/usr/local/nginx/rules/"
        backup_dir = "/usr/local/nginx/rules_backup/"
        
        if not os.path.exists(backup_dir):
            raise Exception(f"Backup folder does not exist: {backup_dir}")

        try:
            backup_files = [f for f in os.listdir(backup_dir) if f.endswith(".conf")]
            
            for backup_file in backup_files:
                backup_file_path = os.path.join(backup_dir, backup_file)
                rule_file_path = os.path.join(rules_dir, backup_file)
                
                shutil.copy(backup_file_path, rule_file_path) 

            print(f"Restoration of rules completed. {len(backup_files)} rule(s) restored.")
        except Exception as e:
            print(f"Error while restoring rules: {str(e)}")
