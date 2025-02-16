import os
import re
import json
import ctypes
from ctypes import c_bool, c_char_p

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

    def load_rule(self, rule):
        if not self.check_waf_enabled():
            raise Exception("WAF is offline. Please enable ModSecurity first.")
        result = lib.loadRule(rule.encode('utf-8'))
        if not result:
            raise Exception(f"Failed to load rule: {rule}")
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
            raise Exception(f"Failed to create new rule: {e}")
        
        return True
