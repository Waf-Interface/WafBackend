import re
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union
from services.logger.logger_service import app_logger

class Waf_Log:
    def __init__(self, log_path: str ="/var/log/modsec_audit.log", cache_path: str = None):
     self.log_path = log_path
     self.cache_path = cache_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache.json")
     self.rule_name_pattern = re.compile(r'file "(.*?)"')
     self._verify_log_file()

    def _verify_log_file(self) -> Tuple[bool, int, str]:
        self.file_exists = os.path.exists(self.log_path)
        self.file_size = os.path.getsize(self.log_path) if self.file_exists else 0
        self.file_status = "OK" if self.file_exists and self.file_size > 0 else "Missing or empty"
       
        if not self.file_exists:
            raise FileNotFoundError(f"ModSecurity log file not found at {self.log_path}")
        if self.file_size == 0:
            raise ValueError(f"ModSecurity log file is empty: {self.log_path}")
       
        return self.file_exists, self.file_size, self.file_status
    
    def parse_audit_log(self) -> List[Dict]:
     try:
         self._verify_log_file()
        
        # Check if cached data exists and is valid
         if os.path.exists(self.cache_path):
             try:
                 with open(self.cache_path, 'r') as cache_file:
                     cached_data = json.load(cache_file)
                     if isinstance(cached_data, list):  # Basic validation
                         return cached_data
             except (json.JSONDecodeError, IOError) as e:
                 app_logger.warning(f"Invalid cache file, regenerating: {str(e)}")
                 os.remove(self.cache_path)  # Remove invalid cache
 
         entries = self._parse_log_file()
         if not entries:
             raise ValueError("No valid log entries found - check file format")

         processed_logs = self._process_entries(entries[::-1])
        
        # Save processed logs to cache
         try:
             with open(self.cache_path, 'w') as cache_file:
                 json.dump(processed_logs, cache_file)
         except IOError as e:
             app_logger.warning(f"Could not write cache: {str(e)}")
 
         return processed_logs

     except Exception as e:
         error_info = {
            "error": str(e),
            "type": type(e).__name__,
            "log_metadata": self.get_log_metadata()
        }
         raise RuntimeError(f"Failed to parse audit logs: {error_info}") from e
        
    def get_log_metadata(self) -> Dict:
        return {
            "path": self.log_path,
            "exists": self.file_exists,
            "size": self.file_size,
            "status": self.file_status,
            "last_modified": datetime.fromtimestamp(os.path.getmtime(self.log_path)).isoformat() 
                          if self.file_exists else None
        }

    def _parse_log_file(self) -> List[Dict]:
     entries = []
     current_entry = None
     current_raw = []
     current_section = None

     try:
         with open(self.log_path, 'r') as f:
             for line_num, line in enumerate(f, 1):
                 stripped_line = line.strip()
                
                 # Check for section header (more flexible matching)
                 if stripped_line.startswith('---') and '---' in stripped_line:
                     # Extract parts between dashes
                     parts = [p.strip() for p in stripped_line.strip('-').split('-') if p.strip()]
                    
                     if len(parts) >= 2:
                         unique_id = parts[0]
                         section_marker = parts[1].upper()  # Normalize to uppercase
                        
                         # New entry starts with section A
                         if section_marker == 'A':
                             if current_entry:  # Finalize previous entry
                                 self._finalize_entry(current_entry, current_raw, entries)
                            
                             # Start new entry
                             current_entry = {
                                 'id': unique_id,
                                 '_line_number': line_num,
                                  'section_A': [],
                                  'section_B': [],
                                 'section_F': [],
                                 'section_H': []
                             }
                             current_raw = [line]
                             current_section = 'A'
                         
                         # Other sections for current entry
                         elif current_entry and section_marker in ['B', 'F', 'H']:
                             current_section = section_marker
                             current_raw.append(line)
                     
                     continue

                 # Add line to current section if we have an active entry and section
                 if current_entry and current_section:
                     section_key = f'section_{current_section}'
                     current_entry[section_key].append(stripped_line)
                     current_raw.append(line)

         # Finalize the last entry if exists
         if current_entry:
             self._finalize_entry(current_entry, current_raw, entries)

         print(f"Parsed {len(entries)} log entries from {self.log_path}")
         if not entries:
             print("Debug - first 10 lines of file:")
             with open(self.log_path, 'r') as f:
                 for i, line in enumerate(f):
                     if i >= 10:
                         break
                     print(f"{i+1}: {line.strip()}")

         return entries

     except Exception as e:
         error_context = {
             "error": str(e),
             "line_number": line_num if 'line_num' in locals() else None,
             "current_section": current_section,
             "entry_id": current_entry.get('id') if current_entry else None,
             "current_raw": current_raw[-20:] if current_raw else None
         }
         raise RuntimeError(f"Error parsing log file: {error_context}") from e

    def _finalize_entry(self, entry: Dict, raw_lines: List[str], entries: List[Dict]) -> None:
     if entry.get('section_A') or entry.get('section_B') or entry.get('section_H'):
         entry['raw'] = ''.join(raw_lines)
         entries.append(entry)
     else:
         print(f"Dropping incomplete entry: {entry.get('id')} - no valid sections")

    def _process_entries(self, entries: List[Dict]) -> List[Dict]:
        return [self._process_entry(entry) for entry in entries]

    def _process_entry(self, entry: Dict) -> Dict:
        alerts = self._parse_alerts(entry.get('section_H', []))
        
        return {
            'id': entry.get('id'),
            'timestamp': self._parse_timestamp(entry.get('section_A', [])),
            'client_ip': self._parse_client_ip(entry.get('section_A', [])),
            'method': self._parse_method(entry.get('section_B', [])),
            'path': self._parse_path(entry.get('section_B', [])),
            'request': self._parse_request(entry.get('section_B', [])),
            'response': self._parse_response(entry.get('section_F', [])),
            'alerts': alerts,
            'triggered_rules': self._extract_triggered_rules(alerts),
            'details': entry.get('raw', '')
        }

    def _extract_triggered_rules(self, alerts: List[Dict]) -> List[Dict]:
        triggered_rules = []
        for alert in alerts:
            if 'message' not in alert:
                continue
                
            rule_info = {
                'id': alert.get('id', '').strip('"'),
                'msg': alert.get('msg', '').strip('"'),
                'rule_name': self._extract_rule_name(alert.get('message', '')),
                'file': alert.get('file', '').strip('"'),
                'data': alert.get('data', '').strip('"'),
                'severity': alert.get('severity', '').strip('"')
            }
            triggered_rules.append(rule_info)
        return triggered_rules

    def _extract_rule_name(self, alert_message: str) -> str:
        match = self.rule_name_pattern.search(alert_message)
        if match:
            full_path = match.group(1)
            return os.path.basename(full_path)
        return ""

    def _parse_timestamp(self, section_a: List[str]) -> Optional[str]:
        if not section_a:
            return None
        try:
            match = re.search(r'\[(.*?)\]', section_a[0])
            return match.group(1) if match else None
        except (IndexError, AttributeError):
            return None

    def _parse_client_ip(self, section_a: List[str]) -> Optional[str]:
        """Corrected client IP parsing (2nd field after timestamp)"""
        if not section_a:
            return None
        try:
            parts = section_a[0].split()
            return parts[2] if len(parts) > 2 else None  # Changed from 3 to 2
        except IndexError:
            return None

    def _parse_method(self, section_b: List[str]) -> Optional[str]:
        if not section_b:
            return None
        try:
            return section_b[0].split()[0]
        except IndexError:
            return None

    def _parse_path(self, section_b: List[str]) -> Optional[str]:
        if not section_b:
            return None
        try:
            return section_b[0].split()[1]
        except IndexError:
            return None

    def _parse_request(self, section_b: List[str]) -> Dict:
        request = {
            'method': None,
            'path': None,
            'protocol': None,
            'headers': {}
        }

        if not section_b:
            return request

        try:
            parts = section_b[0].split()
            if len(parts) >= 3:
                request.update({
                    'method': parts[0],
                    'path': parts[1],
                    'protocol': parts[2]
                })

            for line in section_b[1:]:
                if ':' in line:
                    key, val = line.split(':', 1)
                    request['headers'][key.strip()] = val.strip()
        except Exception:
            pass

        return request

    def _parse_response(self, section_f: List[str]) -> Dict:
        response = {
            'status': None,
            'headers': []
        }

        if not section_f:
            return response

        try:
            response['status'] = section_f[0].split()[1]
            response['headers'] = section_f[1:]
        except IndexError:
            pass

        return response

    def _parse_alerts(self, section_h: List[str]) -> List[Dict]:
        alerts = []
        current_alert = {}

        for line in section_h:
            try:
                if line.startswith('ModSecurity:'):
                    if current_alert:
                        alerts.append(current_alert)
                    current_alert = {'message': line}
                elif ':' in line:
                    key, val = line.split(':', 1)
                    current_alert[key.strip()] = val.strip()
            except Exception:
                continue

        if current_alert:
            alerts.append(current_alert)

        for alert in alerts:
            if 'message' in alert:
                self._parse_alert_metadata(alert)
        return alerts

    def _parse_alert_metadata(self, alert: Dict) -> None:
        message = alert['message']
        
        metadata_patterns = {
            'id': r'id "([^"]+)"',
            'msg': r'msg "([^"]+)"',
            'file': r'file "([^"]+)"',
            'line': r'line "([^"]+)"',
            'data': r'data "([^"]+)"',
            'severity': r'severity "([^"]+)"',
            'ver': r'ver "([^"]+)"',
            'uri': r'uri "([^"]+)"'
        }

        for key, pattern in metadata_patterns.items():
            match = re.search(pattern, message)
            if match and key not in alert:
                alert[key] = match.group(1)