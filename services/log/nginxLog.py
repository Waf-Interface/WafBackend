from datetime import datetime
import json
import os
import re
from collections import defaultdict

class nginxLog:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.output_file_path = os.path.join(os.getcwd(), 'access_log.json')

    def access_log(self):
        logs = []
        try:
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    match = re.match(
                        r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
                        line
                    )
                    if match:
                        log_entry = {
                            "timestamp": match.group("timestamp"),
                            "ip": match.group("ip"),
                            "request": match.group("request").split()[0] if match.group("request") else "UNKNOWN",
                            "status": match.group("status"),
                            "bytes": match.group("bytes") if match.group("bytes") != '-' else '0',
                            "referrer": match.group("referrer"),
                            "user_agent": match.group("user_agent"),
                            "modsecurity_warnings": [],
                            "summary": ""
                        }
                        logs.append(log_entry)

            with open(self.output_file_path, 'w') as json_file:
                json.dump(logs[::-1], json_file, indent=4)

            return logs[::-1]  

        except Exception as e:
            print(f"Error processing access logs: {str(e)}")
            return []

    def get_summary(self):
        status_count = defaultdict(int)
        unique_ips = set()
        total_requests = 0
        request_methods = defaultdict(int)
        
        try:
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    match = re.match(
                        r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
                        line
                    )
                    if match:
                        total_requests += 1
                        unique_ips.add(match.group("ip"))
                        status_count[match.group("status")] += 1
                        
                        request_parts = match.group("request").split()
                        if request_parts:
                            method = request_parts[0]
                            request_methods[method] += 1
            
            return {
                "total_requests": total_requests,
                "unique_ips": len(unique_ips),
                "status_counts": dict(status_count),
                "request_methods": dict(request_methods)
            }
            
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
            return {
                "total_requests": 0,
                "unique_ips": 0,
                "status_counts": {},
                "request_methods": {}
            }

    def get_daily_traffic(self):
        daily_traffic = defaultdict(int)
        
        try:
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    match = re.match(
                        r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
                        line
                    )
                    if match:
                        timestamp_str = match.group("timestamp")
                        date_str = timestamp_str.split(':')[0]
                        try:
                            date = datetime.strptime(date_str, '%d/%b/%Y').date()
                            daily_traffic[date] += 1
                        except ValueError:
                            continue

            return dict(daily_traffic)
            
        except Exception as e:
            print(f"Error calculating daily traffic: {str(e)}")
            return {}