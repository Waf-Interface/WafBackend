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
                        "request": match.group("request").split()[0],  
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

    def get_summary(self):
        status_count = defaultdict(int)
        unique_ips = set()
        total_requests = 0

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

        summary = {
            "total_requests": total_requests,
            "unique_ips": len(unique_ips),
            "status_counts": dict(status_count)
        }

        return summary
    
    def get_daily_traffic(self):
        daily_traffic = defaultdict(int)  

        with open(self.log_file_path, 'r') as f:
            for line in f:
                match = re.match(
                    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"',
                    line
                )
                if match:
                    timestamp_str = match.group("timestamp")
                    date_str = timestamp_str.split(':')[0] 
                    date = datetime.strptime(date_str, '%d/%b/%Y').date()  
                    daily_traffic[date] += 1  


        return dict(daily_traffic)
