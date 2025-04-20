import logging
import os
import json
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
import shutil

LOG_DIRECTORY = 'logs'
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)

APP_LOG_FILE = os.path.join(LOG_DIRECTORY, 'app_log.json')
LOGIN_LOG_FILE = os.path.join(LOG_DIRECTORY, 'login_log.json')

app_logger = logging.getLogger('app_logger')
app_logger.setLevel(logging.INFO)

login_logger = logging.getLogger('login_logger')
login_logger.setLevel(logging.INFO)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)

app_handler = TimedRotatingFileHandler(APP_LOG_FILE, when='H', interval=1, backupCount=0)
app_handler.setFormatter(JsonFormatter())
app_logger.addHandler(app_handler)

login_handler = logging.FileHandler(LOGIN_LOG_FILE)
login_handler.setFormatter(JsonFormatter())
login_logger.addHandler(login_handler)

def cleanup_old_logs():
    now = datetime.now()
    for log_file in os.listdir(LOG_DIRECTORY):
        log_file_path = os.path.join(LOG_DIRECTORY, log_file)
        if log_file != "login_log.json":  
            file_creation_time = datetime.fromtimestamp(os.path.getctime(log_file_path))
            if now - file_creation_time > timedelta(hours=1):
                os.remove(log_file_path)

cleanup_old_logs()
