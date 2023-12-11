import datetime

def log_audit(message):
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    with open('audit_log.txt', 'a') as log_file:
        log_file.write(f"{timestamp}: {message}\n")