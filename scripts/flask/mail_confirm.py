import re
import dns.resolver
import smtplib

from datetime import datetime, timedelta
from utils import get_random_string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SERVER_MAIL = 'cordell.confirm@gmail.com'
SERVER_MAIL_PASS = 'zqcn eljx qjjj ekpu'

code_buffer = {}


def insert_code(mail: str):
    code = get_random_string(6)
    code_buffer[mail] = {
        'code': code, 
        'end_life': datetime.now() + timedelta(minutes=3)
    }
    
    return code


def check_code(mail: str, code: str):
    if code_buffer[mail]['code'] == code:
        if code_buffer[mail]['end_life'] > datetime.now():
            del code_buffer[mail]
            return True
        else:
            del code_buffer[mail]
            return False
        
    return False


def send_mail(mail: str, data: str):
    message = MIMEMultipart()
    
    message["From"] = SERVER_MAIL
    message["To"] = mail
    message["Subject"] = "Verification code"
    
    message.attach(MIMEText(data, "plain"))
    
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(SERVER_MAIL, SERVER_MAIL_PASS)
        server.sendmail(SERVER_MAIL, mail, message.as_string())


def confirm_mail(mail: str):
    if re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,8})$', mail) is None:
        return False
     
    try:
        records = dns.resolver.resolve(mail.split('@')[1], 'MX')    
        mxRecord = records[0].exchange
        mxRecord = str(mxRecord)
    except Exception as ex:
        return False
        
    return True