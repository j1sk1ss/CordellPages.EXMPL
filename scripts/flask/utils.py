import random
import string
import requests
import json

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    
    return result_str
    
def is_human(captcha_response):
    secret = "6LfvAycpAAAAAJyS8EsUEGpLeIr-1stusIKpaXR2"
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    
    return response_text['success']