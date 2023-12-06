import os
import random
import string

from mail_confirm import confirm_mail, insert_code, check_code, send_mail
from password_confirm import password_confirm
from utils import is_human

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
CORS(app)

app.config.update(dict(
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456789@localhost/site_data_base',
    SQLALCHEMY_TRACK_MODIFICATIONS = False
))

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    admin = db.Column(db.Integer)


@app.route('/captcha', methods=['POST'])
def handle_captcha():
    if is_human(request.get_json()['g-recaptcha-response']):
        return jsonify({'response': 'Captcha solved'})
    else:
        return jsonify({'response': 'Captcha not solved'})
 
    
code_buffer = {}

@app.route('/mail_confirm', methods=['POST'])
def handle_mail_confirm():
    data = request.get_json()
    user_mail = data['data']['mail']
    
    if data['data']['operation_type'] == 'Generate code':  
        if confirm_mail(user_mail):
            send_mail(user_mail, f'Code for verification: {insert_code(user_mail)}')
            return jsonify({'response': 'Code generated. Check your mail'})
        else:
            return jsonify({'response': 'Verify provided mail'})
    else:
        if check_code(user_mail, data['data']['code']):
            return jsonify({'response': 'Mail verified'})
        else:
            return jsonify({'response': 'Mail not verified'})
    
    return jsonify({'response': 'Unknown error'})


@app.route('/post_method', methods=['POST'])
def handle_post_request():
    data = request.get_json()
    user_login = data['user_side_data']['user_data']['login']
    user_pass = data['user_side_data']['user_data']['password']

    if data['user_side_data']['operation_type'] == 'Create user':
        existing_user = User.query.filter_by(login=user_login, password=user_pass).first()
        if existing_user:
            return jsonify({'response': 'Wrong login'})
    
        if user_login and user_pass:
            if password_confirm(user_pass) is True:
                new_user = User(login=user_login, password=user_pass, admin=0)
                db.session.add(new_user)
                db.session.commit()
                
                print('Data received and saved successfully')
                return jsonify({'response': 'User created'})
            else:
                return jsonify({'response': 'Wrong password'})
        else:
            return jsonify({'response': 'Error via user creating'})
    else:
        existing_user = User.query.filter_by(login=user_login, password=user_pass).first()
        if existing_user:
            return jsonify({'response': 'Succes login',
                            'user': {
                                'user_name': existing_user.login,
                                'admin': existing_user.admin
                            }
            })
        else:
            return jsonify({'response': 'Cant login'})


app.run(host='0.0.0.0')