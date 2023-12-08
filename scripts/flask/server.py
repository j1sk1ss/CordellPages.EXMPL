import os
import random
import string
import bcrypt

from mail_confirm import confirm_mail, insert_code, check_code, send_mail
from password_confirm import password_confirm
from utils import is_human

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy


###############
# Configuration

app = Flask(__name__)
CORS(app)

app.config.update(dict(
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456789@localhost/site_data_base',
    SQLALCHEMY_TRACK_MODIFICATIONS = False
))

db = SQLAlchemy(app)

###############


###############
# Initialise classes for working with data base objects

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(255), nullable=False)
    mail = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer)

class Salt(db.Model):
    __tablename__ = 'salts'
    salt_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    pass_salt = db.Column(db.LargeBinary, nullable=False)

###############


###############
# Handling

@app.route('/captcha', methods=['POST'])
def handle_captcha():
    if is_human(request.get_json()['g-recaptcha-response']):
        return jsonify({'response': 'Captcha solved'})
    else:
        return jsonify({'response': 'Captcha not solved'})
 

@app.route('/mail_confirm', methods=['POST'])
def handle_mail_confirm():
    user_mail = request.get_json()['data']['mail']
    if confirm_mail(user_mail):
        send_mail(user_mail, f'Code for verification: {insert_code(user_mail)}')
        return jsonify({'response': 'Code generated. Check your mail'})
    else:
        return jsonify({'response': 'Bad mail'})


@app.route('/code_confirm', methods=['POST'])
def handle_code_confirm():
    data = request.get_json()

    user_mail = data['data']['mail']
    if check_code(user_mail, data['data']['code']):
        return jsonify({'response': 'Mail verified'})
    else:
        return jsonify({'response': 'Mail not verified'})


@app.route('/register', methods=['POST'])
def handle_registration():
    data = request.get_json()

    # Recieve data
    user_pass = data['user_side_data']['user_data']['password']
    user_mail = data['user_side_data']['user_data']['mail']
    user_login = data['user_side_data']['user_data']['login']
    #

    # Generate salt and encrypt
    pass_salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user_pass.encode('utf-8'), pass_salt)
    #

    # Check if user mail are occupied
    if User.query.filter_by(mail=user_mail).first():
        return jsonify({'response': 'Wrong login or mail occupied'})
    #

    # Save data to Postrges
    if user_login and user_pass:
        if password_confirm(user_pass) is True:
            new_user = User(login=user_login, password=hashed_password.decode('utf-8'), mail=user_mail)

            db.session.add(new_user)
            db.session.commit()

            db.session.add(Salt(user_id=new_user.id, pass_salt=pass_salt))
            db.session.commit()

            return jsonify({'response': 'User created'})
        else:
            return jsonify({'response': 'Wrong password'})
    else:
        return jsonify({'response': 'Error via user creating'})
    #


@app.route('/login', methods=['POST'])
def handle_login():
    data = request.get_json()

    # Recieve data
    user_pass = data['user_side_data']['user_data']['password']
    user_mail = data['user_side_data']['user_data']['mail']
    #

    # Get data from Postgres
    existing_user = User.query.filter_by(mail=user_mail).first()
    #

    if existing_user:
        # Get data from Salt Postgres, encrypt
        salt = Salt.query.filter_by(user_id=existing_user.id).first()
        hashed_password = bcrypt.hashpw(user_pass.encode('utf-8'), salt.pass_salt)

        if hashed_password != existing_user.password.encode('utf-8'):
            return jsonify({'response' : 'Wrong password'})
        #

        # Check admin status
        admin = 0
        if Admin.query.filter_by(user_id=existing_user.id):
            admin = 1
        #

        return jsonify({'response': 'Succes login',
                        'user': {
                            'user_name': existing_user.login,
                            'admin': admin
                        }
        })
    else:
        return jsonify({'response': 'Cant login'})

###############

app.run(host='0.0.0.0', ssl_context=('/etc/ssl/certs/server.pem', '/etc/ssl/private/server.key'))