from flask_restful import Resource, request
import jwt
from time import time
from datetime import datetime
import pymongo
import verify
import hashlib
import os
import base64

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test


class AuthLogin(Resource):
    def post(self):
        arg = request.headers.get('Authorization')

        invalid = {
            'message': 'Provided token is invalid, please check and try again'
        }

        if arg is None:
            return invalid, 401

        validate = arg.split(" ")[1] if arg.split(" ")[0] == 'Basic' else 'Invalid token'

        if validate == 'Invalid token':
            return invalid, 401

        user_pass = base64.b64decode(validate).decode('utf-8')

        username = user_pass.split(':')[0]
        password = user_pass.split(':')[1]

        secret_key = open('secret_key.txt').read()

        db.users.create_index('username')

        user = db.users.find_one({'username': username}, {'_id': 0, 'salt': 1, 'key': 1})

        if user is None:
            return {
               'message': 'Username and password combination not found'
                   }, 404

        unhashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user['salt'], 100000)

        if unhashed_password != user['key']:
            return {
                'message': 'Username and password combination not found'
            }

        access_token = jwt.encode({'username': username, 'iss': 'portscanner.com', 'exp': time() + 3600}, secret_key, algorithm='HS256')
        refresh_token = jwt.encode({'username': username, 'exp': time() + 86400}, secret_key, algorithm='HS256')
        db.refreshTokens.insert_one({'user': username, 'refreshToken': refresh_token, 'timeStamp': datetime.utcnow()})

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 3600
               }, 200


class AuthLogout(Resource):
    def post(self):
        arg = request.headers.get('Authorization')
        token = arg.split(" ")[1] if arg.split(" ")[0] == 'Bearer' else 'Invalid token'

        invalid = {
            'message': 'Provided token is invalid, please check and try again'
        }

        if token == 'Invalid token':
            return invalid, 401

        verification = verify.AuthVerify.post(arg)
        print(verification)

        if verification[0]['message'] == 'Authentication successful':
            db.black_list_token.insert_one({'token': token})
            return {
                'message': 'Log out successful'
                   }, 200
        else:
            return {
                'message': verification[0]['message']
                   }, 401


class AuthSignup(Resource):
    def post(self):
        arg = request.headers.get('Authorization')

        invalid = {
            'message': 'Provided token is invalid, please check and try again'
        }

        if arg is None:
            return invalid, 401

        validate = arg.split(" ")[1] if arg.split(" ")[0] == 'Basic' else 'Invalid token'

        if validate == 'Invalid token':
            return invalid, 401

        user_pass = base64.b64decode(validate).decode('utf-8')

        username = user_pass.split(':')[0]
        password = user_pass.split(':')[1]

        db.users.create_index('username')

        user = db.users.find_one({'username': username})

        if user is not None:
            return {
                'message': 'Username taken, please try again with a different username'
                }, 404

        salt = os.urandom(32)

        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

        db.users.insert_one({'username': username, 'key': key, 'salt': salt, 'timeStamp': datetime.utcnow()})

        return {
            'message': f'Account with username {username} created successfully'
               }, 200

