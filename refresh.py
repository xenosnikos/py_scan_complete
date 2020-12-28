from flask_restful import Resource, request
import jwt
from time import time
import datetime
import pymongo

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test


class AuthRefresh(Resource):
    def post(self):
        arg = request.headers.get('Authorization')
        arg2 = request.headers.get('Refresh')
        token = arg.split(" ")[1] if arg.split(" ")[0] == 'Bearer' else 'Invalid token'

        invalid = {
            'message': 'Provided token is invalid, please check and try again'
        }

        if token == 'Invalid token':
            return invalid, 401

        if db.black_list_token.find_one({'token': token}) is not None:
            return invalid, 401

        ref = db.refreshTokens.find_one({'refreshToken': arg2}, {'_id': 0, 'timeStamp': 1})

        if ref is None or (ref['timeStamp'] + datetime.timedelta(days=1) < datetime.datetime.utcnow()):
            return {
                'message': 'Invalid refresh token'
            }, 401

        secret_key = open('secret_key.txt').read()

        try:
            a = jwt.decode(token, secret_key, algorithms='HS256', options={'verify_exp': False})
        except jwt.exceptions.DecodeError:
            return invalid, 401

        if db.users.find_one({'username': a['username']}) is not None:
            access_token = jwt.encode({'username': a['username'], 'iss': 'portscanner.com', 'exp': time() + 3600},
                                      secret_key, algorithm='HS256')
            return {
                'access_token': access_token,
                'refresh_token': arg2,
                'token_type': 'Bearer',
                'expires_in': 3600
                   }, 200
        else:
            return invalid, 401
