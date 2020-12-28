import jwt
from flask_restful import Resource, request
import pymongo

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test


class AuthVerify(Resource):
    @staticmethod
    def post(*args):
        if args == ():
            arg = request.headers.get('Authorization')
        else:
            arg = args[0]

        invalid = {
            'message': 'Provided token is invalid, please check and try again'
        }

        if arg is None:
            return invalid, 401

        token = arg.split(" ")[1] if arg.split(" ")[0] == 'Bearer' else 'Invalid token'

        if token == 'Invalid token':
            return invalid, 401

        if db.black_list_token.find_one({'token': token}) is not None:
            return invalid, 401

        secret_key = open('secret_key.txt').read()

        try:
            a = jwt.decode(token, secret_key, algorithms='HS256')
        except jwt.ExpiredSignatureError:
            return invalid, 401
        except jwt.exceptions.DecodeError:
            return invalid, 401

        if db.users.find_one({'username': a['username']}) is not None:
            return {
                'message': 'Authentication successful'
            }, 200
        else:
            return invalid, 401
