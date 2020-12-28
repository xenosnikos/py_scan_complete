from flask_restful import Resource, reqparse, request
import socket
from bson import json_util
import json
import pymongo
import verify

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('ip', help='IP is required to lookup history')


class PortScanHistory(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)
        if auth[1] != 200:
            print(auth)
            return auth
        args = portscan_args.parse_args()
        ip = socket.gethostbyname(args['ip'])
        item = db.scans.find({'ip': ip})

        if item is None:
            return {
                       'message': f'IP address {ip} not found in the history'
                   }, 404

        result = []

        for each in item:
            each['timeStamp'] = each['timeStamp'].strftime("%m/%d/%Y, %H:%M:%S") + ' UTC'
            each['_id'] = str(each['_id'])
            result.append(json.loads(json_util.dumps(each)))

        return result
