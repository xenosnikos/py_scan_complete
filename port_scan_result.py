from flask_restful import Resource, reqparse, request
from bson.objectid import ObjectId
import pymongo
import verify

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('id', help='ID is required to lookup historical port scans')


class PortScanResult(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)
        if auth[1] != 200:
            print(auth)
            return auth
        args = portscan_args.parse_args()
        item_id = args['id']
        item = db.scans.find_one({"_id": ObjectId(item_id)})

        if item is None:
            return{
                'message': 'Provided ID does not match with any historical port scans'
            }, 404

        if item['status'] != 'finished':
            return {
                'message': f'Item added to queue and is in {item["status"]} status, please wait and try again'
            }, 202

        return {
            'id': item_id,
            'ip': item['ip'],
            'status': item['status'],
            'timeStamp': item['timeStamp'].strftime("%m/%d/%Y, %H:%M:%S") + ' UTC',
            'openPorts': item['openPorts']
        }, 200
