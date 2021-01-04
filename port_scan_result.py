from flask_restful import Resource, reqparse, request
from bson.objectid import ObjectId
import pymongo
import verify

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('scan_id', help='Scan ID is required to lookup port scan results', required=True)


class PortScanResult(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)
        if auth[1] != 200:
            print(auth)
            return auth
        args = portscan_args.parse_args()
        item_id = args['scan_id']
        item = db.scans.find_one({"_id": ObjectId(item_id)})

        if item is None:
            return{
                'message': 'Provided scan ID does not match with any port scans'
            }, 404

        if item['status'] != 'finished':
            # add timeStamp added and the value/ip and please checkback time from 15 avg minutes
            return {
                'message': f'Item added to queue at {item["timeStamp"].strftime("%m/%d/%Y, %H:%M:%S")} UTC and is in {item["status"]} status, '
                           f'please try again in the next 15 minutes'
            }, 202

        return {
            'id': item_id,
            'ip': item['ip'],
            'status': item['status'],
            'timeStamp': item['timeStamp'].strftime("%m/%d/%Y, %H:%M:%S") + ' UTC',
            'openPorts': item['openPorts']
        }, 200
