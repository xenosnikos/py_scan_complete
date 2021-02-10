from flask_restful import Resource, reqparse, request
from bson.objectid import ObjectId
import pymongo

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('scan_id', help='Scan ID is required to lookup port scan results', required=True)


class PortScanResult(Resource):

    def get(self):
        auth = request.headers.get('Authorization')

        if auth != open('api_key.txt').read():
            return {
                       'message': 'Provided token is invalid, please check and try again'
                   }, 401

        args = portscan_args.parse_args()
        item_id = args['scan_id']
        item = db.scans.find_one({"_id": ObjectId(item_id)})

        if item is None:
            return{
                'message': 'Provided scan ID does not match with any port scans'
            }, 404

        return_obj = {
            'id': item_id,
            'value': item['value'],
            'ip': item['ip'],
            'timeStamp': item['timeStamp'].strftime("%m/%d/%Y, %H:%M:%S") + ' UTC',
            'portScanStatus': item['portScanStatus'],
            'portScanPercentage': item['portScanPercentage'],
            'sslScanStatus': item['sslScanStatus']
        }

        if item['portScanStatus'] != 'finished' and item['sslScanStatus'] != 'finished':
            # add timeStamp added and the value/ip and please checkbox time from 15 avg minutes
            return_obj['message'] = 'please try again in the next 15 minutes for full result set'
        if item['sslScanStatus'] == 'finished':
            return_obj['ssl/tlsTestResults'] = item['ssl/tlsTestResults']
        if item['portScanStatus'] == 'finished':
            return_obj['openPorts'] = item['openPorts']

        return return_obj, 200
