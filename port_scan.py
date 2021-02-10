from flask_restful import Resource, reqparse, request
import socket
from redis import Redis
from rq import Retry, Queue
import port_scan_rec
import sslyze_rec
import pymongo
from datetime import datetime
import validators

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

queue1 = Queue(name='scan_queue', connection=Redis(host='localhost', port=31000), default_timeout=900)
queue2 = Queue(name='sslyze_queue', connection=Redis(host='localhost', port=31000))

portscan_args = reqparse.RequestParser()
# change ip to value
portscan_args.add_argument('value', help='Domain or IP is required to port scan', required=True, action='append')


class PortScan(Resource):

    def post(self):
        auth = request.headers.get('Authorization')

        if auth != open('api_key.txt').read():
            return {
                'message': 'Provided token is invalid, please check and try again'
            }, 401

        args = portscan_args.parse_args()

        list_ips = []
        list_value = []
        mongo_id = []
        print(args['value'])
        print(list(args['value']))
        for val in args['value']:
            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)
                # add the actual value in(URL)
                item = db.scans.insert_one(
                    {'ip': ip, 'value': val, 'portScanStatus': 'queued',
                     'portScanPercentage': 0, 'sslScanStatus': 'queued', "timeStamp": datetime.utcnow()}).inserted_id
                list_ips.append(ip)
                list_value.append(val)
                mongo_id.append(str(item))

                message = {
                    'scan_id': str(item),
                    'ip': ip
                }

                message_sslyze = {
                    'scan_id': str(item),
                    'ip': ip,
                    'value': val
                }

                queue1.enqueue(port_scan_rec.callback, message, retry=Retry(max=3, interval=[10, 30, 60]))
                queue2.enqueue(sslyze_rec.callback, message_sslyze, retry=Retry(max=3, interval=[10, 30, 60]))

                print(" [x] Sent Scan %r" % message)
                print(queue1.count)
                print(" [x] Sent SSLYZE %r" % message_sslyze)
            else:
                return {
                    'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400

        return_list = []

        for i in range(len(mongo_id)):
            return_list.append({
                'scan_id': mongo_id[i],
                'scan_value': list_value[i],
                'message': f'IP address {list_ips[i]} added to queue'
            })

        return return_list
