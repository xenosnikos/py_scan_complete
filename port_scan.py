from flask_restful import Resource, reqparse, request
import socket
from bson import json_util
import pika
import pymongo
from datetime import datetime
import verify
import validators

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
# change ip to value
portscan_args.add_argument('value', help='Domain or IP is required to port scan', required=True, action='append')

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='rabbitmq', heartbeat=0))
channel = connection.channel()

channel.queue_declare(queue='scan_queue', durable=True)


class PortScan(Resource):

    def post(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)

        if auth[1] != 200:
            print(auth)
            return auth
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
                    {'ip': ip, 'value': val, 'status': 'queued', "timeStamp": datetime.utcnow()}).inserted_id
                list_ips.append(ip)
                list_value.append(val)
                mongo_id.append(str(item))

                message = {
                    'scan_id': str(item),
                    'ip': ip
                }

                channel.basic_publish(
                    exchange='',
                    routing_key='scan_queue',
                    body=json_util.dumps(message),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                    ))
                print(" [x] Sent %r" % message)
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
