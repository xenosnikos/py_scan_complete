from flask_restful import Resource, reqparse, request
import socket
from bson import json_util
import pika
import pymongo
from datetime import datetime
import verify

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('ip', help='IP is required to port scan')

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost', heartbeat=900))
channel = connection.channel()

channel.queue_declare(queue='scan_queue', durable=True)


class PortScan(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)

        if auth[1] != 200:
            print(auth)
            return auth
        args = portscan_args.parse_args()
        ip = socket.gethostbyname(args['ip'])

        item = db.scans.insert_one({'ip': ip, 'status': 'queued', "timeStamp": datetime.utcnow()}).inserted_id

        message = {
            '_id': item,
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

        return {
            '_id': str(item),
            'message': f'IP address {ip} added to queue'
        }
