import os
from flask_restful import Resource, reqparse, request, inputs
import socket
import redis
from rq import Retry, Queue
import json
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check, queue_to_db, port_scan_rec
from helpers.requests_retry import retry_session
import logging
import nmap

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

# add_to_db = Queue(name='portScan_db_queue', connection=redis.from_url(url=os.environ.get('REDIS_CONN_STRING')), default_timeout=-1)
logging.info(f"Environment variable {os.environ.get('REDIS_CONN_STRING')} to Redis Conn String")
portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('portScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class PortScanExtended(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        list_scans = {}
        val = args['value']
        db.portScan.create_index('value')
        # see if we have an existing scan for given value and pull the latest
        search = db.portScanExtended.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

        # force comes in as false by default
        if args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)

                item = db.portScan.insert_one(
                    {'ip': ip, 'value': val,
                     "timeStamp": datetime.utcnow()}).inserted_id

                list_scans['ip'] = ip
                list_scans['value'] = val

                list_scans['port_scan_extended'] = None

                nmap_port_scan = nmap.PortScanner()
                patch_check = nmap_port_scan.scan(hosts=val, ports='1-6000')

            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            del search['_id']
            del search['timeStamp']
            return search

        message = {'mongo': str(item),
                   'data': list_scans}

        # add_to_db.enqueue(queue_to_db.port_scan_db_addition, message, retry=Retry(max=3, interval=[10, 30, 60]))

        return list_scans
