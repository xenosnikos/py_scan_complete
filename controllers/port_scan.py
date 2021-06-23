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
from helpers.mongo_connection import db
import logging


# add_to_db = Queue(name='portScan_db_queue', connection=redis.from_url(url=os.environ.get('REDIS_CONN_STRING')), default_timeout=-1)
logging.info(f"Environment variable {os.environ.get('REDIS_CONN_STRING')} to Redis Conn String")
portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('portScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class PortScan(Resource):

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
        search = db.portScan.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

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

                # calling api with retries and backoff_factor
                # session = retry_session()
                # resp = session.get(f"https://api.viewdns.info/portscan/?host={val}&apikey="
                #                    f"{os.environ.get('API_KEY_VIEW_DNS')}&output=json")
                # logging.info(f"Environment variable {os.environ.get('API_KEY_VIEW_DNS')} to view DNS")
                # if resp.status_code == 200:
                #     out = json.loads(resp.content.decode())['response']
                #
                #     list_scans['portScan'] = out['port']
                list_scans['portScan'] = None

                out3 = {}

                # Our internal port scan with multithreading
                out1 = port_scan_rec.callback({'ip': ip,
                                              'type': 'fast'})
                logging.info(f"Output of out1, {out1}")

                if len(out1) >= 3:
                    out2 = port_scan_rec.callback({'ip': ip,
                                                  'type': 'medium'})
                    out1.update(out2)

                    if len(out1) >= 4:
                        out3 = port_scan_rec.callback({'ip': ip,
                                                      'type': 'slow'})

                        out1.update(out3)

                list_scans['internalPortScan'] = out1
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
