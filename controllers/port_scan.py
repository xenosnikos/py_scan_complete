import os
from flask_restful import Resource, reqparse, request, inputs
import socket
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check, port_scan_rec, port_scan_nmap
from helpers.mongo_connection import db
from helpers.queue_to_db import port_scan_db_addition


# add_to_db = Queue(name='portScan_db_queue', connection=redis.from_url(url=os.environ.get('REDIS_CONN_STRING')), default_timeout=-1)
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

        scan_out = {}
        val = args['value']
        db.portScan.create_index([('value', pymongo.DESCENDING), ('status', pymongo.DESCENDING)])
        # see if we have an existing scan for given value and pull the latest
        search = db.portScan.find_one({'value': val, 'status': 'finished'}, sort=[('_id', pymongo.DESCENDING)])

        # force comes in as false by default
        # flipping functionality so ePlace doesn't need a change on their end
        if not args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=3) < datetime.utcnow()

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):

                try:
                    ip = socket.gethostbyname(val)
                except:
                    return {
                               'message': f"{val} does not exists or cannot be reached now, please check and try again"
                           }, 400

                scan_out['ip'] = ip
                scan_out['value'] = val

                out = port_scan_rec.port_scan(ip, 'regular')

                scan_out['count'] = len(out)
                scan_out['internalPortScan'] = out
            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            return search['output']

        port_scan_db_addition(val, scan_out)

        return scan_out
