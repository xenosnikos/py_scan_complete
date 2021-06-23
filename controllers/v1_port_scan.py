from flask_restful import Resource, reqparse, request, inputs
import socket
import pymongo
from datetime import datetime, timedelta
import validators

from helpers import auth_check, port_scan_nmap, port_scan_rec
from helpers.queue_to_db import v1_port_scan_db_addition
from helpers.mongo_connection import db


portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('portScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)
portscan_args.add_argument('threaded', type=inputs.boolean, default=True)
# this threaded default boolean will be changed once we analyze the actual nmap's ability to give consistent results


class V1PortScan(Resource):

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

                if not args['threaded']:
                    out = port_scan_nmap.nmap_scan(ip, 'regular')
                else:
                    out = port_scan_rec.port_scan(ip, 'regular')

                scan_out['count'] = len(out)
                scan_out['internalPortScan'] = out
            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            return search['output']

        v1_port_scan_db_addition(val, scan_out)

        return scan_out
