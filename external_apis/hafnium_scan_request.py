from helpers import hafnium
from flask_restful import Resource, reqparse, request, inputs
import redis
from rq import Queue
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('value', help='Domain is required to scan', required=True)
portscan_args.add_argument('hafniumScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class HafniumScanRequest(Resource):

    @staticmethod
    def post():
        data = {}
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        if args['force']:
            force = True
        else:
            force = False

        data['domain'] = args['value']

        if not hafnium.validate_domain(data['domain']):
            return {
                'message': f"{data['domain']} is not a valid domain, please try again"
            }, 400

        check = hafnium.check_force(data, force)

        if check:
            if hafnium.hafnium_request(data):
                if hafnium.db_queue('hafnium_scan', data):
                    return {'status': 'queued'}
                else:
                    return {'status': 'error',
                            'message': 'Queue Failure'}
            else:
                return {'status': 'error',
                        'message': 'DB Write Failure'}
        else:
            return {'status': check['status']}
