from helpers import hafnium
from flask_restful import Resource, reqparse, request, inputs
import redis
from rq import Queue
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('value', help='Domain is required to scan', required=True, action='append')
portscan_args.add_argument('hafniumScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class HafniumScanRequest(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        domain = args['domain']

        if not HafniumScanRequest.validate_domain(domain):
            return {
                'message': f'{domain} is not a valid domain, please try again'
            }, 400

        db.hafnium.create_index('domain')
        search = db.hafnium.find({'domain': domain})

        # force comes in as false by default
        if args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=1) < datetime.utcnow()

        if search is None or force:
            return {'status': 'queued'}
        else:
            return {'status': search['status']}
