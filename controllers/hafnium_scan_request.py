from helpers import hafnium
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check

request_args = reqparse.RequestParser()
request_args.add_argument('domain', help='Domain is required', required=True)
request_args.add_argument('force', type=inputs.boolean, required=False, default=False)


class HafniumScanRequest(Resource):

    @staticmethod
    def post():
        data = {}
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = request_args.parse_args()

        if args['force']:
            force = True
        else:
            force = False

        data['domain'] = args['domain']

        if not hafnium.validate_domain(data['domain']):
            return {
                       'message': f"{data['domain']} is not a valid domain, please try again"
                   }, 400

        check = hafnium.check_force(data, force)

        if check == 'finished' or check == 'running' or check == 'queued':
            return {'status': check}

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

    @staticmethod
    def get():

        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = request_args.parse_args()

        if not hafnium.validate_domain(args['domain']):
            return {
                       'message': f"{args['domain']} is not a valid domain, please try again"
                   }, 400

        resp = hafnium.hafnium_response(args['domain'])

        if resp == 404:
            return {
                       'message': f"{args['domain']} is not scanned, please try again"
                   }, 404
        else:
            return resp, 200
