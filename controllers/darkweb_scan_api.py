from helpers import utils
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, darkweb_scan

request_args = reqparse.RequestParser()
request_args.add_argument('value', help='Value of a domain is required', required=True)
request_args.add_argument('force', type=inputs.boolean, required=False, default=False)


class DarkWebScan(Resource):

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

        data['value'] = args['value']

        if not utils.validate_domain(data['value']):
            return {
                       'message': f"{data['value']} is not a valid domain, please try again"
                   }, 400

        check = utils.check_force(data, force, 'darkweb', 1)

        if check == 'running' or check == 'queued':
            return {'status': check}
        elif type(check) == dict and check['status'] == 'finished':
            return check['output']

        if check:
            if utils.mark_db_request(data, 'darkweb'):
                output = darkweb_scan.scan(data)
                return output, 200
            else:
                return {'status': 'error',
                        'message': 'DB Write Failure'}
