from flask_restful import Resource, reqparse, request
from helpers import auth_check, hafnium

request_args = reqparse.RequestParser()
request_args.add_argument('domain', help='Domain is required to pull results', required=True)


class HafniumScanResponse(Resource):

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
