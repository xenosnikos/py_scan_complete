import socket

from helpers import utils
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, anubis_domain_expansion, queue_to_db
from helpers import sublist3r2

request_args = reqparse.RequestParser()
request_args.add_argument('value', help='Value of a domain is required', required=True)
request_args.add_argument('force', type=inputs.boolean, required=False, default=False)
request_args.add_argument('ip', type=inputs.boolean, required=False, default=False)


class V1DomainExpansion(Resource):

    @staticmethod
    def post():
        data = {}
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = request_args.parse_args()

        # force comes in as false by default
        # flipping functionality so ePlace doesn't need a change on their end
        if not args['force']:
            force = True
        else:
            force = False

        value = args['value']

        if not utils.validate_domain(value):
            return {
                       'message': f"{value} is not a valid domain or IP, please try again"
                   }, 400

        try:
            socket.gethostbyname(value)
        except:
            return {
                       'message': f"{value} does not exists or cannot be reached now, please check and try again"
                   }, 400

        check = utils.check_force(value, force, collection='expansion', timeframe=3)

        if check == 'running' or check == 'queued':
            return {'status': check}
        elif type(check) == dict and check['status'] == 'finished':
            return check['output']

        if check:
            out = {'value': value}
            if utils.mark_db_request(value, status='queued', collection='expansion'):
                # output_set = domain_expansion_recursive.recursive_scan(data, False)
                output_sublistr = sublist3r2.main(domain=value, engines=None, ports=None, threads=0,
                                                  verbose=False, enable_bruteforce=False, savefile=None, silent=False)
                output_anubis = anubis_domain_expansion.main_scan(value)
                output_set = set(output_sublistr + output_anubis)
                formatted_output, blacklist, out['count'] = utils.v1_format_by_ip(output_set, args['ip'])
                out['blacklist'] = blacklist
                if args['ip']:
                    out['unique_ips'] = len(formatted_output)
                out['sub_domains'] = formatted_output
                queue_to_db.expansion_response_db_addition(value, out)
                return out, 200
            else:
                return {'status': 'error',
                        'message': 'DB Write Failure'}
