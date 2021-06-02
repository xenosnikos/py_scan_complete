import socket

from helpers import utils
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, anubis_domain_expansion, queue_to_db
from helpers import sublist3r2, domain_expansion_recursive

request_args = reqparse.RequestParser()
request_args.add_argument('value', help='Value of a domain is required', required=True)
request_args.add_argument('force', type=inputs.boolean, required=False, default=False)
request_args.add_argument('ip', type=inputs.boolean, required=False, default=False)


class DomainExpansion(Resource):

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
                       'message': f"{data['value']} is not a valid domain or IP, please try again"
                   }, 400

        try:
            socket.gethostbyname(data['value'])
        except:
            return {
                       'message': f"{data['value']} does not exists or cannot be reached now, please check and try again"
                   }, 400

        check = utils.check_force(data, force, 'expansion', 1)

        if check == 'running' or check == 'queued':
            return {'status': check}
        elif type(check) == dict and check['status'] == 'finished':
            return check['output']

        if check:
            out = {'value': data['value']}
            if utils.mark_db_request(data, 'expansion'):
                # output_set = domain_expansion_recursive.recursive_scan(data, False)
                output_sublistr = sublist3r2.main(domain=data['value'], engines=None, ports=None, threads=0,
                                                  verbose=False, enable_bruteforce=False, savefile=None, silent=False)
                output_anubis = anubis_domain_expansion.main_scan(data)
                output_set = set(output_sublistr + output_anubis)
                formatted_output = utils.format_by_ip(output_set, args['ip'])
                out['count'] = len(output_set)
                if args['ip']:
                    out['unique_ips'] = len(formatted_output)
                out['sub_domains'] = formatted_output
                queue_to_db.expansion_response_db_addition(out)
                return out, 200
            else:
                return {'status': 'error',
                        'message': 'DB Write Failure'}
