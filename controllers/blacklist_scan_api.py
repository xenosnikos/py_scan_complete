from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, utils, blacklist_scan, common_strings, logging_setup

request_args = reqparse.RequestParser()

request_args.add_argument('value', help='Domain is required to scan', required=True)
request_args.add_argument('force', type=inputs.boolean, default=False)

logger = logging_setup.initialize('blacklist', 'logs/blacklist_api.log')


class BlacklistScan(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        data = {'value': args['value']}

        logger.info(f"Blacklist scan request received for {args['value']}")

        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.info(f"Unauthenticated blacklist scan request received for {args['value']}")
            return authentication, 401

        if not utils.validate_domain(data['value']):  # if regex doesn't match throw a 400
            logger.info(f"Domain that doesn't match regex request received - {args['value']}")
            return {
                       'message': f"{data['value']}" + common_strings.strings['invalid_domain_ip']
                   }, 400

        # if domain doesn't resolve an IP, throw a 400 as domain doesn't exist in the internet
        if not utils.resolve_domain_ip(data['value']):
            logger.info(f"Domain that doesn't resolve IP - {args['value']}")
            return {
                       'message': f"{data['value']}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        if args['force']:
            force = True
        else:
            force = False

        # based on force either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(data, force, 'blacklist', 3)

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == 'running' or check == 'queued':
            return {'status': check}, 202
        elif type(check) == dict and check['status'] == 'finished':  # if database has an entry with results, send it
            logger.info(f"blacklist scan response sent for {args['value']} from database lookup")
            return check['output'], 200
        else:
            utils.mark_db_request(data, 'blacklist')  # mark in the db that it is queued
            output = blacklist_scan.scan(data)  # the blacklist scan function
            logger.info(f"blacklist scan response sent for {args['value']} performing a new scan")
            return output, 200
