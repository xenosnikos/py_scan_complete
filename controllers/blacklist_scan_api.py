import os

from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, utils, blacklist_scan, common_strings, logging_setup, queue_to_db

request_args = reqparse.RequestParser()

request_args.add_argument('value', help=common_strings.strings['domain_required'], required=True)
request_args.add_argument('force', type=inputs.boolean, default=False)

logger = logging_setup.initialize('blacklist', 'logs/blacklist_api.log')


class BlacklistScan(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args['value']

        logger.debug(f"Blacklist scan request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated blacklist scan request received for {value}")
            return authentication, 401

        if not utils.validate_domain(value):  # if regex doesn't match throw a 400
            logger.debug(f"Domain that doesn't match regex request received - {value}")
            return {
                       'message': f"{value}" + common_strings.strings['invalid_domain_ip']
                   }, 400

        # if domain doesn't resolve into an IP, throw a 400 as domain doesn't exist in the internet
        try:
            ip = utils.resolve_domain_ip(value)
        except:
            logger.debug(f"Domain that doesn't resolve IP - {value}")
            return {
                       'message': f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        if args['force']:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(value, force, collection='blacklist',
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"blacklist scan response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'], collection='blacklist')
            output = {'value': value, 'ip': ip}

            try:
                out = blacklist_scan.scan(value, ip)  # the blacklist scan function
                output.update(out)
            except:
                # remove the record from database so next scan can run through
                utils.delete_db_record(value, collection='blacklist')
                output['blacklisted'] = 'Unknown'
                output['source'] = 'Unknown'

            if output['blacklisted'] != 'Unknown':
                try:
                    queue_to_db.blacklist_db_addition(value, output)
                except:
                    logger.critical(common_strings.strings['database_issue'])

            logger.debug(f"blacklist scan response sent for {value} performing a new scan")
            return output, 200
