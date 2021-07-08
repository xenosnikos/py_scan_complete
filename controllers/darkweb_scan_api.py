import os

from helpers import utils, common_strings, queue_to_db, logging_setup
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, darkweb_scan

"""
API Call: POST
Endpoint: https://{url}/v2/darkweb?force=true
Body: {
        "value": "idagent.com"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()

request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, default=False)
request_args.add_argument(common_strings.strings['input_omit_passwords'], type=inputs.boolean, default=True)

logger = logging_setup.initialize(common_strings.strings['darkweb'], 'logs/darkweb_api.log')


class DarkWebScan(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"Darkweb scan request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated darkweb scan request received for {value}")
            return authentication, 401

        if not utils.validate_domain(value):  # if regex doesn't match throw a 400
            logger.debug(f"Domain that doesn't match regex request received - {value}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['invalid_domain']
                   }, 400

        # if domain doesn't resolve into an IP, throw a 400 as domain doesn't exist in the internet
        try:
            ip = utils.resolve_domain_ip(value)
        except Exception as e:
            logger.debug(f"Domain that doesn't resolve to an IP was received - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['darkweb'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"darkweb scan response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['darkweb'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}

            try:
                output['compromises'] = darkweb_scan.scan(value, args[common_strings.strings['input_omit_passwords']])
            except Exception as e:
                logger.critical(f"Darkweb scan failed for {value, e}")
                output['compromises'] = [common_strings.strings['error']]
                return output, 503

            try:
                queue_to_db.darkweb_response_db_addition(value, output)
            except Exception as e:
                logger.critical(common_strings.strings['database_issue'], e)

            return output, 200
