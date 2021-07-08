import os

from helpers import utils
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, anubis_domain_expansion, queue_to_db, common_strings
from helpers import sublist3r2, logging_setup

"""
API Call: POST
Endpoint: https://{url}/v2/expansion?force=true
Body: {
        "value": "securityvue.com"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()
request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, required=False, default=False)
request_args.add_argument(common_strings.strings['format_by_ip'], type=inputs.boolean, required=False, default=False)

logger = logging_setup.initialize(common_strings.strings['expansion'], 'logs/expansion_api.log')


class DomainExpansion(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"Expansion scan request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated Expansion scan request received for {value}")
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
            logger.debug(f"Domain that doesn't resolve to an IP requested - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings[
                           'unresolved_domain_ip']
                   }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['expansion'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"expansion scan response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['expansion'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip,
                      common_strings.strings['location']: utils.get_location_ip(ip)}
            utils.mark_db_request(value, status=common_strings.strings['status_running'],
                                  collection=common_strings.strings['expansion'])

            # first sub-domain enumeration
            try:
                output_sublistr = sublist3r2.main(domain=value, engines=None, ports=None, threads=0,
                                                  verbose=False, enable_bruteforce=False, savefile=None, silent=False)
            except Exception as e:
                logger.critical(f'sublist3r2 encountered an error {e}')
                output_sublistr = common_strings.strings['error']

            logger.debug(f"sublistr3 expansion scan for {value} is complete")

            # second sub-domain enumeration
            try:
                output_anubis = anubis_domain_expansion.main_scan(value)
            except Exception as e:
                logger.critical(f'anubis encountered an error {e}')
                output_anubis = common_strings.strings['error']

            logger.debug(f"anubis expansion scan for {value} is complete")

            if output_sublistr == common_strings.strings['error'] and output_anubis == common_strings.strings['error']:
                output['sub_domain_count'] = 0

                if args[common_strings.strings['format_by_ip']]:
                    output['unique_ips_count'] = 0

                output['sub_domains'] = common_strings.strings['error']
                return output, 503
            else:

                if output_sublistr == common_strings.strings['error']:
                    output_sublistr = []
                elif output_anubis == common_strings.strings['error']:
                    output_anubis = []

                output_set = set(output_sublistr + output_anubis)
                formatted_output, blacklist, output['sub_domain_count'] = utils.format_by_ip(
                    output_set, args[common_strings.strings['format_by_ip']]
                )
                output['blacklist'] = blacklist

                if args[common_strings.strings['format_by_ip']]:
                    output['unique_ips_count'] = len(formatted_output)

                output['sub_domains'] = formatted_output
                queue_to_db.expansion_response_db_addition(value, output)
                return output, 200
