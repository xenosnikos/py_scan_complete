import os

from helpers import utils
from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, rdp_scan, common_strings, logging_setup, queue_to_db

"""
API Call: POST
Endpoint: https://{url}/rdp?force=true
Body: {
        "value": "173.10.20.70"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()

request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, required=False, default=False)

logger = logging_setup.initialize(common_strings.strings['rdp'], 'logs/rdp_api.log')


class RDPScan(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"RDP scan request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated RDP scan request received for {value}")
            return authentication, 401

        if not utils.validate_ip(value):  # if regex doesn't match throw a 400
            logger.debug(f"IP that doesn't match regex request received - {value}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['invalid_domain_ip']
                   }, 400

        # ping and ip_reachable methods are both inconsistent, we won't be using any method as it stands to make a
        # determination on the status of IP before continuing with the scan
        # try:
        #     utils.ip_reachable_check(value)
        # except Exception as e:
        #     logger.debug(f"IP that doesn't respond to test - {value, e}")
        #     return {
        #                common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
        #            }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['rdp'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results and force is false, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"rdp scan response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['rdp'])
            output = {common_strings.strings['key_value']: value}

            try:
                out = rdp_scan.process(value)
                output.update(out)
                if common_strings.strings['error_enum'] in output or common_strings.strings['error_ntlm'] in output:
                    return output, 503
                else:

                    try:
                        queue_to_db.rdp_response_db_addition(value, output)
                    except Exception as e:
                        logger.critical(common_strings.strings['database_issue'], e)

                    return output, 200
            except Exception as e:

                try:
                    utils.delete_db_record(value, collection=common_strings.strings['rdp'])
                except Exception as e:
                    logger.critical(common_strings.strings['database_issue'], e)

                logger.error(f'Exception occurred in rdp scan process {e}')
                output.update({common_strings.strings['error_enum']: True, common_strings.strings['error_ntlm']: True})
                return output, 503
