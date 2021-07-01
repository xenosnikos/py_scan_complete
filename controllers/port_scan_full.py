import os

from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, port_scan_rec, port_scan_nmap, logging_setup, common_strings, utils, queue_to_db

"""
API Call: POST
Endpoint: https://{url}/port-scan/full?force=true
Body: {
        "value": "idagent.com"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()

request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, default=False)
request_args.add_argument(common_strings.strings['input_threaded'], type=inputs.boolean, default=True)

logger = logging_setup.initialize(common_strings.strings['port-scan'], 'logs/port-scan_api.log')


class PortScanFull(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"Port scan full request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated port scan request received for {value}")
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
            logger.debug(f"Domain that doesn't resolve to an IP - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['port-scan-full'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"port scan full response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['port-scan-full'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}

            if args[common_strings.strings['input_threaded']]:

                try:
                    out = port_scan_rec.port_scan(ip, utils.PortScanEnum(3).name)
                except Exception as e:
                    logger.critical(f"Multi threaded port scan full ran into an issue for {value, e}")
                    out = [common_strings.strings['error']]

            else:

                try:
                    out = port_scan_nmap.nmap_scan(ip, utils.PortScanEnum(3).name)
                except Exception as e:
                    logger.critical(f"NMAP port scan full ran into an issue for {value, e}")
                    out = [common_strings.strings['error']]

            if out != [common_strings.strings['error']]:
                output['count'] = len(out)
                output['result'] = out
                output['risk'] = None
                queue_to_db.port_scan_db_addition(value, output, collection=common_strings.strings['port-scan-full'])
                logger.debug(f"port scan full response sent for {value} from new scan")
                return output, 200
            else:
                output['count'] = 0
                output['result'] = out
                logger.debug(f"port scan full response sent for {value} from new scan with an error status")
                return output, 503
