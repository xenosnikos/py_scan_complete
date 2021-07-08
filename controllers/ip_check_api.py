from flask_restful import Resource, reqparse, request, inputs
from helpers import auth_check, utils, common_strings, logging_setup

"""
API Call: POST
Endpoint: https://{url}/v2/ip-check?force=true
Body: {
        "value": "idagent.com"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()

request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, default=False)

logger = logging_setup.initialize(common_strings.strings['ip-check'], 'logs/ip-check_api.log')


class IpCheck(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"IP check request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated ip check request received for {value}")
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
                       common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        return {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}
