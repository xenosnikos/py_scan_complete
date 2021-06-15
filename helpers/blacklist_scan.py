import logging
import traceback

import pydnsbl
from helpers import utils, common_strings

logger = logging.getLogger(common_strings.strings['blacklist'])


def scan(data_input, ip):
    # marks data to running from queued in db
    utils.mark_db_request(value=data_input, status=common_strings.strings['status_running'],
                          collection=common_strings.strings['blacklist'])

    res = None

    try:
        ip_checker = pydnsbl.DNSBLIpChecker()
        res = ip_checker.check(ip)
    except Exception as e:
        logger.error(f'Cannot initialize blacklist library - {res, e}')
        logger.error(traceback.format_exc())
        raise

    output = {}

    if res is not None:
        output['blacklisted'] = res.blacklisted
        output['source'] = res.detected_by

    return output
