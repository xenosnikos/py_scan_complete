import socket
import logging
import traceback

import pydnsbl
from helpers import utils

logger = logging.getLogger('blacklist')


def scan(data_input):
    data_input['status'] = 'running'
    utils.mark_db_request(scan, 'blacklist')  # marks data to running from queued in db

    ip = socket.gethostbyname(data_input['value'])

    res = None

    try:
        ip_checker = pydnsbl.DNSBLIpChecker()
        res = ip_checker.check(ip)
    except:
        logger.error('Cannot scan for blacklist')
        logger.error(traceback.format_exc())

    output = {'value': data_input['value'], 'ip': ip}

    if res is not None:
        output['blacklisted'] = res.blacklisted
        output['source'] = res.detected_by
    else:
        output['blacklisted'] = 'Unknown'
        output['source'] = {}

    return output
