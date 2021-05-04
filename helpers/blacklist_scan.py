import sys
import socket
import logging
import traceback

import pydnsbl
from helpers import utils

logging.basicConfig(filename='logs/blacklist_scan.log', format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)


def scan(data_input):
    data_input['status'] = 'running'
    utils.mark_db_request(scan, 'blacklist')

    ip = socket.gethostbyname(data_input['value'])

    res = None

    try:
        ip_checker = pydnsbl.DNSBLIpChecker()
        res = ip_checker.check(ip)
    except Exception as e:
        logger.error('Cannot scan for blacklist')
        logger.error(traceback.format_exc())

    output = {'value': data_input['value'],
              'ip': ip,
              }

    if res is not None:
        output['blacklisted'] = res.blacklisted
        output['source'] = res.detected_by
    else:
        output['blacklisted'] = 'Unknown'
        output['source'] = {}

    return output
