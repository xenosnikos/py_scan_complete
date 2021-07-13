import nmap
import socket
import logging

from helpers import utils, common_strings

logger = logging.getLogger(common_strings.strings['ssh'])
socket.setdefaulttimeout(3)


def process(ip):
    #Marks as running in db
    utils.mark_db_request(value=ip, status=common_strings.strings['status_running'],
                          collection=common_strings.strings['ssh'])

    output = {}

    nmap_patch = nmap.PortScanner()

    try:
        patch_check = nmap_patch.scan(hosts=ip, arguments='-p 22 -T4 -Pn -d')
    except Exception as e:
        logger.error(f'SSH scan failed with exception {e}')