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
        patch_check = nmap_patch.scan(hosts=ip, arguments='-p 22 -sV -T4 -Pn -d '
                                                          '--script ssh2-enum-algos '
                                                          '--script ssh-publickey-acceptance '
                                                          '--script ssh-auth-methods')
    except Exception as e:
        logger.error(f'SSH scan failed with exception {e}')
    else:
        #Handle results from nmap
        protocol_version = patch_check['scan'][ip]['tcp'][22]['extrainfo']
        auth_methods = patch_check['scan']['143.198.99.85']['tcp'][22]['script']['ssh-auth-methods']
        known_bad_keys = patch_check['scan']['143.198.99.85']['tcp'][22]['script']['ssh-publickey-acceptance']
        ssh_algos = patch_check['scan']['143.198.99.85']['tcp'][22]['script']['ssh2-enum-algos']

    logger.debug(f"SSH scan complete for {ip}")