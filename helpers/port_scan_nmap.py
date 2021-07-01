import nmap
import logging

from helpers.mongo_connection import db
from helpers import common_strings, utils

logger = logging.getLogger(common_strings.strings['port-scan'])


def nmap_scan(ip, scan_type):
    nmap_port_scan = nmap.PortScanner()

    if scan_type == utils.PortScanEnum(1).name:
        nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sT -Pn --top-ports 200')
    elif scan_type == utils.PortScanEnum(2).name:
        nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sT -Pn --top-ports 1000')
    elif scan_type == utils.PortScanEnum(3).name:
        nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-p- -sT -Pn')
    else:
        raise Exception('Scan type not recognised')

    scan_output = nmap_port_scanner['scan'][ip]['tcp']

    out = []

    for (key, value) in scan_output.items():
        status_flag = True
        for (k, v) in value.items():
            if k == 'state' and v != 'open':
                status_flag = False
                continue
            if k == 'name' and status_flag is True:
                port_dict = {'port': key, k: v, 'type': '', 'description': ''}
                name_type_description = db.portInfo.find_one({'port': key},
                                                             {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
                if name_type_description is not None:
                    port_dict.update(name_type_description)
                out.append(port_dict)
                continue

    return out
