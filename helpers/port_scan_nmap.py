import pymongo
import logging
import os
import sys

import nmap

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

logging.basicConfig(filename='logs/port_scan.log', format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)


def nmap_scan(ip, priority):
    nmap_port_scan = nmap.PortScanner()

    try:
        if priority == 'high':
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sTU -Pn --top-ports 200')
        elif priority == 'low':
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-p- -sTU -Pn')
        else:
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sTU -Pn --top-ports 1000')
    except:
        nmap_port_scanner = None

    if nmap_port_scanner is not None:
        scan_output = nmap_port_scanner['scan'][ip]['tcp']

        out = {}

        for (key, value) in scan_output.items():
            for (k, v) in value.items():
                if k == 'name':
                    out[key] = {k: v, 'type': '', 'description': ''}
                    continue
    else:
        out = None

    return out
