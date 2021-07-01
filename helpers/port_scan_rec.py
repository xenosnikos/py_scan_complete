import socket
import threading
import queue
import os
import logging

from helpers import common_strings, utils
from helpers.mongo_connection import db

socket.setdefaulttimeout(3)

ports = []
ip = None

logger = logging.getLogger(common_strings.strings['port-scan'])


def scan(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            ports.append(port)
        except ConnectionRefusedError:
            logger.debug(f"Connection refused, port: {port}")
        except socket.timeout:
            pass
        except Exception as e:
            print(f'Exception occurred {e}')


def threader():
    while True:
        try:
            worker = q.get(timeout=0.1)
        except queue.Empty:
            break
        scan(worker)
        q.task_done()


def port_scan(input_ip, scan_type):
    global ports
    global ip
    ip = input_ip
    logger.debug(f'{ip} is received for port scan')

    if scan_type == utils.PortScanEnum.quick.name:
        scan_list = db.portPriority.find({'count': {'$gte': 38000}}, {'_id': 0, 'port': 1})
        thread = 200
    elif scan_type == utils.PortScanEnum.regular.name:
        scan_list = db.portPriority.find({'count': {'$gte': 994}}, {'_id': 0, 'port': 1})
        thread = 1001
    elif scan_type == utils.PortScanEnum.full.name:
        scan_list = range(1, 65536)
        thread = int(os.environ.get('MAX_THREADS'))
    else:
        raise Exception('Scan type not recognised')

    for worker in scan_list:
        if type(worker) is dict:
            q.put(worker['port'])
        else:
            q.put(worker)

    logger.debug(f"Worker puts done, {q.qsize()}")

    for x in range(thread):
        t = threading.Thread(target=threader, daemon=False)
        t.start()

    logger.debug(f"Threads created")

    q.join()
    port_list = []

    for each_port in ports:
        port_dict = {'port': each_port, 'name': '', 'type': '', 'description': ''}
        name_type_description = db.portInfo.find_one({'port': each_port},
                                                     {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
        if name_type_description is not None:
            port_dict.update(name_type_description)
        port_list.append(port_dict)

    ports = []
    return port_list


q = queue.Queue()
