import socket, threading
from queue import Queue
import os

from mongo_connection import db

socket.setdefaulttimeout(3)

ports = []
ip = None


# Not in use after NMAP scanning, wanted to leave the code just in case
def scan(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            ports.append(port)
        except ConnectionRefusedError:
            print(f"Connection refused, port: {port}")
            # logger.info(f"Connection refused, port: {port}")
        except socket.timeout:
            pass
        except Exception as e:
            print(f'Exception occurred {e}')


def threader():
    while True:
        worker = q.get()
        scan(worker)
        q.task_done()
        if q.empty():
            break


def port_scan(input_ip, scan_type):
    global ports
    global ip
    ip = input_ip
    # logger.info(f'message {ip} from queue is received')
    print(" [x] Received %r" % ip)

    if scan_type == 'quick':
        scan_list = db.portPriority.find({'count': {'$gte': 38000}}, {'_id': 0, 'port': 1})
        thread = 170
    elif scan_type == 'full':
        scan_list = range(1, 65536)
        thread = int(os.environ.get('MAX_THREADS'))
        # logger.info(f"Environment variable {os.environ.get('MAX_THREADS')} to Max Threads")
    else:
        scan_list = db.portPriority.find({'count': {'$gte': 994}}, {'_id': 0, 'port': 1})
        thread = 900

    for worker in scan_list:
        if type(worker) is dict:
            q.put(worker['port'])
        else:
            q.put(worker)

    # logger.info(f"Worker puts done, {q.qsize()}")

    for x in range(thread):
        t = threading.Thread(target=threader, daemon=False)
        t.start()

    # logger.info(f"Threads created")

    q.join()
    obj = {}

    for each in ports:
        obj[str(each)] = db.portInfo.find_one({'port': each}, {'_id': 0, 'name': 1, 'type': 1, 'description': 1})

    ports = []
    return obj


q = Queue()
