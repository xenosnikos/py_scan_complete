import socket, threading
from queue import Queue
import pymongo
import logging
import os
import sys

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

logging.basicConfig(filename='logs/port_scan.log', format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)

socket.setdefaulttimeout(3)
print_lock = threading.Lock()

ports = []
countp = 0
ip = None


def portscan(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            ports.append(port)
            with print_lock:
                print(port, 'is open')
            # s.close()
        except ConnectionRefusedError:
            logger.info(f"Connection refused, port: {port}")
        except socket.timeout:
            pass
        except Exception as e:
            print(f'Exception occurred {e}')


def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()
        if q.empty():
            break


def callback(body):
    global ports
    logger.info(f'message {body} from queue is received')
    print(" [x] Received %r" % body)
    global ip
    ip = body['ip']

    if body['type'] == 'fast':
        scan_list = db.portPriority.find({'count': {'$gte': 100000}}, {'_id': 0, 'port': 1})
        logger.info(f"Output of scan_list1, {scan_list}")
        thread = 153
    elif body['type'] == 'medium':
        scan_list = db.portPriority.find({'count': {'$lt': 100000, '$gte': 1000}}, {'_id': 0, 'port': 1})
        logger.info(f"Output of scan_list2, {scan_list}")
        thread = 800
    else:
        # scan_list = db.portPriority.find({'count': {'$lt': 1000}}, {'_id': 0, 'port': 1})
        scan_list = range(1, 65536)
        logger.info(f"Output of scan_list3, {scan_list}")
        thread = int(os.environ.get('MAX_THREADS'))
        logger.info(f"Environment variable {os.environ.get('MAX_THREADS')} to Max Threads")

    for worker in scan_list:
        if type(worker) is dict:
            q.put(worker['port'])
        else:
            q.put(worker)

    logger.info(f"Worker puts done, {q.qsize()}")

    for x in range(thread):
        t = threading.Thread(target=threader, daemon=False)
        t.start()

    logger.info(f"Threads created")

    q.join()
    obj = {}
    for each in ports:
        obj[str(each)] = db.portInfo.find_one({'port': each}, {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
    # db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanStatus': 'finished', 'openPorts': obj}})
    print('done')
    logger.info(f'message {body} from queue is complete')
    ports = []
    return obj


q = Queue()
