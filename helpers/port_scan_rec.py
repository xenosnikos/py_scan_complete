import socket, threading
from queue import Queue
import pymongo
import logging
import os

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

logging.basicConfig(filename='../logs/port_scan.log', format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

socket.setdefaulttimeout(3)
print_lock = threading.Lock()

ports = []
countp = 0
ip = None


def portscan(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        logging.info(f"s created, {s}")
        try:
            s.connect((ip, port))
            logging.info(f"Connection successful, {s}")
            ports.append(port)
            with print_lock:
                print(port, 'is open')
            s.close()
        except ConnectionRefusedError:
            logging.info(f"Connection refused, {s}")
            ports.append(port)
            with print_lock:
                print(port, 'is being refused')
        except socket.timeout:
            pass


def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()
        if q.empty():
            break


def callback(body):
    global ports
    logging.info(f'message {body} from queue is received')
    print(" [x] Received %r" % body)
    global ip
    ip = body['ip']

    if body['type'] == 'fast':
        scan_list = db.portPriority.find({'count': {'$gte': 100000}}, {'_id': 0, 'port': 1})
        logging.info(f"Output of scan_list1, {scan_list}")
        thread = 153
    elif body['type'] == 'medium':
        scan_list = db.portPriority.find({'count': {'$lt': 100000, '$gte': 1000}}, {'_id': 0, 'port': 1})
        logging.info(f"Output of scan_list2, {scan_list}")
        thread = 800
    else:
        # scan_list = db.portPriority.find({'count': {'$lt': 1000}}, {'_id': 0, 'port': 1})
        scan_list = range(1, 65536)
        logging.info(f"Output of scan_list3, {scan_list}")
        thread = int(os.environ.get('MAX_THREADS'))
        logging.info(f"Environment variable {os.environ.get('MAX_THREADS')} to Max Threads")

    for worker in scan_list:
        if type(worker) is dict:
            q.put(worker['port'])
        else:
            q.put(worker)

    logging.info(f"Worker puts done, {q.qsize()}")

    for x in range(thread):
        t = threading.Thread(target=threader, daemon=False)
        t.start()

    logging.info(f"Threads created")

    q.join()
    obj = {}
    for each in ports:
        obj[str(each)] = db.portInfo.find_one({'port': each}, {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
    # db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanStatus': 'finished', 'openPorts': obj}})
    print('done')
    logging.info(f'message {body} from queue is complete')
    ports = []
    return obj


q = Queue()
