from bson.objectid import ObjectId
import socket, threading
from queue import Queue
import pymongo
import logging
import os


client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

logging.basicConfig(filename='port_scan.log', format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

socket.setdefaulttimeout(3)
print_lock = threading.Lock()

ports = []
countp = 0
ip = None


def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conx = s.connect((ip, port))
        ports.append(port)
        with print_lock:
            print(port, 'is open')
        conx.close()
    except:
        pass


def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()


def callback(body):
    logging.info(f'message {body} from queue is received')
    print(" [x] Received %r" % body)
    global ip
    ip = body['ip']

    if body['type'] == 'fast':
        scan_list = db.portPriority.find({'count': {'$gte': 100000}}, {'_id': 0, 'port': 1})
        thread = 153
    elif body['type'] == 'medium':
        scan_list = db.portPriority.find({'count': {'$gte': 1000}}, {'_id': 0, 'port': 1})
        thread = 1000
    else:
        scan_list = db.portPriority.find({}, {'_id': 0, 'port': 1})
        thread = int(os.environ.get('MAX_THREADS'))

    for x in range(thread):
        t = threading.Thread(target=threader)
        t.start()

    for worker in scan_list:
        q.put(worker['port'])

    q.join()
    obj = {}
    for each in ports:
        obj[str(each)] = db.portInfo.find_one({'port': each}, {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
    # db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanStatus': 'finished', 'openPorts': obj}})
    print('done')
    logging.info(f'message {body} from queue is complete')
    return obj


q = Queue()
