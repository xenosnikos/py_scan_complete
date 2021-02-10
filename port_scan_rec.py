from bson.objectid import ObjectId
import socket, threading
from queue import Queue
import pymongo
import logging


client = pymongo.MongoClient(open('mongo_string.txt').read())
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
    item_id = body['scan_id']
    db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanStatus': 'running'}})

    for x in range(333):
        t = threading.Thread(target=threader)
        t.start()

    init = 655 * 5

    for worker in range(1, 65535):
        if worker == init:
            db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanPercentage': worker//655}})
            init += 655 * 5
        q.put(worker)

    q.join()
    obj = {}
    for each in ports:
        obj[str(each)] = db.portInfo.find_one({'port': each}, {'_id': 0, 'name': 1, 'type': 1, 'description': 1})
    db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'portScanStatus': 'finished', 'openPorts': obj}})
    logging.info(f'message {body} from queue is complete')


q = Queue()
