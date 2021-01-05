from bson import json_util
from bson.objectid import ObjectId
import socket, threading
from queue import Queue
import pika
import pymongo

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='rabbitmq', heartbeat=0))
channel = connection.channel()

channel.queue_declare(queue='scan_queue', durable=True)

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
    count = 10
    while True:
        count += 1
        worker = q.get()
        portscan(worker)
        q.task_done()


def callback(ch, method, properties, body):
    print(" [x] Received %r" % body.decode())
    json_loaded = json_util.loads(body)
    global ip
    ip = json_loaded['ip']
    item_id = json_loaded['scan_id']
    db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'status': 'running'}})

    for x in range(333):
        t = threading.Thread(target=threader)
        t.start()

    for worker in range(1, 65535):
        q.put(worker)

    q.join()
    db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'status': 'finished', 'openPorts': ports}})
    print(" [x] Done")
    ch.basic_ack(delivery_tag=method.delivery_tag)


q = Queue()
channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue='scan_queue', on_message_callback=callback)
channel.start_consuming()
