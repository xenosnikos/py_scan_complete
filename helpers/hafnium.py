import pymongo
import redis
import validators
from rq import Queue, Retry
from datetime import datetime, timedelta

from helpers import queue_to_db, hafnium_scan

queue_connection = redis.from_url(
            url='rediss://default:kzodr4urcjdpew09@pyscan-redis-stage-do-user-8532994-0.b.db.ondigitalocean.com:25061')

client = pymongo.MongoClient("mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = client.test


def db_queue(queue_name, data):
    queue = Queue(name=queue_name, connection=queue_connection, default_timeout=-1)
    if queue_name == 'hafnium_response':
        worker = queue_to_db.hafnium_response_db_addition
    elif queue_name == 'hafnium_scan':
        worker = hafnium_scan.process
    try:
        queue.enqueue(worker, data, retry=Retry(max=3, interval=[10, 30, 60]))
    except:
        return False

    return True


def hafnium_request(data):
    try:
        if 'status' in data:
            db.hafnium.find_one_and_update({'domain': data['domain']}, {'$set': {'status': data['status']}})
        else:
            db.hafnium.update_one({'domain': data['domain']}, {'$set': {'status': 'queued'}}, upsert=True)
    except:
        return False
    return True


def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True


def check_force(data, force):
    if force:
        return True
    search = db.hafnium.find_one({'domain': data['domain']})
    if search is not None:
        if search['status'] == 'running' or search['status'] == 'queued':
            return search['status']
        force = search['timeStamp'] + timedelta(days=1) < datetime.utcnow()

    if force is True and search is not None:
        return True
    elif force is False and search is not None:
        return search['status']
    elif force is False:
        return True


def hafnium_response(domain):
    resp = db.hafnium.find_one({'domain': domain})
    if resp is not None:
        if 'output' in resp:
            return resp['output']
        else:
            return {'status': resp['status']}
    else:
        return 404
