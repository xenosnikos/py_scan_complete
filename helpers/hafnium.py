import pymongo
import redis
import validators
from rq import Queue, Retry

import queue_to_db

queue_connection = redis.from_url(
            url='rediss://default:kzodr4urcjdpew09@pyscan-redis-stage-do-user-8532994-0.b.db.ondigitalocean.com:25061')

client = pymongo.MongoClient("mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = client.test


class Hafnium:

    @staticmethod
    def db_queue(queue_name, data):
        queue = Queue(name=queue_name, connection=queue_connection)
        if queue_name == 'hafnium_request':
            worker = queue_to_db.spoof_check_db_addition
        elif queue_name == 'hafnium_scan':
            worker = queue_to_db.spoof_check_db_addition
        try:
            queue.enqueue(worker, data, retry=Retry(max=3, interval=[10, 30, 60]))
        except:
            return False

        return True

    @staticmethod
    def hafnium_request(data):
        if 'status' in data:
            db.hafnium.find_one_and_update({'domain': data['domain']}, {'$set': {'status': data['status']}})
            return True
        else:
            db.hafnium.insert_one({'domain': data['domain'], 'status': 'queued'})
            return False

    @staticmethod
    def validate_domain(domain):
        if not validators.domain(domain):
            return False
        else:
            return True
