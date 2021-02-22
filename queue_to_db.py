import logging
import pymongo
from bson import ObjectId
import time
import os

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

logging.basicConfig(filename='add_to_db.log', format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)


def db_addition(value):
    print(value)
    time.sleep(2)
    db.scans.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})
