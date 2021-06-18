import pymongo
import os

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client[os.environ.get('MONGO_DB')]
