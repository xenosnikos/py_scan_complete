import pymongo
from datetime import datetime

client = pymongo.MongoClient(
    "mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = client.test


class Logging:

    @staticmethod
    def add(process, action, result):
        value = {'process': process,
                 'action': action,
                 'result': result,
                 'when': datetime.utcnow()}

        db.logs.insert(value)
