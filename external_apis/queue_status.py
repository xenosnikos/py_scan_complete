from flask_restful import Resource
from redis import Redis
from rq import Queue


class QueueStatus(Resource):

    def get(self):

        queue1 = Queue(name='scan_queue', connection=Redis(host='localhost', port=31000), default_timeout=900)
        queue2 = Queue(name='sslyze_queue', connection=Redis(host='localhost', port=31000))

        return {
            'scanQueue': queue1.count,
            'sslQueue': queue2.count
        }
