from flask_restful import Resource
import pika
import rq
import rq_dashboard


class QueueStatus(Resource):

    def get(self):

        return {
            'scanQueue': 'pending',
            'sslQueue': 'pending'
        }
