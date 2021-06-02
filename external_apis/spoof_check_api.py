import os
from flask_restful import Resource, reqparse, request, inputs
import socket
import redis
from rq import Retry, Queue
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check, queue_to_db, spoofcheck
from helpers.mongo_connection import db

# add_to_db = Queue(name='spoofCheck_db_queue', connection=redis.from_url(url='rediss://default:kzodr4urcjdpew09@pyscan-redis-stage-do-user-8532994-0.b.db.ondigitalocean.com:25061'))

portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('spoofCheck', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class SpoofCheck(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        list_scans = {}
        val = args['value']
        db.spoofCheck.create_index('value')
        # see if we have an existing scan for given value and pull the latest
        search = db.spoofCheck.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

        # force comes in as false by default
        if args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)
                # add the actual value in(URL)
                item = db.spoofCheck.insert_one(
                    {'ip': ip, 'value': val,
                     "timeStamp": datetime.utcnow()}).inserted_id

                list_scans['ip'] = ip
                list_scans['value'] = val

                out = spoofcheck.main_check(val)

                list_scans['spoofCheck'] = out
            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            del search['_id']
            del search['timeStamp']
            return search

        # message = {'mongo': str(item),
        #            'data': list_scans}
        #
        # add_to_db.enqueue(queue_to_db.spoof_check_db_addition, message, retry=Retry(max=3, interval=[10, 30, 60]))

        return list_scans
