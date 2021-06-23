import os
from flask_restful import Resource, reqparse, request, inputs
import socket
from redis import Redis
from rq import Retry, Queue
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check, queue_to_db
from helpers.trustymail.scripts import trustymail1
from helpers.mongo_connection import db

portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class TrustyMail(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        list_scans = {}
        val = args['value']
        db.trustyMail.create_index('value')
        # see if we have an existing scan for given value and pull the latest
        search = db.trustyMail.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

        # force comes in as false by default
        if args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)
                # add the actual value in(URL)
                item = db.trustyMail.insert_one(
                    {'ip': ip, 'value': val,
                     "timeStamp": datetime.utcnow()}).inserted_id

                list_scans['ip'] = ip
                list_scans['value'] = val

                out = trustymail1.main(val)

                list_scans['trustyMail'] = out
            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            del search['_id']
            del search['timeStamp']
            return search

        return list_scans
