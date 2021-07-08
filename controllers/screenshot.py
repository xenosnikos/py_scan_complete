import os
from flask_restful import Resource, reqparse, request, inputs
import socket
from redis import Redis
from rq import Retry, Queue
from helpers.requests_retry import retry_session
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check, queue_to_db
from helpers.mongo_connection import db

portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class ScreenShot(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        list_scans = {}
        val = args['value']
        db.screenShot.create_index('value')
        # see if we have an existing scan for given value and pull the latest
        search = db.screenShot.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

        # force comes in as false by default
        if args['force']:
            force = True
        elif search is not None:
            force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)
                # add the actual value in(URL)
                item = db.screenShot.insert_one(
                    {'ip': ip, 'value': val,
                     "timeStamp": datetime.utcnow()}).inserted_id

                list_scans['ip'] = ip
                list_scans['value'] = val

                # calling api with retries and backoff_factor
                session = retry_session()
                resp = session.get(
                    f"https://website-screenshot.whoisxmlapi.com/api/v1?apiKey={os.environ.get('API_KEY_WHOIS_XML')}"
                    f"&url={val}&credits=DRS&imageOutputFormat=base64")

                if resp.status_code == 200:
                    out = resp.content.decode()

                    list_scans['screenShot'] = out
                else:
                    list_scans['screenShot'] = 'Currently unavailable'
            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            del search['_id']
            del search['timeStamp']
            return search

        return list_scans
