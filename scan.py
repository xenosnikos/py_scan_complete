import os
from flask_restful import Resource, reqparse, request, inputs
import socket
from redis import Redis
from rq import Retry, Queue
import json
import queue_to_db
import requests
import pymongo
from datetime import datetime, timedelta
import validators
import port_scan_rec

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

# queue_port = Queue(name='scan_queue', connection=Redis(host=os.environ.get('REDIS_HOST'), port=int(os.environ.get('REDIS_PORT'))), default_timeout=900)
# queue_ssl = Queue(name='sslyze_queue', connection=Redis(host=os.environ.get('REDIS_HOST'), port=int(os.environ.get('REDIS_PORT'))))
add_to_db = Queue(name='add_db_queue',
                  connection=Redis(host=os.environ.get('REDIS_HOST'), port=int(os.environ.get('REDIS_PORT'))))

portscan_args = reqparse.RequestParser()
# change ip to value
portscan_args.add_argument('value', help='Domain or IP is required to scan', required=True)
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('portScan', type=inputs.boolean, default=False)
portscan_args.add_argument('infrastructureAnalysis', type=inputs.boolean, default=False)
portscan_args.add_argument('connectedDomains', type=inputs.boolean, default=False)
portscan_args.add_argument('domainReputation', type=inputs.boolean, default=False)
portscan_args.add_argument('malwareCheck', type=inputs.boolean, default=False)
portscan_args.add_argument('sslCertificatesChain', type=inputs.boolean, default=False)
portscan_args.add_argument('sslConfiguration', type=inputs.boolean, default=False)
portscan_args.add_argument('screenShot', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=False)


class Scan(Resource):

    def post(self):
        auth = request.headers.get('Authorization')

        if auth != os.environ.get('API_KEY'):
            return {
                       'message': 'Provided token is invalid, please check and try again'
                   }, 401

        args = portscan_args.parse_args()

        list_scans = {}
        val = args['value']

        db.scans.create_index('value')
        search = db.scans.find_one({'value': val}, sort=[('_id', pymongo.DESCENDING)])

        force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

        if args['force']:
            force = True

        if search is None or force is True:

            if validators.domain(val) or validators.ip_address.ipv4(val):
                ip = socket.gethostbyname(val)
                # add the actual value in(URL)
                item = db.scans.insert_one(
                    {'ip': ip, 'value': val,
                     "timeStamp": datetime.utcnow()}).inserted_id

                list_scans['ip'] = ip
                list_scans['value'] = val

                if args['portScan']:
                    resp = requests.get(f"https://api.viewdns.info/portscan/?host={val}&apikey="
                                        f"{os.environ.get('API_KEY_VIEW_DNS')}&output=json")
                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())['response']

                        list_scans['portScan'] = out['port']

                    out = port_scan_rec.callback({'ip': ip,
                                                  'type': 'fast'})

                    if len(out) >= 4:
                        out = port_scan_rec.callback({'ip': ip,
                                                      'type': 'medium'})

                    if len(out) >= 8:
                        out = port_scan_rec.callback({'ip': ip,
                                                      'type': 'slow'})

                    list_scans['internalPortScan'] = out

                if args['infrastructureAnalysis']:
                    resp = requests.get(
                        f"https://api.threatintelligenceplatform.com/v1/infrastructureAnalysis?domainName="
                        f"{val}&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['infrastructureAnalysis'] = out

                if args['connectedDomains']:
                    resp = requests.get(f"https://api.threatintelligenceplatform.com/v1/connectedDomains?domainName="
                                        f"{val}&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['connectedDomains'] = out['domains']

                if args['domainReputation']:
                    resp = requests.get(f"https://api.threatintelligenceplatform.com/v1/reputation?domainName="
                                        f"{val}&mode=fast&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['domainReputation'] = [out]

                if args['malwareCheck']:
                    resp = requests.get(f"https://api.threatintelligenceplatform.com/v1/malwareCheck?domainName="
                                        f"{val}&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['malwareCheck'] = [out]

                if args['sslCertificatesChain']:
                    resp = requests.get(
                        f"https://api.threatintelligenceplatform.com/v1/sslCertificatesChain?domainName="
                        f"{val}&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['sslCertificatesChain'] = out

                if args['sslConfiguration']:
                    resp = requests.get(f"https://api.threatintelligenceplatform.com/v1/sslConfiguration?domainName="
                                        f"{val}&apiKey={os.environ.get('API_KEY_THREAT_INTELLIGENCE')}")

                    if resp.status_code == 200:
                        out = json.loads(resp.content.decode())

                        list_scans['sslConfiguration'] = [out]

                if args['screenShot']:
                    resp = requests.get(
                        f"https://website-screenshot.whoisxmlapi.com/api/v1?apiKey={os.environ.get('API_KEY_WHOIS_XML')}"
                        f"&url={val}&credits=DRS&imageOutputFormat=base64")

                    if resp.status_code == 200:
                        out = resp.content.decode()

                        list_scans['screenShot'] = out

                # queue_port.enqueue(port_scan_rec.callback, message, retry=Retry(max=3, interval=[10, 30, 60]))
                # queue_ssl.enqueue(sslyze_rec.callback, message_sslyze, retry=Retry(max=3, interval=[10, 30, 60]))

            else:
                return {
                           'message': f'{val} is not a valid IP or Domain, please try again'
                       }, 400
        else:
            del search['_id']
            del search['timeStamp']
            return search

        message = {'mongo': str(item),
                   'data': list_scans}

        add_to_db.enqueue(queue_to_db.db_addition, message, retry=Retry(max=3, interval=[10, 30, 60]))

        return list_scans
