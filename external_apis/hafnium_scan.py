import os
from flask_restful import Resource, reqparse, request, inputs
import socket
import dns.resolver
from redis import Redis
from rq import Retry, Queue
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check
import requests
import nmap
import helpers

client = pymongo.MongoClient(os.environ.get('MONGO_CONN'))
db = client.test

add_to_db = Queue(name='hafniumScan_db_queue',
                  connection=Redis(host='pyscan-redis-stage-do-user-8532994-0.b.db.ondigitalocean.com', port='25061', username='default', password='kzodr4urcjdpew09', ssl=True))

portscan_args = reqparse.RequestParser()

portscan_args.add_argument('value', help='Domain is required to scan', required=True, action='append')
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('hafniumScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=True)


class HafniumScan(Resource):

    @staticmethod
    def post():
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        breach_outputs = {}
        db.hafniumScan.create_index([('value', pymongo.ASCENDING), ('mx_record', pymongo.ASCENDING)])

        check_ep = ('/owa/auth/web.aspx', '/owa/auth/help.aspx', '/owa/auth/document.aspx', '/owa/auth/errorEE.aspx',
                    '/owa/auth/errorEEE.aspx', '/owa/auth/errorEW.aspx', '/owa/auth/errorFF.aspx',
                    '/owa/auth/healthcheck.aspx', '/owa/auth/aspnet_www.aspx', '/owa/auth/aspnet_client.aspx',
                    '/owa/auth/xx.aspx', '/owa/auth/shell.aspx', '/owa/auth/aspnet_iisstart.aspx', '/owa/auth/one.aspx', '/aspnet_client', '/aspnet_client/system_web', '/OAB')

        for target in args['value']:

            if not validators.domain(target):
                return {
                           'message': f'{target} is not a valid domain, please try again'
                       }, 400

            mx_records = []
            mx_on_prem_records = {}
            mx_cloud_records = {}
            mx_patch_status = {}

            try:
                for mx_record in dns.resolver.query(target, 'MX'):
                    # Ternary operator
                    mx_records.append(str(mx_record.exchange)[:len(str(mx_record.exchange)) - 1] if
                                      str(mx_record.exchange)[len(str(mx_record.exchange)) - 1] == '.' else
                                      str(mx_record.exchange))
            except:
                return {
                    target: {'No MX': 'None'}
                }

            for each in mx_records:
                try:
                    ip = socket.gethostbyname(each)
                except:
                    mx_cloud_records['No MX'] = 'None'
                    continue
                nmap_patch = nmap.PortScanner()
                patch_check = nmap_patch.scan(hosts=ip, ports='443', arguments='--script=/usr/local/share/nmap'
                                                                               '/scripts/http-vuln-cve2021-26855.nse')
                # Check to see if this path exists in the nmap result:
                # patch_check['scan']['50.245.242.69']['tcp'][443]['script']['http-vuln-cve2021-26855']
                if 'scan' in patch_check and ip in patch_check['scan'] and 'tcp' in patch_check['scan'][ip] and 443 in \
                        patch_check['scan'][ip]['tcp'] and 'script' in patch_check['scan'][ip]['tcp'][443] and \
                        'http-vuln-cve2021-26855' in patch_check['scan'][ip]['tcp'][443]['script']:
                    mx_patch_status[each] = 'vulnerable'
                else:
                    mx_patch_status[each] = 'patched'
                if target == each[-len(target):]:
                    mx_on_prem_records[each] = ip
                else:
                    mx_cloud_records[each] = 'Cloud'
                    message = {'domain': target,
                               'mx_record': each,
                               'ip': ip,
                               'patch_status': mx_patch_status[each],
                               'force': args['force']}

                    add_to_db.enqueue('helpers.queue_to_db.hafnium_db_addition', message,
                                      retry=Retry(max=3, interval=[10, 30, 60]))

            print(mx_records)

            if len(mx_on_prem_records) == 0:
                breach_outputs[target] = mx_cloud_records
                continue

            mx_outputs = {}

            for target_value, target_ip in mx_on_prem_records.items():
                print(target_value)

                # see if we have an existing scan for given value and pull the latest
                search = db.hafniumScan.find_one({'value': target, 'mx_record': target_value},
                                                 sort=[('_id', pymongo.DESCENDING)])

                # force comes in as true by default
                if args['force']:
                    force = True
                elif search is not None:
                    force = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()

                if search is None or force is True:
                    item = db.hafniumScan.insert_one(
                        {'value': target,
                         'mx_record': target_value,
                         'ip': target_ip,
                         'patch_status': mx_patch_status[target_value],
                         'type': 'on-prem',
                         'breached': False,
                         'breach_count': 0,
                         "timeStamp": datetime.utcnow()}).inserted_id

                    ip_breaches = {}
                    last_endpoint = None
                    issue_found = False
                    count = 0
                    data = {}

                    for endpoint in check_ep:
                        print(endpoint)
                        url = f"https://{target_ip}{endpoint}"

                        if last_endpoint is not None and data[last_endpoint] == 'Connection Refused':
                            data[endpoint] = 'Connection Refused'
                            continue

                        try:
                            resp = requests.get(url=url, verify=False)
                        except requests.exceptions.ConnectionError:
                            last_endpoint = endpoint
                            data[endpoint] = 'Connection Refused'
                            continue
                        except requests.exceptions.TooManyRedirects:
                            data[endpoint] = 'Too many Redirects'
                            continue

                        if resp.status_code == 200:
                            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                                data[endpoint] = False
                                continue
                            else:
                                finding = {'etag': resp.headers['ETag'] if 'ETag' in resp.headers else False,
                                           'powered': resp.headers[
                                               'X-Powered-By'] if 'X-Powered-By' in resp.headers else False,
                                           'server': resp.headers['Server'] if 'Server' in resp.headers else False}
                                data[endpoint] = finding
                                issue_found = True
                        else:
                            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                                data[endpoint] = False
                                continue
                            else:
                                data[endpoint] = f'Status Code: {resp.status_code}'

                    ip_breaches['ip'] = target_ip
                    ip_breaches['patch_status'] = mx_patch_status[target_value]
                    ip_breaches['type'] = 'on-prem'
                    ip_breaches['breached'] = issue_found
                    ip_breaches['count'] = count
                    ip_breaches['data'] = data

                    if len(mx_cloud_records) != 0:
                        mx_outputs.update(mx_cloud_records)
                    mx_outputs[target_value] = ip_breaches

                    if search is None or force is True:
                        message = {'mongo': str(item),
                                   'endpoints': ip_breaches,
                                   'issue_found': issue_found}

                        add_to_db.enqueue('helpers.queue_to_db.hafnium_db_addition', message,
                                          retry=Retry(max=3, interval=[10, 30, 60]))

                else:
                    del search['_id']
                    del search['timeStamp']
                    mx_outputs[target_value] = search

            breach_outputs[target] = mx_outputs

        return breach_outputs
