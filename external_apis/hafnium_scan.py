import os
from flask_restful import Resource, reqparse, request, inputs
import socket, threading
import dns.resolver
import pymongo
from datetime import datetime, timedelta
import validators
from helpers import auth_check
import requests
import nmap
from queue import Queue
import time


portscan_args = reqparse.RequestParser()
portscan_args.add_argument('value', help='Domain is required to scan', required=True, action='append')
portscan_args.add_argument('companyId', help='Company ID is required to associate scan results', required=True)
portscan_args.add_argument('domainId', help='Domain ID is required to associate company with different domains',
                           required=True)
portscan_args.add_argument('hafniumScan', type=inputs.boolean, default=False)
portscan_args.add_argument('force', type=inputs.boolean, default=True)

data = {}
issue_found = False
count = 0
q = Queue()
exit_event = threading.Event()


class HafniumScan(Resource):

    @staticmethod
    def ep_check(url):
        global data, issue_found, count
        try:
            resp = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError:
            data[url] = 'Connection Refused'
            return
        except requests.exceptions.TooManyRedirects:
            data[url] = 'Too many Redirects'
            return

        if resp.status_code == 200:
            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                data[url] = False
                return
            else:
                finding = {'etag': resp.headers['ETag'] if 'ETag' in resp.headers else False,
                           'powered': resp.headers[
                               'X-Powered-By'] if 'X-Powered-By' in resp.headers else False,
                           'server': resp.headers['Server'] if 'Server' in resp.headers else False}
                data[url] = finding
                issue_found = True
                count += 1
        else:
            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                data[url] = False
                return
            else:
                data[url] = resp.status_code

    @staticmethod
    def threader():
        while True:
            worker = q.get()
            HafniumScan.ep_check(worker)
            q.task_done()
            break

    @staticmethod
    def post():
        global data, issue_found, count, q
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            return authentication, 401

        args = portscan_args.parse_args()

        breach_outputs = {}

        check_ep = ('shellex.aspx', 'iistart.aspx', 'one.aspx', 't.aspx', 'aspnettest.aspx', 'error.aspx',
                    'discover.aspx', 'supp0rt.aspx', 'shell.aspx', 'HttpProxy.aspx', '0QWYSEXe.aspx', 'load.aspx',
                    'sol.aspx', 'RedirSuiteServerProxy.aspx', 'OutlookEN.aspx', 'errorcheck.aspx', 'web.aspx',
                    'help.aspx', 'document.aspx', 'errorEE.aspx', 'errorEEE.aspx', 'errorEW.aspx', 'errorFF.aspx',
                    'healthcheck.aspx', 'aspnet_www.aspx', 'aspnet_client.aspx', 'xx.aspx', 'aspnet_iisstart.aspx')

        folders = ('/aspnet_client/', '/aspnet_client/system_web/', '/owa/auth/')

        for target in args['value']:

            if not validators.domain(target):
                return {
                           'message': f'{target} is not a valid domain, please try again'
                       }, 400

            mx_records = set()
            mx_on_prem_records = {}
            mx_cloud_records = {}
            mx_patch_status = {}

            try:
                for mx_record in dns.resolver.query(target, 'MX'):
                    # Ternary operator
                    mx_records.add(str(mx_record.exchange)[:len(str(mx_record.exchange)) - 1] if
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
                    mx_cloud_records[each] = 'Cannot resolve IP'
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

            if len(mx_on_prem_records) == 0:
                breach_outputs[target] = mx_cloud_records
                continue

            mx_outputs = {}

            print(mx_records)

            for target_value, target_ip in mx_on_prem_records.items():
                print(target_value)
                ip_breaches = {}

                for x in range(84):
                    t = threading.Thread(target=HafniumScan.threader, daemon=False)
                    t.start()

                data = {}
                issue_found = False
                count = 0

                for folder in folders:
                    for endpoint in check_ep:
                        url = None
                        print(folder+endpoint)
                        url = f"https://{target_value}{folder}{endpoint}"

                        q.put(url)

                q.join()

                ip_breaches['ip'] = target_ip
                ip_breaches['patch_status'] = mx_patch_status[target_value]
                ip_breaches['type'] = 'on-prem'
                ip_breaches['breached'] = issue_found
                ip_breaches['count'] = count
                ip_breaches['data'] = data

                if len(mx_cloud_records) != 0:
                    mx_outputs.update(mx_cloud_records)
                mx_outputs[target_value] = ip_breaches

            breach_outputs[target] = mx_outputs
            time.sleep(2)

        return breach_outputs
