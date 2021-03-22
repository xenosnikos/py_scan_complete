import socket, threading
import dns.resolver
import requests
import nmap
from queue import Queue
from helpers import hafnium, logs

data = {}
issue_found = False
count = 0
q = Queue()


class HafniumScan():

    @staticmethod
    def ep_check(url):
        global data, issue_found, count
        try:
            resp = requests.get(url=url, verify=False, timeout=300)
        except requests.exceptions.ConnectionError:
            data[url] = 'Connection Refused'
            return
        except requests.exceptions.TooManyRedirects:
            data[url] = 'Too many Redirects'
            return
        except requests.exceptions.ReadTimeout:
            data[url] = 'Read Timeout'
            return
        except Exception as e:
            data[url] = 'Request exception'
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


def process(scan):
    global data, issue_found, count, q
    scan['status'] = 'running'
    hafnium.hafnium_request(scan)

    breach_outputs = {}

    check_ep = ('shellex.aspx', 'iistart.aspx', 'one.aspx', 't.aspx', 'aspnettest.aspx', 'error.aspx',
                'discover.aspx', 'supp0rt.aspx', 'shell.aspx', 'HttpProxy.aspx', '0QWYSEXe.aspx', 'load.aspx',
                'sol.aspx', 'RedirSuiteServerProxy.aspx', 'OutlookEN.aspx', 'errorcheck.aspx', 'web.aspx',
                'help.aspx', 'document.aspx', 'errorEE.aspx', 'errorEEE.aspx', 'errorEW.aspx', 'errorFF.aspx',
                'healthcheck.aspx', 'aspnet_www.aspx', 'aspnet_client.aspx', 'xx.aspx', 'aspnet_iisstart.aspx')

    folders = ('/aspnet_client/', '/aspnet_client/system_web/', '/owa/auth/')

    target = scan['domain']

    mx_records = set()
    mx_on_prem_records = {}
    mx_cloud_records = {}
    mx_patch_status = {}

    logs.Logging.add('hafnium scan', target, 'scan start', 'starting')

    try:
        for mx_record in dns.resolver.query(target, 'MX'):
            # Ternary operator
            mx_records.add(str(mx_record.exchange)[:len(str(mx_record.exchange)) - 1] if
                           str(mx_record.exchange)[len(str(mx_record.exchange)) - 1] == '.' else
                           str(mx_record.exchange))
    except:
        resp = {'domain': scan['domain'], 'output': {scan['domain']: {'No MX': 'None'}}}
        hafnium.db_queue('hafnium_response', resp)
        return

    for each in mx_records:
        logs.Logging.add('hafnium scan', target, f'resolving ips and determining patch status of {each}', 'starting')
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

        logs.Logging.add('hafnium scan', target, f'resolved ip and determining patch status of {each}', 'starting')

    if len(mx_on_prem_records) == 0:
        breach_outputs[target] = mx_cloud_records

    mx_outputs = {}

    for target_value, target_ip in mx_on_prem_records.items():

        logs.Logging.add('hafnium scan', target, 'starting on prem check', target_value)

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

        logs.Logging.add('hafnium scan', target, 'finished on prem check', 'complete')

        breach_outputs[target] = mx_outputs

    logs.Logging.add('hafnium scan', target, 'scan of all records complete', 'sending to the response queue')

    response = {'domain': scan['domain'], 'output': breach_outputs}

    hafnium.db_queue('hafnium_response', response)
