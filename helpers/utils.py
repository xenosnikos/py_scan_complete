import socket
import os
import logging
import validators
from datetime import datetime, timedelta
import nmap
import json
from enum import Enum

from helpers.mongo_connection import db
from helpers.requests_retry import retry_session
from helpers import common_strings


def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True


def validate_domain_or_ip(value):
    if not (validators.domain(value) or validators.ipv4(value)):
        return False
    else:
        return True


def validate_ip(ip):
    if not validators.ipv4(ip):
        return False
    else:
        return True


def check_force(data, force, collection, timeframe):
    if force:
        return True
    db[collection].create_index(common_strings.strings['mongo_value'])
    search = db[collection].find_one({common_strings.strings['mongo_value']: data})

    if search is not None:
        if search['status'] == common_strings.strings['status_running'] or \
                search['status'] == common_strings.strings['status_queued']:
            return search['status']
        else:
            force = search['timeStamp'] + timedelta(days=timeframe) < datetime.utcnow()

    if force is False and search is not None:
        return search
    else:
        return True


def mark_db_request(value, status, collection):
    try:
        db[collection].update_one({common_strings.strings['mongo_value']: value}, {'$set': {'status': status}},
                                  upsert=True)
    except Exception as e:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'], e)
    return True


def get_location_ip(ip):
    session = retry_session()
    resp = session.get(f"{os.environ.get('WHOISXML_IP_LOCATION')}?apiKey={os.environ.get('API_KEY_WHOIS_XML')}"
                       f"&ipAddress={ip}")
    # if location cannot be found or if 3rd party provider has an issue then send an error back
    return json.loads(resp.text)['location'] if resp.status_code == 200 else {'country': common_strings.strings['error']}


def v1_format_by_ip(sub_domains, out_format):
    out_dict = {}
    out_list = []
    out_blacklist = []
    blacklist_dict = {}
    out_sub_domain_count = 0

    blacklist = ['.nat.']

    for each_domain in sub_domains:
        try:
            ip = socket.gethostbyname(each_domain)  # we don't need to display sub-domains that do not have an IP
            for each_item in blacklist:
                if each_item in each_domain:
                    if each_item in blacklist_dict:
                        blacklist_dict[each_item] += 1
                    else:
                        blacklist_dict[each_item] = 1
                    break
            else:
                out_sub_domain_count += 1
                if out_format:
                    if ip in out_dict:
                        out_dict[ip] += [each_domain]
                    else:
                        out_dict[ip] = [each_domain]
                else:
                    out_list.append(each_domain)
        except:
            pass

    for each_blacklist in blacklist_dict:
        out_blacklist.append({'count': blacklist_dict[each_blacklist],
                              'reason': f"Blacklisted because the sub-domain contains '{each_blacklist}'"})

    if out_format:
        return out_dict, out_blacklist, out_sub_domain_count
    else:
        return out_list, out_blacklist, out_sub_domain_count


def format_by_ip(sub_domains, out_format):
    out_dict = {}
    out_list = []
    out_blacklist = []
    blacklist_dict = {}
    out_sub_domain_count = 0

    blacklist = ['.nat.']

    for each_domain in sub_domains:
        try:
            ip = socket.gethostbyname(each_domain)  # we don't need to display sub-domains that do not have an IP
            for each_item in blacklist:
                if each_item in each_domain:
                    if each_item in blacklist_dict:
                        blacklist_dict[each_item] += 1
                    else:
                        blacklist_dict[each_item] = 1
                    break
            else:
                out_sub_domain_count += 1
                if out_format:
                    if ip in out_dict:
                        out_dict[ip] += [each_domain]
                    else:
                        out_dict[ip] = [each_domain]
                else:
                    out_list.append(each_domain)
        except:
            pass

    if out_format:
        for each_item in out_dict:
            out_list.append({'ip': each_item, 'domains': out_dict[each_item],
                             common_strings.strings['location']: get_location_ip(each_item)})

    for each_blacklist in blacklist_dict:
        out_blacklist.append({'count': blacklist_dict[each_blacklist],
                              'reason': f"Blacklisted because the sub-domain contains '{each_blacklist}'"})

    return out_list, out_blacklist, out_sub_domain_count


def resolve_domain_ip(data_input):
    return socket.gethostbyname(data_input)


def ip_reachable_check(ip):
    scanner = nmap.PortScanner()
    result = scanner.scan(ip, '1', '-v')['scan'][ip]['status']['state']
    if result == 'up':
        return True
    else:
        raise Exception('IP is not up')


def delete_db_record(value, collection):
    try:
        db[collection].find_one_and_delete({common_strings.strings['mongo_value']: value})
    except Exception as e:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'], e)


class PortScanEnum(Enum):
    quick = 1
    regular = 2
    full = 3
