import socket

import validators
import pymongo
from datetime import datetime, timedelta

client = pymongo.MongoClient(
    "mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = client.test


def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True


def validate_domain_ip(value):
    if not (validators.domain(value) or validators.ipv4(value)):
        return False
    else:
        return True


def check_force(data, force, collection, timeframe):
    if force:
        return True
    search = db[collection].find_one({'value': data['value']})
    if search is not None:
        if search['status'] == 'running' or search['status'] == 'queued':
            return search['status']
        force = search['timeStamp'] + timedelta(days=timeframe) < datetime.utcnow()

    if force is True and search is not None:
        return True
    elif force is False and search is not None:
        return search
    elif force is False:
        return True


def mark_db_request(data, collection):
    try:
        if 'status' in data:
            db[collection].find_one_and_update({'value': data['value']}, {'$set': {'status': data['status']}})
        else:
            db[collection].update_one({'value': data['value']}, {'$set': {'status': 'queued'}}, upsert=True)
    except:
        return False
    return True


def format_by_ip(sub_domains, out_format):
    out_dict = {}
    out_list = []

    for each in sub_domains:
        try:
            ip = socket.gethostbyname(each)  # we don't need to display sub-domains that do not have an IP
            if out_format:
                if ip in out_dict:
                    out_dict[ip] += [each]
                else:
                    out_dict[ip] = [each]
            else:
                out_list.append(each)
        except:
            pass
    if out_format:
        return out_dict
    else:
        return out_list
