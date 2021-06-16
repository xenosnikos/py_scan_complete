import socket
import logging
import validators
from datetime import datetime, timedelta

from helpers.mongo_connection import db
from helpers import common_strings


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
    except:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'])
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


def resolve_domain_ip(data_input):
    return socket.gethostbyname(data_input)


def delete_db_record(value, collection):
    try:
        db[collection].find_one_and_delete({common_strings.strings['mongo_value']: value})
    except:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'])
