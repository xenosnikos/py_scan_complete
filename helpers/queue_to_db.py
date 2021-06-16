from bson import ObjectId
from datetime import datetime
from helpers import logs, common_strings
from helpers.mongo_connection import db


def blacklist_db_addition(value, output):
    db.blacklist.find_one_and_update({common_strings.strings['mongo_value']: value},
                                     {'$set': {'status': common_strings.strings['status_finished'],
                                               'timeStamp': datetime.utcnow(), 'output': output}})


def port_scan_db_addition(value):
    db.portScan.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def infrastructure_analysis_db_addition(value):
    db.infrastructureAnalysis.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def connected_domains_db_addition(value):
    db.connectedDomains.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def domain_reputation_db_addition(value):
    db.domainReputation.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def malware_check_db_addition(value):
    db.malwareCheck.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def ssl_certificates_chain_db_addition(value):
    db.sslCertificatesChain.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def ssl_configuration_db_addition(value):
    db.sslConfiguration.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def screenshot_db_addition(value):
    db.screenShot.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def spoof_check_db_addition(value):
    db.spoofCheck.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def trustymail_db_addition(value):
    db.trustyMail.find_one_and_update({'_id': ObjectId(value['mongo'])}, {'$set': value['data']})


def hafnium_response_db_addition(value):
    db.hafnium.find_one_and_update({'domain': value['domain']}, {'$set': {'status': 'finished', 'timeStamp': datetime.utcnow(), 'output': value['output']}})
    logs.Logging.add('hafnium scan', value['domain'], 'adding completed records to DB', 'response queue job complete')


def rdp_response_db_addition(value):
    db.rdp.find_one_and_update({'value': value['value']}, {'$set': {'status': 'finished', 'timeStamp': datetime.utcnow(), 'output': value['output']}})
    logs.Logging.add('RDP scan', value['value'], 'adding completed records to DB', 'job complete')


def expansion_response_db_addition(value):
    output = {
        'value': value['value'],
        'count': value['count'],
        'sub_domains': value['sub_domains']
    }
    db.expansion.find_one_and_update({'value': value['value']}, {'$set': {'status': 'finished', 'timeStamp': datetime.utcnow(), 'output': output}})
    logs.Logging.add('Expansion scan', value['value'], 'adding completed records to DB', 'job complete')