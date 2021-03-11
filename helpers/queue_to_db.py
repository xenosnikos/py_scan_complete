import logging
import pymongo
from bson import ObjectId
from datetime import datetime, timedelta

client = pymongo.MongoClient('mongodb+srv://san:U652JqPlfdYFdwDp@cluster0.aove7.mongodb.net/test?retryWrites=true&w=majority')
db = client.test

logging.basicConfig(filename='logs/add_to_db.log', format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)


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


def hafnium_db_addition(value):
    # check if the incoming queued database request is for on-prem/cloud by checking
    # if a record is inserted into database and we have a value for it
    if 'mongo' in value:
        # check for whether any endpoint is not returned as false
        if value['issue_found']:
            count = 0
            for key, val in value['endpoints'].items():
                if val is not False:
                    count += 1
            db.hafniumScan.find_one_and_update({'_id': ObjectId(value['mongo'])},
                                               {'$set': {'results': value['endpoints'],
                                                         'breached': True, 'breach_count': count}})
        else:
            db.hafniumScan.find_one_and_update({'_id': ObjectId(value['mongo'])},
                                               {'$set': {'results': value['endpoints']}})
    else:
        # see if we have an existing scan for given value and pull the latest
        search = db.hafniumScan.find_one({'value': value['domain'], 'mx_record': value['mx_record']},
                                         sort=[('_id', pymongo.DESCENDING)])
        if search is not None:
            value['force'] = search['timeStamp'] + timedelta(days=2) < datetime.utcnow()
        if search is None or value['force'] is True:
            db.hafniumScan.insert_one(
                {'value': value['domain'],
                 'mx_record': value['mx_record'],
                 'ip': value['ip'],
                 'patch_status': value['patch_status'],
                 'type': 'cloud',
                 'breached': False,
                 'breach_count': 0,
                 "timeStamp": datetime.utcnow()})
