from bson import ObjectId
from datetime import datetime
from helpers import logs, common_strings
from helpers.mongo_connection import db


def blacklist_db_addition(value, output):
    db.blacklist.find_one_and_update({common_strings.strings['mongo_value']: value},
                                     {'$set': {'status': common_strings.strings['status_finished'],
                                               'timeStamp': datetime.utcnow(), 'output': output}})


# in v1 we do not do status returns if something is in progress for port scan as ePlace doesn't expect that, so once we
# have completed results we store them in database for a later retrieval, that's why we have an upsert=True argument
def v1_port_scan_db_addition(value, output):
    db.portScan.find_one_and_update({common_strings.strings['mongo_value']: value},
                                    {'$set': {'status': common_strings.strings['status_finished'],
                                              'timeStamp': datetime.utcnow(), 'output': output}}, upsert=True)


def port_scan_db_addition(value, output, collection):
    db[collection].find_one_and_update({common_strings.strings['mongo_value']: value},
                                       {'$set': {'status': common_strings.strings['status_finished'],
                                                 'timeStamp': datetime.utcnow(), 'output': output}})


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
    db.hafnium.find_one_and_update({'domain': value['domain']}, {
        '$set': {'status': 'finished', 'timeStamp': datetime.utcnow(), 'output': value['output']}})
    logs.Logging.add('hafnium scan', value['domain'], 'adding completed records to DB', 'response queue job complete')


def rdp_response_db_addition(value, output):
    db.rdp.find_one_and_update({common_strings.strings['mongo_value']: value},
                               {'$set': {'status': common_strings.strings['status_finished'],
                                         'timeStamp': datetime.utcnow(), 'output': output}})


def expansion_response_db_addition(value, output):
    db.expansion.find_one_and_update({common_strings.strings['mongo_value']: value},
                                     {'$set': {'status': common_strings.strings['status_finished'],
                                               'timeStamp': datetime.utcnow(), 'output': output}})


def darkweb_response_db_addition(value, output):
    db.darkweb.find_one_and_update({common_strings.strings['mongo_value']: value},
                                   {'$set': {'status': common_strings.strings['status_finished'],
                                             'timeStamp': datetime.utcnow(), 'output': output}})
