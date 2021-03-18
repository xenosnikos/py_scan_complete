import logging
import pymongo
from bson import ObjectId
from datetime import datetime
from helpers import logs

client = pymongo.MongoClient("mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
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


def hafnium_response_db_addition(value):
    db.hafnium.find_one_and_update({'domain': value['domain']}, {'$set': {'status': 'finished', 'timeStamp': datetime.utcnow(), 'output': value['output']}})
    logs.Logging.add('hafnium scan', value['domain'], 'adding completed records to DB', 'response queue job complete')
