from flask_restful import Resource, reqparse, request
import pymongo
import verify
import datetime
import validators
import requests
from bson import ObjectId

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

emotetscan_args = reqparse.RequestParser()
emotetscan_args.add_argument('domain', help='Domain is required to EMOTET scan', required=True)
emotetscan_args.add_argument('type', help='Type can be fakeSender, realSender, recipient', action='append')
# defaults to as if type=realSender is sent in by customer if no type is specified in the url


class EmotetCheck(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)

        if auth[1] != 200:
            print(auth)
            return auth
        args = emotetscan_args.parse_args()
        domain = args['domain']

        if not validators.domain(domain):
            return {
                       'message': f'{domain} is not a valid domain, please try again'
                   }, 400

        pre_def = ['fakeSender', 'realSender', 'recipient']

        if args['type'] is not None:
            for each_type in args['type']:
                if each_type not in pre_def:
                    return {
                               'message': f"{each_type} is not a valid type, please try again"
                           }, 400

        db.emotetScan.create_index('domain')
        db.emotetData.create_index('emotetScanId')

        exists = list(db.emotetScan.find({'domain': domain}).sort([('_id', -1)]).limit(1))

        if len(exists) == 0:
            exists = None
        else:
            exists = exists[0]

        if exists is None:
            start_date = '2020-08-01'
            new_record = db.emotetScan.insert_one({'domain': domain}).inserted_id
        else:
            start_date = exists['timeStamp'].strftime('%Y-%m-%d')
            new_record = exists['_id']
        end_date = datetime.datetime.utcnow().strftime('%Y-%m-%d')

        if exists is None or (
                exists is not None and exists['timeStamp'] + datetime.timedelta(days=7) < datetime.datetime.utcnow()):

            url = f"https://www.haveibeenemotet.com/API/raw/query.php?apikey={open('emotet.txt').read()}&type=2A" \
                  f"&sd={start_date}&ld={end_date}&domain={domain}"

            req = requests.get(url=url)

            data_split1 = req.content.decode("ISO-8859-1").split('\n')

            fields = ('FAKE_SENDER:', 'REAL_SENDER:', 'RECIPIENT:')

            result_type = ''
            scan_id = str(new_record)

            for data in data_split1:
                record = {}
                if data.split(': ')[0] == 'DOMAIN':
                    continue
                if data in fields:
                    result_type = data.replace(':', '')
                    continue
                if data == 'No data found':
                    continue
                if data.split(': ')[0] == 'PRICE':
                    updated_timestamp = datetime.datetime.utcnow()
                    db.emotetScan.find_one_and_update({"_id": ObjectId(new_record)}, {'$set': {'timeStamp':
                                                                                                   updated_timestamp}})
                    db.emotetScan.update_one({"_id": ObjectId(new_record)},
                                             {'$inc': {'cost': float(data.split(': ')[1].split(' Euro')[0])}, "$push": {
                                                 'history': updated_timestamp}}, upsert=True)
                    break

                values = data.replace('[omissis]', '').split(';')

                record['emotetScanId'] = scan_id
                record['type'] = result_type
                record['emailDate'] = values[0]
                record['fakeSender'] = values[1]
                record['realSender'] = values[2]
                record['recipient'] = values[3]
                record['emailSubject'] = values[4]

                db.emotetData.insert_one(record)

        db.emotetData.create_index([('fakeSender', 1), ('realSender', 1), ('recipient', 1)])

        domain = '@' + domain

        query = db.emotetData.find({'$or': [{'fakeSender': domain}, {'realSender': domain}, {'recipient': domain}]},
                                   {'_id': 0, 'emotetScanId': 0})

        result = {}

        if args['type'] is not None:
            for input_type in args['type']:
                result[input_type] = []
        else:
            result['realSender'] = []

        for each in query:
            if 'fakeSender' in result and each['type'] == 'FAKE_SENDER':
                del each['type']
                result['fakeSender'].append(each)
            elif 'realSender' in result and each['type'] == 'REAL_SENDER':
                del each['type']
                result['realSender'].append(each)
            elif 'recipient' in result and each['type'] == 'RECIPIENT':
                del each['type']
                result['recipient'].append(each)

        return result, 200
