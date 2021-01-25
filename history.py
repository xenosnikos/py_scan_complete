from flask_restful import Resource, reqparse, request
import socket
from bson import json_util
import json
import pymongo
import verify
import validators

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

portscan_args = reqparse.RequestParser()
portscan_args.add_argument('value', help='IP or Domain is required to lookup history')


class PortScanHistory(Resource):

    def get(self):
        auth_arg = request.headers.get('Authorization')
        auth = verify.AuthVerify.post(auth_arg)
        if auth[1] != 200:
            print(auth)
            return auth
        args = portscan_args.parse_args()

        if args['value'] is not None:
            ip = socket.gethostbyname(args['value'])

            if not (validators.domain(args['value']) or validators.ip_address.ipv4(ip)):
                print(validators.domain(args['value']))
                return {
                    'message': f"{args['value']} is not a valid IP or Domain, please try again"
                       }, 400

        limit = 10
        offset = 0

        if 'limit' in args and args['limit'] is not None and args['limit'] != '':
            limit = int(args['limit'])

        if 'offset' in args and args['offset'] is not None and args['offset'] != '':
            offset = int(args['offset'])

        if args['value'] is not None:
            if validators.domain(args['value']):
                db.scans.create_index([('user_id', 1), ('value', 1)])
                item = list(db.scans.find({'user_id': auth[0]['user_id'], 'value': args['value']}))[offset:offset + limit:1]
                total = db.scans.count_documents({'user_id': auth[0]['user_id'], 'value': args['value']})
            else:
                db.scans.create_index([('user_id', 1), ('ip', 1)])
                item = list(db.scans.find({'user_id': auth[0]['user_id'], 'ip': ip}))[offset:offset + limit:1]
                total = db.scans.count_documents({'user_id': auth[0]['user_id'], 'ip': ip})
        else:
            db.scans.create_index('user_id')
            item = list(db.scans.find({'user_id': auth[0]['user_id']}))[offset:offset + limit:1]
            total = db.scans.count_documents({'user_id': auth[0]['user_id']})

        if item is None:
            return {
                'message': f"{args['value']} not found in the history"
                   }, 404

        if offset == 0:
            page = 1
        else:
            page = int(offset / limit) + 1

        next_page = page + 1
        next_offset = offset + limit
        previous_offset = offset - limit
        last_page = int(total / limit) + 1
        last_offset = int(total / limit) * limit

        meta = {
            "current page": page,
            "next page": next_page,
            "last page": last_page,
            "per page": limit,
            "total": total
        }

        links = {
            "first page": f"?limit={limit}&offset={0}",
            "previous page": f"?limit={limit}&offset={previous_offset}",
            "next page": f"?limit={limit}&offset={next_offset}",
            "last page": f"?limit={limit}&offset={last_offset}"
        }

        if offset == 0:
            links.pop('first page')
            links.pop('previous page')

        if total <= limit:
            links.pop('next page')
            links.pop('last page')
            meta.pop('next page')
            meta.pop('last page')

        result = [
            meta
        ]

        if limit < total:
            result.append(links)

        for each in item:
            each['timeStamp'] = each['timeStamp'].strftime("%m/%d/%Y, %H:%M:%S") + ' UTC'
            each['scan_id'] = str(each['_id'])
            each.pop('_id')
            result.append(json.loads(json_util.dumps(each)))

        return result
