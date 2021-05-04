import os
import json
import requests

from helpers.requests_retry import retry_session
from helpers import utils


def scan(data_input):

    data_input['status'] = 'running'
    utils.mark_db_request(scan, 'darkweb')

    # calling api with retries and backoff_factor
    session = retry_session()

    headers = {"Authorization": os.environ.get('DARWEB_BASIC_TOKEN'),
               "Content-Type": "application/x-www-form-urlencoded"}
    resp = session.post(os.environ.get('DARWEB_AUTH'), headers=headers)

    if resp.status_code == 200:
        out = json.loads(resp.content.decode())

        try:
            headers_main = {"Authorization": out["access_token"]}
            body = {"value": "@" + data_input["value"]}

            resp = session.post(os.environ.get('DARWEB_HOST') + '/search' + '?limit=10000', data=json.dumps(body),
                                headers=headers_main)

            if resp.status_code == 200:
                data_out = json.loads(resp.content.decode())
        except requests.HTTPError:
            pass

        final_result = {}
        result = []

        for each in data_out["records"]:
            comp = {
                "email": each['email'],
                "password": each['password'] if each['password'] is None or len(each['password']) < 4 else each['password'].replace(each['password'][4:], len(each['password'][4:])*'X')[:10],
                "breach": each['breach'],
                "found": each['timeline']['sort_date'],
                "source": each['source'],
                "pii": each['pii'] if 'pii' in each else [],
                "hash": each['hashType']
            }
            result.append(comp)

        final_result['value'] = data_input["value"]
        final_result['count'] = len(result)
        final_result['compromises'] = result

        return final_result
