import logging
import os
import json

from helpers.requests_retry import retry_session
from helpers import utils, common_strings

logger = logging.getLogger(common_strings.strings['darkweb'])


def scan(value, omit_password):
    utils.mark_db_request(value, status=common_strings.strings['status_running'],
                          collection=common_strings.strings['darkweb'])

    # calling api with retries and backoff_factor
    session = retry_session()

    headers = {"Authorization": os.environ.get('DARWEB_BASIC_TOKEN'),
               "Content-Type": "application/x-www-form-urlencoded"}

    try:
        resp = session.post(os.environ.get('DARWEB_AUTH'), headers=headers)
    except Exception as e:
        logger.critical(f"Cannot get a Cognito token for DarkwebID, scan value {value}")
        raise e

    if resp.status_code == 200:
        out = json.loads(resp.content.decode())

        try:
            headers_main = {"Authorization": out["access_token"]}
            body = {"value": "@" + value}

            resp = session.post(os.environ.get('DARWEB_HOST') + '/search?limit=10000', data=json.dumps(body),
                                headers=headers_main)

        except Exception as e:
            logger.critical(f"Cannot get darkweb results, scan value {value}")
            raise e

        result = []

        if resp.status_code == 200:
            data_out = json.loads(resp.content.decode())
            for each in data_out["records"]:
                comp = {
                    "email": each['email'],
                    "breach": each['breach'],
                    "found": each['sort_date'],
                    "source": each['source'],
                    "pii": each['pii'] if 'pii' in each else [],
                    "hash": each['hashType']
                }

                if omit_password is not True:
                    comp['password'] = each['password'] if each['password'] is None or len(each['password']) < 4 else \
                                           each['password'].replace(each['password'][4:], len(each['password'][4:])*'X')[:10]

                result.append(comp)
        else:
            logger.critical(f"No compromises due to a non 200 status code")
            raise Exception('Non 200 status code received for darkweb scan')

        return result
