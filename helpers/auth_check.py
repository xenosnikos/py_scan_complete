import os


def auth_check(auth):

    if auth != os.environ.get('API_KEY'):
        return {
            'status': 401,
            'message': 'Provided token is invalid, please check and try again'
        }
    else:
        return {
            'status': 200,
        }
