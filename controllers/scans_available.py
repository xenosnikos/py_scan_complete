from flask_restful import Resource, request
import os


class AvailableScans(Resource):

    def get(self):
        auth = request.headers.get('Authorization')

        if auth != os.environ.get('API_KEY'):
            return {
                       'message': 'Provided token is invalid, please check and try again'
                   }, 401

        return {
            'availableScans': [
                'portScan',
                'sslScan',
                'infrastructureAnalysis',
                'connectedDomains',
                'domainReputation',
                'malwareCheck',
                'sslCertificatesChain',
                'sslConfiguration',
                'screenShot',
                'force'
            ]
        }
