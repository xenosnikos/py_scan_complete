from flask import Flask
from flask_restful import Api
from external_apis.port_scan import PortScan
from external_apis.infrastructure_analysis import InfrastructureAnalysis
from external_apis.connected_domains import ConnectedDomains
from external_apis.domain_reputation import DomainReputation
from external_apis.malware_check import MalwareCheck
from external_apis.ssl_certificates_chain import SSLCertificatesChain
from external_apis.ssl_configuration import SSLConfiguration
from external_apis.screenshot import ScreenShot
from external_apis.spoof_check_api import SpoofCheck
from external_apis.trustymail_api import TrustyMail
from external_apis import scans_available, queue_status
from external_apis.hafnium_scan import HafniumScan
from external_apis.hafnium_scan_request import HafniumScanRequest
from external_apis.hafnium_scan_response import HafniumScanResponse

app = Flask(__name__)
api = Api(app)

api.add_resource(PortScan, "/portScan")
api.add_resource(InfrastructureAnalysis, "/infrastructureAnalysis")
api.add_resource(ConnectedDomains, "/connectedDomains")
api.add_resource(DomainReputation, "/domainReputation")
api.add_resource(MalwareCheck, "/malwareCheck")
api.add_resource(SSLCertificatesChain, "/sslCertificatesChain")
api.add_resource(SSLConfiguration, "/sslConfiguration")
api.add_resource(ScreenShot, "/screenShot")
api.add_resource(SpoofCheck, "/spoofCheck")
api.add_resource(TrustyMail, "/trustyMail")
api.add_resource(HafniumScan, "/hafniumScan")
api.add_resource(HafniumScanRequest, "/hafniumScanRequest")
api.add_resource(HafniumScanResponse, "/hafniumScanResponse")
api.add_resource(scans_available.AvailableScans, '/supportedScans')
api.add_resource(queue_status.QueueStatus, "/queue/status/conf")

if __name__ == "__main__":
    app.run()
