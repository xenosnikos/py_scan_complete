from flask import Flask
from flask_restful import Api
from controllers.port_scan import PortScan
from controllers.infrastructure_analysis import InfrastructureAnalysis
from controllers.connected_domains import ConnectedDomains
from controllers.domain_reputation import DomainReputation
from controllers.malware_check import MalwareCheck
from controllers.ssl_certificates_chain import SSLCertificatesChain
from controllers.ssl_configuration import SSLConfiguration
from controllers.screenshot import ScreenShot
from controllers.spoof_check_api import SpoofCheck
from controllers.trustymail_api import TrustyMail
from controllers import scans_available, queue_status
from controllers.hafnium_scan import HafniumScan
from controllers.hafnium_scan_request import HafniumScanRequest
from controllers.rdp_scan_api import RDPScan
from controllers.domain_expansion import DomainExpansion
from controllers.darkweb_scan_api import DarkWebScan
from controllers.blacklist_scan_api import BlacklistScan
from controllers.port_scan_regular import PortScanRegular
from controllers.port_scan_full import PortScanExtended

app = Flask(__name__)
api = Api(app)

api.add_resource(PortScan, "/portScan")
api.add_resource(PortScanRegular, "/portScan/regular")
api.add_resource(PortScanExtended, "/portScan/full")  # will be changed when I start working on port scan API
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
api.add_resource(HafniumScanRequest, "/hafnium")
api.add_resource(RDPScan, "/rdp")
api.add_resource(DomainExpansion, "/expansion")
api.add_resource(DarkWebScan, "/darkweb")
api.add_resource(BlacklistScan, "/blacklist")
api.add_resource(scans_available.AvailableScans, '/supportedScans')
api.add_resource(queue_status.QueueStatus, "/queue/status/conf")

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
