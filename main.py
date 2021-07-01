from flask import Flask
from flask_restful import Api

from controllers.v1_domain_expansion import V1DomainExpansion
from controllers.v1_port_scan import V1PortScan

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
from controllers.port_scan_quick import PortScanQuick
from controllers.port_scan_full import PortScanFull

app = Flask(__name__)
api = Api(app)

# version 1 apis
api.add_resource(V1DomainExpansion, "/expansion")
api.add_resource(V1PortScan, "/portScan")

# version 2 apis
api.add_resource(PortScan, "/v2/port-scan")
api.add_resource(PortScanQuick, "/v2/port-scan/quick")
api.add_resource(PortScanFull, "/v2/port-scan/full")
api.add_resource(InfrastructureAnalysis, "/v2/infrastructureAnalysis")
api.add_resource(ConnectedDomains, "/v2/connectedDomains")
api.add_resource(DomainReputation, "/v2/domainReputation")
api.add_resource(MalwareCheck, "/v2/malwareCheck")
api.add_resource(SSLCertificatesChain, "/v2/sslCertificatesChain")
api.add_resource(SSLConfiguration, "/v2/sslConfiguration")
api.add_resource(ScreenShot, "/v2/screenShot")
api.add_resource(SpoofCheck, "/v2/spoofCheck")
api.add_resource(TrustyMail, "/v2/trustyMail")
api.add_resource(HafniumScan, "/v2/hafniumScan")
api.add_resource(HafniumScanRequest, "/v2/hafnium")
api.add_resource(RDPScan, "/v2/rdp")
api.add_resource(DomainExpansion, "/v2/expansion")
api.add_resource(DarkWebScan, "/v2/darkweb")
api.add_resource(BlacklistScan, "/v2/blacklist")
api.add_resource(scans_available.AvailableScans, '/v2/supportedScans')
api.add_resource(queue_status.QueueStatus, "/v2/queue/status/conf")

if __name__ == "__main__":
    app.run()
