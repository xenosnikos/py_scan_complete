from flask import Flask
from flask_restful import Api
from port_scan import PortScan

import history
import port_scan_result
import queue_status


app = Flask(__name__)
api = Api(app)

api.add_resource(PortScan, "/portscan")
api.add_resource(port_scan_result.PortScanResult, "/portscan/result")
api.add_resource(history.PortScanHistory, "/portscan/history")
api.add_resource(queue_status.QueueStatus, "/queue/status/conf")

if __name__ == "__main__":
    app.run(debug=True)
