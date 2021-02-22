from flask import Flask
from flask_restful import Api
from scan import Scan

import history
import scan_result
import queue_status
import scans_available


app = Flask(__name__)
api = Api(app)

api.add_resource(Scan, "/scan")
api.add_resource(scans_available.AvailableScans, '/supportedScans')
api.add_resource(scan_result.ScanResult, "/scan/result")
api.add_resource(history.ScanHistory, "/portscan/history")
api.add_resource(queue_status.QueueStatus, "/queue/status/conf")

if __name__ == "__main__":
    app.run()
