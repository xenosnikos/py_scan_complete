from flask import Flask
from flask_restful import Api
from port_scan import PortScan

import auth
import history
import port_scan_result
import refresh
import verify
import queue_status


app = Flask(__name__)
api = Api(app)

api.add_resource(auth.AuthLogin, "/login")
api.add_resource(verify.AuthVerify, '/verify')
api.add_resource(auth.AuthLogout, "/logout")
api.add_resource(auth.AuthSignup, "/signup")
api.add_resource(refresh.AuthRefresh, '/refresh')
api.add_resource(PortScan, "/portscan")
api.add_resource(port_scan_result.PortScanResult, "/portscan/result")
api.add_resource(history.PortScanHistory, "/portscan/history")
api.add_resource(queue_status.QueueStatus, "/queue/status/conf")

if __name__ == "__main__":
    app.run(host='0.0.0.0')
