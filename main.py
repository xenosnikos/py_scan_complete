from flask import Flask
from flask_restful import Api
import auth
import verify
import port_scan
import port_scan_result
import history
import refresh
# U652JqPlfdYFdwDp


app = Flask(__name__)
api = Api(app)

api.add_resource(auth.AuthLogin, "/login")
api.add_resource(verify.AuthVerify, '/verify')
api.add_resource(auth.AuthLogout, "/logout")
api.add_resource(auth.AuthSignup, "/signup")
api.add_resource(refresh.AuthRefresh, '/refresh')
api.add_resource(port_scan.PortScan, "/portscan")
api.add_resource(port_scan_result.PortScanResult, "/portscan/result")
api.add_resource(history.PortScanHistory, "/portscan/history")

if __name__ == "__main__":
    app.run(host='0.0.0.0')
