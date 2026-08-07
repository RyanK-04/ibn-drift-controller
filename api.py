import json
import os
import requests
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
requests.packages.urllib3.disable_warnings()

AUTH = ("admin", "NokiaSrl1!")
AUDIT_LOG_PATH = "logs/audit.log"
os.makedirs("logs", exist_ok=True)

# Comprehensive registry mapping all lab management IPs to their baselines / profiles
NODE_REGISTRY = {
    "172.16.99.6": {
        "name": "core-srl-1",
        "type": "switch",
        "url": "http://172.16.99.6/jsonrpc",
        "baseline": "configs/core-srl-1_baseline.json"
    },
    "172.16.99.3": {
        "name": "core-srl-2",
        "type": "switch",
        "url": "http://172.16.99.3/jsonrpc",
        "baseline": "configs/core-srl-2_baseline.json"
    },
    "172.16.99.4": {
        "name": "dist-srl-1",
        "type": "switch",
        "url": "http://172.16.99.4/jsonrpc",
        "baseline": "configs/dist-srl-1_baseline.json"
    },
    "172.16.99.2": {
        "name": "dist-srl-2",
        "type": "switch",
        "url": "http://172.16.99.2/jsonrpc",
        "baseline": "configs/dist-srl-2_baseline.json"
    },
    "172.16.99.5": {
        "name": "client-desktop",
        "type": "endpoint",
        "baseline": "configs/client-desktop_profile.json"
    },
    "172.16.99.7": {
        "name": "server-app",
        "type": "endpoint",
        "baseline": "configs/server-app_profile.json"
    },
    "172.16.99.8": {
        "name": "client-atm",
        "type": "endpoint",
        "baseline": "configs/client-atm_profile.json"
    }
}

def write_audit_log(event_type, details):
    timestamp = datetime.utcnow().isoformat()
    log_entry = {"timestamp": timestamp, "event": event_type, "details": details}
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    print(f"[AUDIT] {timestamp} - {event_type}: {details}")

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "controller": "IBN Enterprise Banking Controller active"})

@app.route("/api/ztp/bootstrap", methods=["GET"])
def ztp_bootstrap():
    client_ip = request.args.get("ip") or request.remote_addr
    node_name_param = request.args.get("node")
    
    write_audit_log("ZTP_BOOTSTRAP_REQUEST", {"client_ip": client_ip, "node_param": node_name_param})

    node_info = None
    if node_name_param:
        for ip, info in NODE_REGISTRY.items():
            if info["name"] == node_name_param:
                node_info = info
                client_ip = ip
                break
    else:
        node_info = NODE_REGISTRY.get(client_ip)

    if not node_info:
        write_audit_log("ZTP_UNKNOWN_DEVICE", {"client_ip": client_ip})
        return jsonify({"error": f"Unknown device IP {client_ip} or node name for ZTP provisioning"}), 404

    try:
        with open(node_info["baseline"], "r") as f:
            config_data = json.load(f)
        write_audit_log("ZTP_PROVISION_SUCCESS", {"node": node_info["name"], "type": node_info["type"], "ip": client_ip})
        return jsonify(config_data)
    except Exception as e:
        default_payload = {"node": node_info["name"], "status": "provisioned", "gateway": "172.16.10.1"}
        return jsonify(default_payload)

@app.route("/api/drift/check/<node_ip>", methods=["GET"])
def check_drift_api(node_ip):
    node_info = NODE_REGISTRY.get(node_ip)
    if not node_info or node_info["type"] != "switch":
        return jsonify({"error": "Switch node not found in registry"}), 404

    with open(node_info["baseline"], "r") as f:
        baseline = json.load(f)

    # Correct SR Linux JSON-RPC 'get' payload structure using the 'commands' wrapper
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get",
        "params": {
            "commands": [
                {
                    "path": "/interface[name=ethernet-1/1]",
                    "datastore": "state"
                }
            ]
        }
    }
    try:
        res = requests.post(node_info["url"], json=payload, auth=AUTH, verify=False, timeout=5).json()
        result_list = res.get("result", [])
        live_data = {}
        if result_list:
            item = result_list[0]
            live_data = item.get("value", item)
    except Exception as e:
        return jsonify({"error": f"Failed to connect to device: {str(e)}"}), 500

    target_mtu = baseline.get("interfaces", [{}])[0].get("mtu")
    live_mtu = live_data.get("mtu")
    drift_detected = target_mtu != live_mtu

    report = {
        "node": node_info["name"],
        "drift_detected": drift_detected,
        "intended_mtu": target_mtu,
        "live_mtu": live_mtu
    }
    
    if drift_detected:
        write_audit_log("DRIFT_DETECTED", report)
    else:
        write_audit_log("COMPLIANCE_CHECK_PASSED", report)

    return jsonify(report)

@app.route("/api/drift/remediate/<node_ip>", methods=["POST"])
def remediate_drift(node_ip):
    node_info = NODE_REGISTRY.get(node_ip)
    if not node_info or node_info["type"] != "switch":
        return jsonify({"error": "Switch node not found in registry"}), 404

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "set",
        "params": {
            "commands": [{
                "action": "update",
                "path": "/interface[name=ethernet-1/1]/mtu",
                "value": 9000
            }]
        }
    }
    try:
        res = requests.post(node_info["url"], json=payload, auth=AUTH, verify=False, timeout=5).json()
        if "error" not in res:
            write_audit_log("REMEDIATION_SUCCESS", {"node": node_info["name"]})
            return jsonify({"status": "success", "message": f"MTU reset to 9000 on {node_info['name']}"})
        else:
            write_audit_log("REMEDIATION_FAILED", {"node": node_info["name"], "details": res})
            return jsonify({"status": "error", "details": res}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)