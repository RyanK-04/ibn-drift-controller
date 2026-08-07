import json
import requests

requests.packages.urllib3.disable_warnings()

# Configuration
SRL_IP = "172.16.99.2"
URL = f"http://{SRL_IP}/jsonrpc"
AUTH = ("admin", "NokiaSrl1!")
BASELINE_PATH = "configs/dist-srl-1_baseline.json"

def load_baseline():
    with open(BASELINE_PATH, "r") as f:
        return json.load(f)

def fetch_live_state():
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
    headers = {"Content-Type": "application/json"}
    response = requests.post(URL, json=payload, auth=AUTH, headers=headers, verify=False, timeout=5)
    return response.json().get("result", [{}])[0]

def detect_drift():
    print("Loading baseline configuration...")
    baseline = load_baseline()
    
    print("Fetching live operational state from dist-srl-1...")
    live_data = fetch_live_state()
    
    print("\n--- Drift Analysis Report ---")
    drift_found = False

    # Find the baseline configuration specifically for ethernet-1/1
    target_interface = None
    for intf in baseline.get("interfaces", []):
        if intf["name"] == "e1-1": # Mapped to ethernet-1/1 physically
            target_interface = intf
            break

    if not target_interface:
        print("[ERROR] Interface e1-1 not found in baseline configuration.")
        return

    # Check MTU drift
    intended_mtu = target_interface.get("mtu")
    live_mtu = live_data.get("mtu")
    if intended_mtu != live_mtu:
        print(f"[DRIFT DETECTED] MTU Mismatch on ethernet-1/1:")
        print(f"  - Intended (Baseline): {intended_mtu}")
        print(f"  - Live State (Actual): {live_mtu}")
        drift_found = True

    # Check Admin State drift
    intended_state = target_interface.get("admin-state")
    live_state = live_data.get("admin-state")
    if intended_state != live_state:
        print(f"[DRIFT DETECTED] Admin State Mismatch on ethernet-1/1:")
        print(f"  - Intended (Baseline): {intended_state}")
        print(f"  - Live State (Actual): {live_state}")
        drift_found = True

    if not drift_found:
        print("[compliant] No configuration drift detected! Live state matches baseline.")
    else:
        print("\n[ACTION REQUIRED] Drift found between intended intent and actual switch state.")

if __name__ == "__main__":
    detect_drift()