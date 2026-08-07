import json
import requests

# Disable SSL warnings for self-signed lab certificates if using HTTPS
requests.packages.urllib3.disable_warnings()

# Configuration
SRL_IP = "172.16.99.2"  
URL = f"http://{SRL_IP}/jsonrpc"
USERNAME = "admin"
PASSWORD = "NokiaSrl1!"

# JSON-RPC Payload to fetch interface states from SR Linux
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

headers = {
    "Content-Type": "application/json"
}

try:
    print(f"Connecting to Nokia SR Linux at {SRL_IP}...")
    response = requests.post(
        URL,
        json=payload,
        auth=(USERNAME, PASSWORD),
        headers=headers,
        verify=False,
        timeout=5
    )
    
    if response.status_code == 200:
        print("\n[SUCCESS] Successfully connected via JSON-RPC!")
        result = response.json()
        print(json.dumps(result, indent=2))
    else:
        print(f"\n[ERROR] HTTP Status Code: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"\n[EXCEPTION] Failed to connect: {e}")