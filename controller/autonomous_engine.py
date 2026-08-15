import yaml
import time
import json
import logging
import requests
import socket
import os
from datetime import datetime
from pygnmi.client import gNMIclient
from netmiko import ConnectHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTENT_FILE = "/opt/controller/controller/intent.yml"
SRL_AUTH = (os.environ.get("SRL_USERNAME"), os.environ.get("SRL_PASSWORD"))
ALPINE_AUTH = {
    "username": os.environ.get("ALPINE_USERNAME"),
    "password": os.environ.get("ALPINE_PASSWORD")
}
ZABBIX_SERVER = "172.16.99.106"
ZABBIX_PORT = 10051

logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def load_intent():
    with open(INTENT_FILE, "r") as f:
        return yaml.safe_load(f)

def send_zabbix_trap(host, key, value):
    packet = {"request": "sender data", "data": [{"host": host, "key": key, "value": value}]}
    payload = json.dumps(packet).encode('utf-8')
    header = b'ZBXD\x01' + (len(payload)).to_bytes(8, byteorder='little')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ZABBIX_SERVER, ZABBIX_PORT))
            s.sendall(header + payload)
            s.recv(1024)
            logger.info(f"[ZABBIX] Trap sent for {host} | {key}: {value}")
    except Exception as e:
        logger.error(f"[ZABBIX] Failed to send trap: {e}")

def remediate_switch_drift(node_ip, node_name, intent_data):
    logger.info(f"[*] Initiating JSON-RPC remediation for {node_name}...")
    url = f"http://{node_ip}/jsonrpc"
    acl_name = intent_data["global_settings"]["security"]["acl_name"]
    drop_port = intent_data["global_settings"]["security"]["drop_tcp_ports"][0]
    commands = [{
        "action": "update",
        "path": "/acl/ipv4-filter",
        "value": [{
            "name": acl_name,
            "entry": [{"sequence-id": 10, "action": {"drop": {}}, "match": {"protocol": "tcp", "tcp": {"destination-port": drop_port}}}]
        }]
    }]
    payload = {"jsonrpc": "2.0", "id": 1, "method": "set", "params": {"commands": commands}}
    try:
        res = requests.post(url, json=payload, auth=SRL_AUTH, verify=False, timeout=10)
        if res.status_code == 200:
            logger.info(f"[+] Remediation successful on {node_name}")
            send_zabbix_trap(node_name, "drift.status", "Compliant")
        else:
            logger.error(f"[-] Remediation failed on {node_name}: {res.text}")
    except Exception as e:
        logger.error(f"[-] HTTP Error communicating with {node_name}: {e}")

def monitor_switch_telemetry(device, intent_data):
    node_ip = device["management_ip"]
    node_name = device["name"]
    target = (f"{node_ip}", 57400)
    try:
        with gNMIclient(target=target, username=SRL_AUTH[0], password=SRL_AUTH[1], insecure=True) as gc:
            logger.info(f"[gNMI] Polling state for {node_name}...")
            acl_path = ["acl", "ipv4-filter"]
            result = gc.get(path=[acl_path], datatype='state')
            drift_detected = False
            if not result or 'acl' not in str(result):
                drift_detected = True
            if drift_detected:
                logger.warning(f"[!] Configuration drift detected on {node_name}!")
                send_zabbix_trap(node_name, "drift.status", "Drifted")
                remediate_switch_drift(node_ip, node_name, intent_data)
            else:
                send_zabbix_trap(node_name, "drift.status", "Compliant")
    except Exception as e:
        logger.error(f"[gNMI] Failed to fetch telemetry from {node_name}: {e}")

def run_engine():
    logger.info("Starting Autonomous IBN Drift Engine for Enterprise Core...")
    while True:
        try:
            intent = load_intent()
            devices = intent.get("devices", [])
            logger.info(f"--- Starting Audit Cycle at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
            for device in devices:
                if "srl" in device["name"]:
                    monitor_switch_telemetry(device, intent)
            logger.info("Cycle complete. Sleeping for 30 seconds...")
            time.sleep(30)
        except Exception as e:
            logger.error(f"[FATAL] Engine encountered an error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    run_engine()