import html
import json
import logging
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
import yaml
from jinja2 import Environment, FileSystemLoader
from netmiko import ConnectHandler
from pygnmi.client import gNMIclient


# ============================================================
# Runtime configuration
# ============================================================

INTENT_FILE = os.environ.get("INTENT_FILE", "/opt/controller/controller/intent.yml")
DAY0_INVENTORY_FILE = os.environ.get(
    "DAY0_INVENTORY_FILE", "/opt/controller/provisioning/day0_inventory.yml"
)
LINUX_INIT_FILE = os.environ.get(
    "LINUX_INIT_FILE", "/opt/controller/provisioning/client-static-init.yml"
)

SRL_USERNAME = os.environ.get("SRL_USERNAME")
SRL_PASSWORD = os.environ.get("SRL_PASSWORD")
if not SRL_USERNAME or not SRL_PASSWORD:
    raise ValueError("[FATAL] SRL_USERNAME and SRL_PASSWORD must be set")

ALPINE_USERNAME = os.environ.get("ALPINE_USERNAME", "root")
ALPINE_PASSWORD = os.environ.get("ALPINE_PASSWORD")
if not ALPINE_PASSWORD:
    raise ValueError("[FATAL] ALPINE_PASSWORD must be set")

ZABBIX_SERVER = os.environ.get("ZABBIX_SERVER", "172.16.99.106")
ZABBIX_PORT = int(os.environ.get("ZABBIX_PORT", "10051"))

GNMI_PORT = int(os.environ.get("GNMI_PORT", "57400"))
JSON_RPC_PORT = int(os.environ.get("JSON_RPC_PORT", "80"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
OSPF_AREA_ID = "0.0.0.0"
SRL_CONTROL_SLOT = os.environ.get("SRL_CONTROL_SLOT", "A")
PING_TIMEOUT_SECONDS = int(os.environ.get("PING_TIMEOUT_SECONDS", "1"))
MAX_REMEDIATION_ATTEMPTS = int(os.environ.get("MAX_REMEDIATION_ATTEMPTS", "3"))
REMEDIATION_VERIFY_DELAY = float(os.environ.get("REMEDIATION_VERIFY_DELAY", "2"))
TCP_CONNECT_TIMEOUT = float(os.environ.get("TCP_CONNECT_TIMEOUT", "2"))

TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR", "/opt/controller/provisioning")
REMEDIATION_TEMPLATE = "srl_remediation.j2"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ============================================================
# Intent / inventory
# ============================================================

def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_intent() -> Dict[str, Any]:
    return load_yaml(INTENT_FILE)


def load_day0_inventory() -> Dict[str, Any]:
    return load_yaml(DAY0_INVENTORY_FILE)


def load_linux_init() -> Dict[str, Any]:
    return load_yaml(LINUX_INIT_FILE)


def build_alpine_node_config(
    device: Dict[str, Any],
    linux_init_data: Dict[str, Any],
) -> Dict[str, Any]:
    name = device["name"]
    facts = linux_init_data.get(name, {})
    return {
        "name": name,
        "management_ip": device["management_ip"],
        "vlan_id": facts.get("vlan_id"),
        "vlan_ip": facts.get("ip"),
        "vlan_gw": facts.get("gw"),
        "role": facts.get("role"),
    }


def build_node_config(
    device: Dict[str, Any],
    day0_data: Dict[str, Any],
) -> Dict[str, Any]:
    name = device["name"]
    facts = day0_data.get("switches", {}).get(name, {})
    return {
        "name": name,
        "management_ip": device["management_ip"],
        "router_id": facts.get("router_id"),
        "interfaces": facts.get("interfaces", {}),
        "vlan_interfaces": facts.get("vlan_interfaces", []),
    }


# ============================================================
# Device state and incident deduplication
# ============================================================

DEVICE_STATE_COMPLIANT = "COMPLIANT"
DEVICE_STATE_DRIFT = "DRIFT_DETECTED"
DEVICE_STATE_REMEDIATING = "REMEDIATING"
DEVICE_STATE_MANUAL = "MANUAL_REVIEW"
DEVICE_STATE_UNREACHABLE = "UNREACHABLE"
DEVICE_STATE_TELEMETRY_ERROR = "TELEMETRY_ERROR"

REMEDIATION_STATUS_NONE = 0
REMEDIATION_STATUS_IN_PROGRESS = 1
REMEDIATION_STATUS_RECOVERED = 2
REMEDIATION_STATUS_FAILED = 3
REMEDIATION_STATUS_MANUAL_REVIEW = 4

DEVICE_REACHABLE = 1
DEVICE_UNREACHABLE = 0
TELEMETRY_OK = 1
TELEMETRY_FAILED = 0

# These keys track currently active incidents separately. An incident is
# re-notified only after it has cleared and later recurs.
INCIDENT_DRIFT = "CONFIGURATION_DRIFT"
INCIDENT_UNREACHABLE = "DEVICE_UNREACHABLE"
INCIDENT_TELEMETRY = "TELEMETRY_ERROR"
INCIDENT_SECURITY_REVIEW = "SECURITY_MANUAL_REVIEW"
INCIDENT_REMEDIATION = "REMEDIATION_OUTCOME"

_device_states: Dict[str, Dict[str, Any]] = {}


def get_device_state(name: str) -> Dict[str, Any]:
    return _device_states.setdefault(
        name,
        {
            "state": DEVICE_STATE_COMPLIANT,
            "remediation_attempts": 0,
            "finding_signature": None,
            "last_incident_signature": None,  # kept for compatibility
            "active_incidents": set(),
        },
    )


def finding_signature(reasons: List[str]) -> str:
    return " | ".join(sorted(reasons))


def mask_ip_address(ip: str) -> str:
    """Mask the final IPv4 octet for email/reporting."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["xxx"])
    except Exception:
        pass
    return "masked"


def build_drift_details(reasons: List[str]) -> str:
    if not reasons:
        return "No active configuration drift."
    return "<br>".join(f"• {html.escape(str(reason))}" for reason in reasons)


def clear_incident(state: Dict[str, Any], incident_key: str) -> None:
    state.setdefault("active_incidents", set()).discard(incident_key)


def is_incident_active(state: Dict[str, Any], incident_key: str) -> bool:
    return incident_key in state.setdefault("active_incidents", set())


# ============================================================
# Jinja remediation rendering
# ============================================================

_jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_remediation_commands(
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
    drift_reasons: List[str],
) -> List[Dict[str, Any]]:
    security = intent_data["global_settings"]["security"]
    template = _jinja_env.get_template(REMEDIATION_TEMPLATE)

    rendered = template.render(
        acl_name=security["acl_name"],
        drop_port=int(security["drop_tcp_ports"][0]),
        expected_banner=intent_data["global_settings"]["system_banner"],
        interfaces=list(node_config["interfaces"].keys()),
        routing_protocol=intent_data["global_settings"]["routing"]["protocol"].lower(),
        router_id=node_config["router_id"],
        area_id=intent_data["global_settings"]["routing"].get("area", OSPF_AREA_ID),
        vlan_interfaces=node_config["vlan_interfaces"],
        purge_backdoor=any(
            "backdoor account" in reason.lower() for reason in drift_reasons
        ),
    )

    try:
        commands = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Rendered remediation template is not valid JSON: {exc}\n---\n{rendered}"
        ) from exc

    if not isinstance(commands, list):
        raise RuntimeError("Remediation template must render a JSON list")
    return commands


# ============================================================
# Zabbix sender protocol
# ============================================================

def send_zabbix_trap(host: str, key: str, value: Any) -> bool:
    return send_zabbix_metrics(host, {key: value})


def send_zabbix_metrics(host: str, key_value_pairs: Dict[str, Any]) -> bool:
    """Send trapper values and validate Zabbix's sender response."""
    if not key_value_pairs:
        return True

    packet = {
        "request": "sender data",
        "data": [
            {"host": host, "key": key, "value": str(value)}
            for key, value in key_value_pairs.items()
        ],
    }
    payload = json.dumps(packet).encode("utf-8")
    header = b"ZBXD\x01" + len(payload).to_bytes(8, byteorder="little")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((ZABBIX_SERVER, ZABBIX_PORT))
            sock.sendall(header + payload)
            response = sock.recv(4096)

        if not response.startswith(b"ZBXD\x01"):
            raise RuntimeError("Zabbix returned an invalid sender response")

        response_payload = response[13:].decode("utf-8", errors="replace")
        response_data = json.loads(response_payload)
        failed = int(response_data.get("failed", 0))
        processed = int(response_data.get("processed", 0))

        if failed:
            logger.error(
                "[ZABBIX] Server rejected %d/%d item(s) for %s: %s",
                failed, len(key_value_pairs), host, response_data,
            )
            return False

        logger.info("[ZABBIX] Accepted %d item(s) for %s", processed, host)
        return True
    except Exception as exc:
        logger.error("[ZABBIX] Failed to send trap(s) for %s: %s", host, exc)
        return False


# ============================================================
# Reachability helpers
# ============================================================

def tcp_port_open(ip: str, port: int, timeout: float = TCP_CONNECT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def ping_host(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip],
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT_SECONDS + 2,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def classify_management_failure(ip: str, service_port: int, secondary_port: Optional[int] = None) -> str:
    """
    Return 'TELEMETRY_ERROR' if the host appears reachable but its monitoring
    service failed; otherwise return 'UNREACHABLE'.

    ICMP can be blocked in some environments, so an open secondary management
    port also counts as evidence that the host is reachable.
    """
    if tcp_port_open(ip, service_port):
        return DEVICE_STATE_TELEMETRY_ERROR
    if secondary_port and tcp_port_open(ip, secondary_port):
        return DEVICE_STATE_TELEMETRY_ERROR
    if ping_host(ip):
        return DEVICE_STATE_TELEMETRY_ERROR
    return DEVICE_STATE_UNREACHABLE


# ============================================================
# Health metrics
# ============================================================

def measure_latency_ms(ip: str) -> Optional[float]:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip],
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT_SECONDS + 2,
        )
        if result.returncode != 0:
            return None
        match = re.search(r"time[=<]([\d.]+)", result.stdout)
        return float(match.group(1)) if match else None
    except Exception as exc:
        logger.error("[PING] Failed to measure latency to %s: %s", ip, exc)
        return None


def collect_switch_metrics(gc: gNMIclient, node_ip: str) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}

    mem_util = gnmi_get_value(
        gc, f"/platform/control[slot={SRL_CONTROL_SLOT}]/memory/utilization"
    )
    if mem_util is not None:
        try:
            metrics["ibn.metrics.memory_utilization_percent"] = float(mem_util)
        except (TypeError, ValueError):
            pass

    last_booted = gnmi_get_value(gc, "/platform/chassis/last-booted")
    if last_booted:
        try:
            boot_time = datetime.fromisoformat(str(last_booted).replace("Z", "+00:00"))
            metrics["ibn.metrics.uptime_seconds"] = max(
                (datetime.now(timezone.utc) - boot_time).total_seconds(), 0
            )
        except ValueError:
            logger.warning("[METRICS] Unrecognized last-booted timestamp: %r", last_booted)

    latency = measure_latency_ms(node_ip)
    if latency is not None:
        metrics["ibn.metrics.latency_ms"] = latency
    return metrics


def collect_alpine_metrics(ssh: ConnectHandler, node_ip: str) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}

    try:
        cpu_command = (
            "awk '/^cpu / {total=$2+$3+$4+$5+$6+$7+$8; idle=$5; "
            "printf \"%.2f %.2f\\n\", total, idle}' /proc/stat"
        )
        first = ssh.send_command(cpu_command).strip().split()
        if len(first) == 2:
            total_1, idle_1 = float(first[0]), float(first[1])
            time.sleep(0.2)
            second = ssh.send_command(cpu_command).strip().split()
            if len(second) == 2:
                total_2, idle_2 = float(second[0]), float(second[1])
                total_delta, idle_delta = total_2 - total_1, idle_2 - idle_1
                if total_delta > 0:
                    cpu = 100.0 * (1.0 - idle_delta / total_delta)
                    metrics["ibn.metrics.cpu_utilization_percent"] = round(
                        max(0.0, min(100.0, cpu)), 2
                    )
    except Exception as exc:
        logger.error("[METRICS] Failed to read CPU on %s: %s", node_ip, exc)

    try:
        meminfo = ssh.send_command("cat /proc/meminfo")
        total_match = re.search(r"MemTotal:\s+(\d+)", meminfo)
        available_match = re.search(r"MemAvailable:\s+(\d+)", meminfo)
        if total_match and available_match:
            total_kb, available_kb = int(total_match.group(1)), int(available_match.group(1))
            if total_kb > 0:
                metrics["ibn.metrics.memory_utilization_percent"] = round(
                    100.0 * (total_kb - available_kb) / total_kb, 2
                )
    except Exception as exc:
        logger.error("[METRICS] Failed to read memory on %s: %s", node_ip, exc)

    try:
        disk_output = ssh.send_command(
            "df -P / | awk 'NR==2 {gsub(/%/,\"\",$5); print $5}'"
        ).strip()
        if disk_output:
            metrics["ibn.metrics.disk_utilization_percent"] = round(float(disk_output), 2)
    except Exception as exc:
        logger.error("[METRICS] Failed to read disk utilization on %s: %s", node_ip, exc)

    try:
        proc_uptime = ssh.send_command("cat /proc/uptime")
        metrics["ibn.metrics.uptime_seconds"] = float(proc_uptime.split()[0])
    except Exception as exc:
        logger.error("[METRICS] Failed to read uptime on %s: %s", node_ip, exc)

    latency = measure_latency_ms(node_ip)
    if latency is not None:
        metrics["ibn.metrics.latency_ms"] = latency
    return metrics


def json_rpc_set(node_ip: str, commands: List[Dict[str, Any]]) -> Dict[str, Any]:
    url = f"http://{node_ip}:{JSON_RPC_PORT}/jsonrpc"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "set",
        "params": {"commands": commands},
    }
    response = requests.post(
        url, json=payload, auth=(SRL_USERNAME, SRL_PASSWORD),
        verify=False, timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data


# ============================================================
# gNMI structured state
# ============================================================

def gnmi_get_value(gc: gNMIclient, path: str) -> Any:
    """
    Return the first structured value for a path. Exceptions are allowed to
    propagate so missing data is not confused with telemetry failure.
    """
    response = gc.get(path=[path], datatype="all")
    for notification in response.get("notification", []):
        updates = notification.get("update", [])
        if updates:
            return updates[0].get("val")
    return None


# ============================================================
# SR Linux drift detection
# ============================================================

def detect_switch_drift(
    gc: gNMIclient,
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
) -> List[str]:
    drift_reasons: List[str] = []
    security = intent_data["global_settings"]["security"]
    acl_name = security["acl_name"]
    drop_port = int(security["drop_tcp_ports"][0])
    expected_banner = intent_data["global_settings"]["system_banner"]
    routing_protocol = intent_data["global_settings"]["routing"]["protocol"].lower()
    area_id = intent_data["global_settings"]["routing"].get("area", OSPF_AREA_ID)
    router_id = node_config["router_id"]
    interfaces = node_config["interfaces"]
    vlan_interfaces = node_config["vlan_interfaces"]

    acl_val = gnmi_get_value(gc, f"/acl/acl-filter[name={acl_name}][type=ipv4]")
    if acl_val is None:
        drift_reasons.append(
            f"Security ACL missing | Current: absent | Expected: ACL {acl_name} "
            f"with drop destination port {drop_port}"
        )
    else:
        entries = acl_val.get("entry", []) if isinstance(acl_val, dict) else []
        has_matching_drop = any(
            "drop" in entry.get("action", {})
            and str(
                entry.get("match", {}).get("transport", {})
                .get("destination-port", {}).get("value")
            ) == str(drop_port)
            for entry in entries
        )
        if not has_matching_drop:
            drift_reasons.append(
                f"Security ACL present but drop-port rule missing/incorrect | "
                f"Current: required drop rule for destination port {drop_port} not present | "
                f"Expected: drop destination port {drop_port}"
            )

    banner_val = gnmi_get_value(gc, "/system/banner/login-banner")
    if banner_val != expected_banner:
        drift_reasons.append(
            f"Login-banner mismatch | Current: {banner_val!r} | Expected: {expected_banner!r}"
        )

    for iface in interfaces.keys():
        admin_state = gnmi_get_value(gc, f"/interface[name={iface}]/admin-state")
        if str(admin_state).strip().lower() in {"disable", "disabled"}:
            drift_reasons.append(
                f"Administratively disabled interface {iface} | Current admin-state: disable | "
                "Expected: enable | Manual review required; do not automatically enable"
            )

        mtu_val = gnmi_get_value(gc, f"/interface[name={iface}]/mtu")
        try:
            mtu_ok = int(mtu_val) == 9000
        except (TypeError, ValueError):
            mtu_ok = False
        if not mtu_ok:
            drift_reasons.append(
                f"MTU degraded on {iface} | Current: {mtu_val} | Expected: 9000"
            )

    if routing_protocol == "ospfv2":
        ospf_val = gnmi_get_value(
            gc, "/network-instance[name=default]/protocols/ospf/instance[name=default]"
        )
        if ospf_val is None:
            drift_reasons.append(
                "OSPFv2 instance deleted | Current: absent | Expected: configured OSPFv2 instance"
            )
        else:
            admin_state_ok = str(ospf_val.get("admin-state", "")).lower() == "enable"
            router_id_ok = router_id is not None and str(ospf_val.get("router-id")) == str(router_id)
            associated_ifaces = set()
            for area in ospf_val.get("area", []):
                if str(area.get("area-id")) != str(area_id):
                    continue
                for iface_entry in area.get("interface", []):
                    iface_name = iface_entry.get("interface-name")
                    if iface_name:
                        associated_ifaces.add(iface_name)

            expected_ifaces = {f"{iface}.0" for iface in interfaces.keys()}
            expected_ifaces.update(
                f"{vlan['port']}.{vlan['subinterface_index']}" for vlan in vlan_interfaces
            )
            if not expected_ifaces.issubset(associated_ifaces):
                drift_reasons.append(
                    f"OSPFv2 area/interface associations incomplete | "
                    f"Current: {sorted(associated_ifaces)} | Expected: {sorted(expected_ifaces)}"
                )
            if not admin_state_ok or not router_id_ok:
                drift_reasons.append(
                    f"OSPFv2 admin-state or router-id mismatch | "
                    f"Current admin-state: {ospf_val.get('admin-state')} | "
                    f"Expected admin-state: enable | Current router-id: {ospf_val.get('router-id')} | "
                    f"Expected router-id: {router_id}"
                )

    rogue_val = gnmi_get_value(gc, "/system/aaa/authentication/user[username=rogueadmin]")
    if rogue_val is not None:
        drift_reasons.append(
            "Unauthorized backdoor account 'rogueadmin' detected | "
            "Current: account exists | Expected: account absent"
        )

    for vlan in vlan_interfaces:
        port, idx = vlan["port"], vlan["subinterface_index"]
        vlan_val = gnmi_get_value(gc, f"/interface[name={port}]/subinterface[index={idx}]")
        if vlan_val is None:
            drift_reasons.append(
                f"VLAN {vlan['vlan_id']} ({vlan['name']}) subinterface deleted | "
                f"Current: absent | Expected: configured subinterface {port}.{idx} "
                f"with IP {vlan['gateway_ip']}"
            )
        else:
            expected_ip = vlan["gateway_ip"]
            address_list = vlan_val.get("ipv4", {}).get("address", [])
            actual_prefixes = {
                item.get("ip-prefix") for item in address_list if isinstance(item, dict)
            }
            if expected_ip not in actual_prefixes:
                drift_reasons.append(
                    f"VLAN {vlan['vlan_id']} ({vlan['name']}) subinterface IP misconfigured | "
                    f"Current: {sorted(actual_prefixes)} | Expected: {expected_ip}"
                )
    return drift_reasons


# ============================================================
# SR Linux remediation + verification
# ============================================================

def remediate_switch_drift(
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
    drift_reasons: List[str],
) -> Tuple[bool, str]:
    node_ip, node_name = node_config["management_ip"], node_config["name"]
    try:
        commands = render_remediation_commands(node_config, intent_data, drift_reasons)
        result = json_rpc_set(node_ip, commands)
        logger.info("[REMEDIATION] %s: JSON-RPC accepted: %s", node_name, result)
        return True, "Remediation commands accepted by SR Linux"
    except Exception as exc:
        logger.error("[REMEDIATION] %s failed: %s", node_name, exc)
        return False, f"Remediation failed: {exc}"


def verify_switch_compliance(
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
) -> Tuple[bool, List[str], Optional[str]]:
    node_ip = node_config["management_ip"]
    try:
        with gNMIclient(
            target=(node_ip, GNMI_PORT), username=SRL_USERNAME,
            password=SRL_PASSWORD, skip_verify=True,
        ) as gc:
            reasons = detect_switch_drift(gc, node_config, intent_data)
        return not reasons, reasons, None
    except Exception as exc:
        return False, [], str(exc)


# ============================================================
# Alpine drift + remediation + verification
# ============================================================

def detect_alpine_drift(
    ssh: ConnectHandler,
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
) -> Dict[str, Any]:
    security = intent_data["global_settings"]["security"]
    expected_dns = intent_data["global_settings"]["linux_services"]["expected_dns"]
    authorized_users = set(security.get("authorized_users", [])) | {"root"}
    report = {
        "reasons": [], "dns_mismatch": False, "vlan_missing": False,
        "vlan_ip_wrong": False, "unauthorized_accounts": [],
    }

    dns_output = ssh.send_command("cat /etc/resolv.conf")
    if expected_dns not in dns_output:
        report["dns_mismatch"] = True
        report["reasons"].append(
            f"DNS nameserver mismatch | Current: {dns_output.strip()} | "
            f"Expected: nameserver {expected_dns}"
        )

    vlan_id = node_config["vlan_id"]
    if vlan_id:
        vlan_iface = f"eth1.{vlan_id}"
        link_output = ssh.send_command(f"ip -o link show {vlan_iface} 2>&1")
        if not link_output.strip() or "does not exist" in link_output.lower():
            report["vlan_missing"] = True
            report["reasons"].append(
                f"VLAN sub-interface {vlan_iface} missing | Current: absent | "
                f"Expected: {vlan_iface} with IP {node_config['vlan_ip']}"
            )
        else:
            expected_ip = node_config["vlan_ip"]
            addr_output = ssh.send_command(f"ip -4 -o addr show {vlan_iface}")
            if expected_ip and expected_ip.split("/")[0] not in addr_output:
                report["vlan_ip_wrong"] = True
                report["reasons"].append(
                    f"VLAN sub-interface {vlan_iface} IP misconfigured | "
                    f"Current: {addr_output.strip()} | Expected: {expected_ip}"
                )

    passwd_output = ssh.send_command("cat /etc/passwd")
    for line in passwd_output.splitlines():
        fields = line.split(":")
        if len(fields) < 3:
            continue
        uname, uid_str = fields[0].strip(), fields[2].strip()
        if not uname or not uid_str.isdigit():
            continue
        uid = int(uid_str)
        # Alpine's standard "nobody" service account commonly uses UID 65534.
        # It is a system identity, not an interactive user, and should not
        # block unrelated automatic configuration remediation.
        is_unexpected_root_account = uid == 0 and uname != "root"
        is_unapproved_login_account = uid >= 1000 and uid < 60000 and uname not in authorized_users
        if is_unexpected_root_account or is_unapproved_login_account:
            report["unauthorized_accounts"].append(uname)

    if report["unauthorized_accounts"]:
        report["reasons"].append(
            "Unauthorized local account(s) detected | Current: "
            f"{', '.join(report['unauthorized_accounts'])} | Expected: authorized accounts only"
        )
    return report


def remediate_alpine_drift(
    ssh: ConnectHandler,
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
    report: Dict[str, Any],
) -> Tuple[bool, str]:
    node_name, actions = node_config["name"], []
    try:
        if report["dns_mismatch"]:
            expected_dns = intent_data["global_settings"]["linux_services"]["expected_dns"]
            ssh.send_command(f"printf 'nameserver {expected_dns}\\n' > /etc/resolv.conf")
            actions.append(f"DNS restored to {expected_dns}")

        if report["vlan_missing"] or report["vlan_ip_wrong"]:
            vlan_id, vlan_ip, vlan_gw = (
                node_config["vlan_id"], node_config["vlan_ip"], node_config["vlan_gw"]
            )
            vlan_iface = f"eth1.{vlan_id}"
            ssh.send_command("ip link set eth1 up")
            ssh.send_command(
                f"ip link add link eth1 name {vlan_iface} type vlan id {vlan_id} "
                "2>/dev/null || true"
            )
            ssh.send_command(f"ip link set {vlan_iface} up")
            ssh.send_command(
                f"ip addr flush dev {vlan_iface} 2>/dev/null || true; "
                f"ip addr add {vlan_ip} dev {vlan_iface}"
            )
            ssh.send_command(f"ip route replace default via {vlan_gw} dev {vlan_iface}")
            actions.append(f"VLAN {vlan_iface} reconstructed")

        # Security-related account findings are handled by manual review before
        # this function is called. This loop remains for compatibility with reports.
        for account in report["unauthorized_accounts"]:
            if account != "root":
                ssh.send_command(f"deluser {account} 2>/dev/null || true")
                actions.append(f"Removed unauthorized account '{account}'")
        return True, "; ".join(actions) if actions else "Nothing actionable"
    except Exception as exc:
        logger.error("[REMEDIATION] %s failed: %s", node_name, exc)
        return False, str(exc)


def verify_alpine_compliance(
    ssh: ConnectHandler,
    node_config: Dict[str, Any],
    intent_data: Dict[str, Any],
) -> Tuple[bool, List[str], Optional[str]]:
    try:
        report = detect_alpine_drift(ssh, node_config, intent_data)
        return not report["reasons"], report["reasons"], None
    except Exception as exc:
        return False, [], str(exc)


# ============================================================
# Incident and status reporting
# ============================================================

def send_incident(
    host: str,
    event_type: str,
    summary: str,
    details: str = "",
    masked_ip: str = "",
    manual_review: bool = False,
) -> bool:
    """Send one incident payload to the existing Zabbix trapper item."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    manual_review_text = "YES" if manual_review else "NO"
    payload = (
        f"<b>IBN {html.escape(str(event_type))}</b><br>"
        f"<b>Timestamp:</b> {timestamp}<br>"
        f"<b>Masked IP:</b> {html.escape(str(masked_ip))}<br>"
        f"<b>Manual Review Required:</b> {manual_review_text}<br>"
        f"<b>Summary:</b> {html.escape(str(summary))}"
        + (f"<br><b>Details:</b> {html.escape(str(details))}" if details else "")
    )
    return send_zabbix_trap(host, "ibn.incident_report", payload)


def send_incident_once(
    host: str,
    state: Dict[str, Any],
    incident_key: str,
    event_type: str,
    summary: str,
    details: str = "",
    masked_ip: str = "",
    manual_review: bool = False,
) -> bool:
    """
    Suppress repeated sends for the same active incident. Mark it active only
    when Zabbix accepts the trap; this confirms sender acceptance, not email
    delivery by a downstream Zabbix action.
    """
    if is_incident_active(state, incident_key):
        logger.info("[%s] Incident already active; suppressing duplicate", incident_key)
        return False

    accepted = send_incident(
        host, event_type, summary, details,
        masked_ip=masked_ip, manual_review=manual_review,
    )
    if accepted:
        state.setdefault("active_incidents", set()).add(incident_key)
    return accepted


def send_status_metrics(
    host: str,
    state: Dict[str, Any],
    compliant: bool,
    drift_count: int,
    reachable: bool = True,
    telemetry_ok: bool = True,
    remediation_status: int = REMEDIATION_STATUS_NONE,
    last_event: str = "",
    masked_ip: str = "",
    drift_details: str = "",
) -> None:
    send_zabbix_metrics(
        host,
        {
            "ibn.compliance.state": 1 if compliant else 0,
            "ibn.drift.active": 0 if compliant else 1,
            "ibn.drift.count": max(0, drift_count),
            "ibn.remediation.attempts": state["remediation_attempts"],
            "ibn.remediation.status": remediation_status,
            "ibn.manual_review": 1 if state["state"] == DEVICE_STATE_MANUAL else 0,
            "ibn.device.reachable": DEVICE_REACHABLE if reachable else DEVICE_UNREACHABLE,
            "ibn.telemetry.status": TELEMETRY_OK if telemetry_ok else TELEMETRY_FAILED,
            "ibn.last_event": last_event or state["state"],
            "ibn.device.ip.masked": masked_ip,
            "ibn.drift.details": drift_details,
        },
    )


def is_manual_review_finding(reason: str) -> bool:
    """Findings that must not be autonomously changed."""
    lowered = reason.lower()
    markers = (
        "unauthorized backdoor account",
        "unauthorized privileged account",
        "unauthorized local account",
        "unauthorized account",
        "administratively disabled interface",
        "interface administratively disabled",
    )
    return any(marker in lowered for marker in markers)


def split_manual_review_findings(reasons: List[str]) -> Tuple[List[str], List[str]]:
    automatic, manual = [], []
    for reason in reasons:
        (manual if is_manual_review_finding(reason) else automatic).append(reason)
    return automatic, manual


def requires_manual_review(reasons: List[str]) -> bool:
    """Compatibility helper for callers that need a manual-review boolean."""
    return any(is_manual_review_finding(reason) for reason in reasons)


def handle_compliance_result(
    host: str,
    state: Dict[str, Any],
    reasons: List[str],
    remediation_fn,
    verify_fn,
    masked_ip: str = "",
) -> None:
    """Detect -> remediate -> verify, with one alert per active incident class."""
    drift_details = build_drift_details(reasons)

    # A successful telemetry/reconciliation pass means previous reachability and
    # telemetry incidents have cleared, regardless of whether drift remains.
    clear_incident(state, INCIDENT_UNREACHABLE)
    clear_incident(state, INCIDENT_TELEMETRY)

    if not reasons:
        was_problem = state["state"] != DEVICE_STATE_COMPLIANT
        had_drift_alert = is_incident_active(state, INCIDENT_DRIFT)
        had_security_alert = is_incident_active(state, INCIDENT_SECURITY_REVIEW)

        state["state"] = DEVICE_STATE_COMPLIANT
        state["remediation_attempts"] = 0
        state["finding_signature"] = None
        state["last_incident_signature"] = None
        clear_incident(state, INCIDENT_DRIFT)
        clear_incident(state, INCIDENT_SECURITY_REVIEW)
        clear_incident(state, INCIDENT_REMEDIATION)

        send_status_metrics(
            host, state, True, 0, reachable=True, telemetry_ok=True,
            remediation_status=(
                REMEDIATION_STATUS_RECOVERED if was_problem
                else REMEDIATION_STATUS_NONE
            ),
            last_event="Device recovered and is compliant" if was_problem else "Device compliant",
            masked_ip=masked_ip,
            drift_details=build_drift_details([]),
        )

        # Recovery is a separate lifecycle event, emitted once only if an
        # incident alert had previously been accepted by Zabbix.
        if was_problem and (had_drift_alert or had_security_alert):
            send_incident(
                host, "RECOVERY",
                "Device is compliant again; the active incident has cleared.",
                "A successful check found no remaining configuration drift.",
                masked_ip=masked_ip,
            )
        return

    signature = finding_signature(reasons)
    state["finding_signature"] = signature

    automatic_reasons, manual_reasons = split_manual_review_findings(reasons)

    # Manual-review findings are flagged but do not block unrelated safe fixes.
    # Pass ONLY automatic findings to remediation so protected settings/accounts
    # cannot be changed by a broad template or remediation routine.
    if manual_reasons:
        state["state"] = DEVICE_STATE_MANUAL
        send_incident_once(
            host, state, INCIDENT_SECURITY_REVIEW,
            "MANUAL REVIEW REQUIRED",
            "One or more findings require administrator review; these findings will not be changed automatically.",
            build_drift_details(manual_reasons),
            masked_ip=masked_ip,
            manual_review=True,
        )
    else:
        clear_incident(state, INCIDENT_SECURITY_REVIEW)

    if not automatic_reasons:
        send_incident_once(
            host, state, INCIDENT_DRIFT,
            "MANUAL REVIEW REQUIRED",
            "No automatically remediable findings remain; administrator review is required.",
            build_drift_details(manual_reasons),
            masked_ip=masked_ip,
            manual_review=True,
        )
        send_status_metrics(
            host, state, False, len(reasons), reachable=True, telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_MANUAL_REVIEW,
            last_event="Manual-review findings flagged; no automatic changes needed",
            masked_ip=masked_ip,
            drift_details=drift_details,
        )
        return

    # Report the full mixed finding set, then remediate only automatic findings.
    send_incident_once(
        host, state, INCIDENT_DRIFT,
        "CONFIGURATION DRIFT DETECTED",
        (
            "Mixed automatic and manual-review findings detected; safe findings will be remediated "
            "and manual-review findings will remain unchanged."
            if manual_reasons else
            "The observed device state differs from the intended configuration."
        ),
        signature,
        masked_ip=masked_ip,
        manual_review=bool(manual_reasons),
    )

    state["state"] = DEVICE_STATE_MANUAL if manual_reasons else DEVICE_STATE_DRIFT
    state["remediation_attempts"] += 1
    attempt = state["remediation_attempts"]

    if attempt > MAX_REMEDIATION_ATTEMPTS:
        state["state"] = DEVICE_STATE_MANUAL
        send_status_metrics(
            host, state, False, len(reasons), reachable=True, telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_MANUAL_REVIEW,
            last_event="Autonomous remediation suspended after retry limit",
            masked_ip=masked_ip,
            drift_details=drift_details,
        )
        send_incident_once(
            host, state, INCIDENT_REMEDIATION,
            "REMEDIATION FAILED",
            "Autonomous remediation was suspended after reaching the retry limit.",
            f"Attempts: {state['remediation_attempts']}\nRemaining findings: {drift_details}",
            masked_ip=masked_ip,
            manual_review=True,
        )
        return

    state["state"] = DEVICE_STATE_REMEDIATING
    send_status_metrics(
        host, state, False, len(reasons), reachable=True, telemetry_ok=True,
        remediation_status=REMEDIATION_STATUS_IN_PROGRESS,
        last_event=f"Remediation attempt {attempt}",
        masked_ip=masked_ip,
        drift_details=drift_details,
    )

    applied, action_text = remediation_fn(automatic_reasons)
    if not applied:
        state["state"] = DEVICE_STATE_MANUAL if manual_reasons else DEVICE_STATE_DRIFT
        send_status_metrics(
            host, state, False, len(reasons), reachable=True, telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_FAILED,
            last_event="Remediation failed; drift incident remains active",
            masked_ip=masked_ip,
            drift_details=drift_details,
        )
        logger.error("[REMEDIATION] %s: %s", host, action_text)
        if attempt >= MAX_REMEDIATION_ATTEMPTS:
            send_incident_once(
                host, state, INCIDENT_REMEDIATION,
                "REMEDIATION FAILED",
                "Autonomous remediation failed and the retry limit has been reached.",
                f"Attempts: {attempt}\nResult: {action_text}\nFindings: {drift_details}",
                masked_ip=masked_ip,
                manual_review=True,
            )
        return

    time.sleep(REMEDIATION_VERIFY_DELAY)
    verified, verification_reasons, verify_error = verify_fn()

    verification_auto, verification_manual = split_manual_review_findings(verification_reasons or [])
    if verified or (not verify_error and not verification_auto):
        state["state"] = DEVICE_STATE_MANUAL if verification_manual else DEVICE_STATE_COMPLIANT
        state["remediation_attempts"] = 0
        state["finding_signature"] = finding_signature(verification_manual) if verification_manual else None
        state["last_incident_signature"] = None
        had_drift_alert = is_incident_active(state, INCIDENT_DRIFT)
        if not verification_manual:
            clear_incident(state, INCIDENT_DRIFT)
            clear_incident(state, INCIDENT_SECURITY_REVIEW)

        send_incident_once(
            host, state, INCIDENT_REMEDIATION,
            "PARTIAL REMEDIATION — MANUAL REVIEW REMAINS" if verification_manual else "REMEDIATION SUCCEEDED",
            "Safe configuration drift was remediated and verification completed.",
            (
                f"Attempts: {attempt}\nAutomatic remediation result: {action_text}\n"
                f"Automatic findings addressed: {build_drift_details(automatic_reasons)}\n"
                f"Manual-review findings remaining: {build_drift_details(verification_manual)}"
                if verification_manual else f"Attempts: {attempt}\nResult: {action_text}\nOriginal findings: {drift_details}"
            ),
            masked_ip=masked_ip,
            manual_review=bool(verification_manual),
        )

        send_status_metrics(
            host, state, not verification_manual, len(verification_manual),
            reachable=True, telemetry_ok=True,
            remediation_status=(
                REMEDIATION_STATUS_MANUAL_REVIEW if verification_manual
                else REMEDIATION_STATUS_RECOVERED
            ),
            last_event=(
                "Safe drift remediated; manual-review findings remain"
                if verification_manual else "Remediation verified successfully"
            ),
            masked_ip=masked_ip,
            drift_details=build_drift_details(verification_manual),
        )
        if had_drift_alert and not verification_manual:
            send_incident(
                host, "RECOVERY",
                "Desired state was verified after remediation.",
                action_text,
                masked_ip=masked_ip,
            )
        return

    # A failed verification is recorded in Zabbix metrics/logs but does not
    # generate another email while the original drift incident is active.
    failed_reasons = verification_reasons or reasons
    _failed_auto, failed_manual = split_manual_review_findings(failed_reasons)
    state["state"] = DEVICE_STATE_MANUAL if failed_manual else DEVICE_STATE_DRIFT
    send_status_metrics(
        host, state, False, len(failed_reasons), reachable=True, telemetry_ok=True,
        remediation_status=REMEDIATION_STATUS_FAILED,
        last_event=(
            "Remediation verification failed"
            if verify_error else "Remediation did not converge"
        ),
        masked_ip=masked_ip,
        drift_details=build_drift_details(failed_reasons),
    )
    if verify_error:
        logger.error("[VERIFY] %s: %s", host, verify_error)
    else:
        logger.warning(
            "[VERIFY] %s still has drift after remediation: %s",
            host, finding_signature(verification_reasons),
        )
    if attempt >= MAX_REMEDIATION_ATTEMPTS:
        send_incident_once(
            host, state, INCIDENT_REMEDIATION,
            "REMEDIATION FAILED",
            "Configuration drift remained after the final remediation verification.",
            f"Attempts: {attempt}\nVerification error: {verify_error or 'none'}\nRemaining findings: {build_drift_details(failed_reasons)}",
            masked_ip=masked_ip,
            manual_review=True,
        )


# ============================================================
# Monitoring loops
# ============================================================

def report_management_failure(
    host: str,
    state: Dict[str, Any],
    node_ip: str,
    error: Exception,
    service_name: str,
    service_port: int,
    secondary_port: Optional[int] = None,
) -> None:
    failure_state = classify_management_failure(node_ip, service_port, secondary_port)
    masked_ip = mask_ip_address(node_ip)
    detail = f"{service_name} monitoring failed | Current: {error}"

    if failure_state == DEVICE_STATE_UNREACHABLE:
        state["state"] = DEVICE_STATE_UNREACHABLE
        clear_incident(state, INCIDENT_TELEMETRY)
        send_status_metrics(
            host, state, False, 0, reachable=False, telemetry_ok=False,
            remediation_status=REMEDIATION_STATUS_NONE,
            last_event="Device unreachable",
            masked_ip=masked_ip,
            drift_details=f"Device appears unreachable | {detail}",
        )
        send_incident_once(
            host, state, INCIDENT_UNREACHABLE,
            "DEVICE UNREACHABLE",
            "The device cannot be reached through the tested management paths.",
            detail,
            masked_ip=masked_ip,
        )
    else:
        state["state"] = DEVICE_STATE_TELEMETRY_ERROR
        clear_incident(state, INCIDENT_UNREACHABLE)
        send_status_metrics(
            host, state, False, 0, reachable=True, telemetry_ok=False,
            remediation_status=REMEDIATION_STATUS_NONE,
            last_event=f"{service_name} telemetry/management failure",
            masked_ip=masked_ip,
            drift_details=f"Device responds, but monitoring access failed | {detail}",
        )
        send_incident_once(
            host, state, INCIDENT_TELEMETRY,
            "TELEMETRY ERROR",
            f"The device appears reachable, but {service_name} monitoring failed.",
            detail,
            masked_ip=masked_ip,
        )


def automatic_reasons_for_remediation(reasons: List[str]) -> List[str]:
    automatic, _manual = split_manual_review_findings(reasons)
    return automatic


def monitor_switch_telemetry(
    device: Dict[str, Any],
    intent_data: Dict[str, Any],
    day0_data: Dict[str, Any],
) -> None:
    node_config = build_node_config(device, day0_data)
    node_ip, node_name = node_config["management_ip"], node_config["name"]
    state = get_device_state(node_name)
    masked_ip = mask_ip_address(node_ip)

    if not node_config["router_id"]:
        logger.warning("[CONFIG] %s has no day-0 router-id", node_name)

    try:
        with gNMIclient(
            target=(node_ip, GNMI_PORT), username=SRL_USERNAME,
            password=SRL_PASSWORD, skip_verify=True,
        ) as gc:
            drift_reasons = detect_switch_drift(gc, node_config, intent_data)
            metrics = collect_switch_metrics(gc, node_ip)

        clear_incident(state, INCIDENT_UNREACHABLE)
        clear_incident(state, INCIDENT_TELEMETRY)
        if metrics:
            send_zabbix_metrics(node_name, metrics)

        handle_compliance_result(
            node_name, state, drift_reasons,
            remediation_fn=lambda automatic_reasons: remediate_switch_drift(
                node_config, intent_data, automatic_reasons
            ),
            verify_fn=lambda: verify_switch_compliance(node_config, intent_data),
            masked_ip=masked_ip,
        )
    except Exception as exc:
        logger.error("[gNMI] Monitoring failed for %s: %s", node_name, exc)
        report_management_failure(
            node_name, state, node_ip, exc,
            service_name="gNMI", service_port=GNMI_PORT,
            secondary_port=JSON_RPC_PORT,
        )


def monitor_alpine_node(
    device: Dict[str, Any],
    intent_data: Dict[str, Any],
    linux_init_data: Dict[str, Any],
) -> None:
    node_config = build_alpine_node_config(device, linux_init_data)
    node_ip, node_name = node_config["management_ip"], node_config["name"]
    state = get_device_state(node_name)
    masked_ip = mask_ip_address(node_ip)
    alpine_device = {
        "device_type": "linux",
        "host": node_ip,
        "username": ALPINE_USERNAME,
        "password": ALPINE_PASSWORD,
        "global_delay_factor": 0.5,
    }

    try:
        with ConnectHandler(**alpine_device) as ssh:
            metrics = collect_alpine_metrics(ssh, node_ip)
            if metrics:
                send_zabbix_metrics(node_name, metrics)

            report = detect_alpine_drift(ssh, node_config, intent_data)
            clear_incident(state, INCIDENT_UNREACHABLE)
            clear_incident(state, INCIDENT_TELEMETRY)
            handle_compliance_result(
                node_name, state, report["reasons"],
                remediation_fn=lambda automatic_reasons: remediate_alpine_drift(
                    ssh, node_config, intent_data,
                    {
                        **report,
                        "reasons": automatic_reasons,
                        "dns_mismatch": report["dns_mismatch"] and any("dns nameserver mismatch" in r.lower() for r in automatic_reasons),
                        "vlan_missing": report["vlan_missing"] and any("vlan sub-interface" in r.lower() and "missing" in r.lower() for r in automatic_reasons),
                        "vlan_ip_wrong": report["vlan_ip_wrong"] and any("vlan sub-interface" in r.lower() and "ip misconfigured" in r.lower() for r in automatic_reasons),
                        "unauthorized_accounts": [],
                    }
                ),
                verify_fn=lambda: verify_alpine_compliance(
                    ssh, node_config, intent_data
                ),
                masked_ip=masked_ip,
            )
    except Exception as exc:
        logger.error("[SSH] Monitoring failed for %s: %s", node_name, exc)
        report_management_failure(
            node_name, state, node_ip, exc,
            service_name="SSH", service_port=22,
        )


# ============================================================
# Main loop
# ============================================================

def run_engine() -> None:
    logger.info(
        "Starting Autonomous Tier-1 IBN Drift Engine | poll=%ss | max_attempts=%s",
        POLL_INTERVAL, MAX_REMEDIATION_ATTEMPTS,
    )
    while True:
        try:
            intent = load_intent()
            day0 = load_day0_inventory()
            linux_init = load_linux_init()
            devices = intent.get("devices", [])

            for device in devices:
                name = device["name"].lower()
                if "srl" in name:
                    monitor_switch_telemetry(device, intent, day0)
                elif any(k in name for k in ["terminal", "workstation", "server"]):
                    monitor_alpine_node(device, intent, linux_init)

            time.sleep(POLL_INTERVAL)
        except Exception as exc:
            logger.error("[ENGINE] Failure: %s", exc)
            time.sleep(10)


if __name__ == "__main__":
    run_engine()
