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


def build_alpine_node_config(device: Dict[str, Any], linux_init_data: Dict[str, Any]) -> Dict[str, Any]:
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


def build_node_config(device: Dict[str, Any], day0_data: Dict[str, Any]) -> Dict[str, Any]:
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
# Device state
# ============================================================

DEVICE_STATE_COMPLIANT = "COMPLIANT"
DEVICE_STATE_DRIFT = "DRIFT_DETECTED"
DEVICE_STATE_REMEDIATING = "REMEDIATING"
DEVICE_STATE_MANUAL = "MANUAL_REVIEW"
DEVICE_STATE_UNREACHABLE = "UNREACHABLE"
DEVICE_STATE_TELEMETRY_ERROR = "TELEMETRY_ERROR"

# Zabbix remediation status values
REMEDIATION_STATUS_NONE = 0
REMEDIATION_STATUS_IN_PROGRESS = 1
REMEDIATION_STATUS_RECOVERED = 2
REMEDIATION_STATUS_FAILED = 3
REMEDIATION_STATUS_MANUAL_REVIEW = 4

# Zabbix reachability / telemetry values
DEVICE_REACHABLE = 1
DEVICE_UNREACHABLE = 0
TELEMETRY_OK = 1
TELEMETRY_FAILED = 0

_device_states: Dict[str, Dict[str, Any]] = {}


def get_device_state(name: str) -> Dict[str, Any]:
    return _device_states.setdefault(
        name,
        {
            "state": DEVICE_STATE_COMPLIANT,
            "remediation_attempts": 0,
            "finding_signature": None,
            "last_incident_signature": None,
        },
    )


def finding_signature(reasons: List[str]) -> str:
    return " | ".join(sorted(reasons))


# ============================================================
# Jinja remediation rendering
# ============================================================

_jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_remediation_commands(
    node_config: Dict[str, Any], intent_data: Dict[str, Any], drift_reasons: List[str]
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
        purge_backdoor=any("backdoor account" in reason.lower() for reason in drift_reasons),
    )

    try:
        commands = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Rendered remediation template is not valid JSON: {exc}\n---\n{rendered}")

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
                failed,
                len(key_value_pairs),
                host,
                response_data,
            )
            return False

        logger.info("[ZABBIX] Accepted %d item(s) for %s", processed, host)
        return True

    except Exception as exc:
        logger.error("[ZABBIX] Failed to send trap(s) for %s: %s", host, exc)
        return False


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

    # CPU utilization
    try:
        cpu_command = (
            "awk '/^cpu / {total=$2+$3+$4+$5+$6+$7+$8; idle=$5; "
            "printf \"%.2f %.2f\\n\", total, idle}' /proc/stat"
        )

        first = ssh.send_command(cpu_command).strip().split()
        if len(first) == 2:
            total_1 = float(first[0])
            idle_1 = float(first[1])

            time.sleep(0.2)

            second = ssh.send_command(cpu_command).strip().split()
            if len(second) == 2:
                total_2 = float(second[0])
                idle_2 = float(second[1])
                total_delta = total_2 - total_1
                idle_delta = idle_2 - idle_1

                if total_delta > 0:
                    cpu_utilization = 100.0 * (1.0 - idle_delta / total_delta)
                    metrics["ibn.metrics.cpu_utilization_percent"] = round(
                        max(0.0, min(100.0, cpu_utilization)), 2
                    )
    except Exception as exc:
        logger.error("[METRICS] Failed to read CPU on %s: %s", node_ip, exc)

    # Memory utilization
    try:
        meminfo = ssh.send_command("cat /proc/meminfo")
        total_match = re.search(r"MemTotal:\s+(\d+)", meminfo)
        available_match = re.search(r"MemAvailable:\s+(\d+)", meminfo)
        if total_match and available_match:
            total_kb = int(total_match.group(1))
            available_kb = int(available_match.group(1))
            if total_kb > 0:
                metrics["ibn.metrics.memory_utilization_percent"] = round(
                    100.0 * (total_kb - available_kb) / total_kb, 2
                )
    except Exception as exc:
        logger.error("[METRICS] Failed to read memory on %s: %s", node_ip, exc)

    # Root filesystem utilization
    try:
        disk_output = ssh.send_command(
            "df -P / | awk 'NR==2 {gsub(/%/,\"\",$5); print $5}'"
        ).strip()
        if disk_output:
            metrics["ibn.metrics.disk_utilization_percent"] = round(
                float(disk_output), 2
            )
    except Exception as exc:
        logger.error("[METRICS] Failed to read disk utilization on %s: %s", node_ip, exc)

    # Uptime
    try:
        proc_uptime = ssh.send_command("cat /proc/uptime")
        metrics["ibn.metrics.uptime_seconds"] = float(proc_uptime.split()[0])
    except Exception as exc:
        logger.error("[METRICS] Failed to read uptime on %s: %s", node_ip, exc)

    # Latency from the autonomous controller to the endpoint
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
        url,
        json=payload,
        auth=(SRL_USERNAME, SRL_PASSWORD),
        verify=False,
        timeout=10,
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
    Return the first structured value for a path.

    Exceptions are deliberately raised to the caller. "Path absent" and
    "telemetry failed" are different conditions and must not be treated as
    the same thing by the reconciliation engine.
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

def detect_switch_drift(gc: gNMIclient, node_config: Dict[str, Any], intent_data: Dict[str, Any]) -> List[str]:
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
        drift_reasons.append("Security ACL missing")
    else:
        entries = acl_val.get("entry", []) if isinstance(acl_val, dict) else []
        has_matching_drop = any(
            "drop" in entry.get("action", {})
            and str(entry.get("match", {}).get("transport", {}).get("destination-port", {}).get("value"))
            == str(drop_port)
            for entry in entries
        )
        if not has_matching_drop:
            drift_reasons.append("Security ACL present but drop-port rule missing/incorrect")

    banner_val = gnmi_get_value(gc, "/system/banner/login-banner")
    if banner_val != expected_banner:
        drift_reasons.append("Login-banner mismatch")

    for iface in interfaces.keys():
        mtu_val = gnmi_get_value(gc, f"/interface[name={iface}]/mtu")
        try:
            mtu_ok = int(mtu_val) == 9000
        except (TypeError, ValueError):
            mtu_ok = False
        if not mtu_ok:
            drift_reasons.append(f"MTU degraded on {iface}")

    if routing_protocol == "ospfv2":
        ospf_val = gnmi_get_value(
            gc, "/network-instance[name=default]/protocols/ospf/instance[name=default]"
        )
        if ospf_val is None:
            drift_reasons.append("OSPFv2 instance deleted")
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
                drift_reasons.append("OSPFv2 area/interface associations incomplete")
            if not admin_state_ok or not router_id_ok:
                drift_reasons.append("OSPFv2 admin-state or router-id mismatch")

    rogue_val = gnmi_get_value(gc, "/system/aaa/authentication/user[username=rogueadmin]")
    if rogue_val is not None:
        drift_reasons.append("Unauthorized backdoor account 'rogueadmin' detected")

    for vlan in vlan_interfaces:
        port = vlan["port"]
        idx = vlan["subinterface_index"]
        vlan_val = gnmi_get_value(gc, f"/interface[name={port}]/subinterface[index={idx}]")
        if vlan_val is None:
            drift_reasons.append(f"VLAN {vlan['vlan_id']} ({vlan['name']}) subinterface deleted")
        else:
            expected_ip = vlan["gateway_ip"]
            address_list = vlan_val.get("ipv4", {}).get("address", [])
            actual_prefixes = {
                item.get("ip-prefix") for item in address_list if isinstance(item, dict)
            }
            if expected_ip not in actual_prefixes:
                drift_reasons.append(
                    f"VLAN {vlan['vlan_id']} ({vlan['name']}) subinterface IP misconfigured"
                )

    return drift_reasons


# ============================================================
# SR Linux remediation + verification
# ============================================================

def remediate_switch_drift(
    node_config: Dict[str, Any], intent_data: Dict[str, Any], drift_reasons: List[str]
) -> Tuple[bool, str]:
    node_ip = node_config["management_ip"]
    node_name = node_config["name"]

    try:
        commands = render_remediation_commands(node_config, intent_data, drift_reasons)
        result = json_rpc_set(node_ip, commands)
        logger.info("[REMEDIATION] %s: JSON-RPC accepted: %s", node_name, result)
        return True, "Remediation commands accepted by SR Linux"
    except Exception as exc:
        logger.error("[REMEDIATION] %s failed: %s", node_name, exc)
        return False, f"Remediation failed: {exc}"


def verify_switch_compliance(
    node_config: Dict[str, Any], intent_data: Dict[str, Any]
) -> Tuple[bool, List[str], Optional[str]]:
    node_ip = node_config["management_ip"]
    try:
        with gNMIclient(
            target=(node_ip, GNMI_PORT),
            username=SRL_USERNAME,
            password=SRL_PASSWORD,
            skip_verify=True,
        ) as gc:
            reasons = detect_switch_drift(gc, node_config, intent_data)
        return not reasons, reasons, None
    except Exception as exc:
        return False, [], str(exc)


# ============================================================
# Alpine drift + remediation + verification
# ============================================================

def detect_alpine_drift(
    ssh: ConnectHandler, node_config: Dict[str, Any], intent_data: Dict[str, Any]
) -> Dict[str, Any]:
    security = intent_data["global_settings"]["security"]
    expected_dns = intent_data["global_settings"]["linux_services"]["expected_dns"]
    authorized_users = set(security.get("authorized_users", [])) | {"root"}

    report = {
        "reasons": [],
        "dns_mismatch": False,
        "vlan_missing": False,
        "vlan_ip_wrong": False,
        "unauthorized_accounts": [],
    }

    dns_output = ssh.send_command("cat /etc/resolv.conf")
    if expected_dns not in dns_output:
        report["dns_mismatch"] = True
        report["reasons"].append(f"DNS nameserver mismatch (expected {expected_dns})")

    vlan_id = node_config["vlan_id"]
    if vlan_id:
        vlan_iface = f"eth1.{vlan_id}"
        link_output = ssh.send_command(f"ip -o link show {vlan_iface} 2>&1")
        if not link_output.strip() or "does not exist" in link_output.lower():
            report["vlan_missing"] = True
            report["reasons"].append(f"VLAN sub-interface {vlan_iface} missing")
        else:
            expected_ip = node_config["vlan_ip"]
            addr_output = ssh.send_command(f"ip -4 -o addr show {vlan_iface}")
            if expected_ip and expected_ip.split("/")[0] not in addr_output:
                report["vlan_ip_wrong"] = True
                report["reasons"].append(f"VLAN sub-interface {vlan_iface} IP misconfigured")

    passwd_output = ssh.send_command("cat /etc/passwd")
    for line in passwd_output.splitlines():
        fields = line.split(":")
        if len(fields) < 3:
            continue
        uname, uid_str = fields[0].strip(), fields[2].strip()
        if not uname or not uid_str.isdigit():
            continue
        uid = int(uid_str)
        if (uid == 0 and uname != "root") or (uid >= 1000 and uname not in authorized_users):
            report["unauthorized_accounts"].append(uname)

    if report["unauthorized_accounts"]:
        report["reasons"].append(
            "Unauthorized local account(s) detected: " + ", ".join(report["unauthorized_accounts"])
        )

    return report


def remediate_alpine_drift(
    ssh: ConnectHandler, node_config: Dict[str, Any], intent_data: Dict[str, Any], report: Dict[str, Any]
) -> Tuple[bool, str]:
    node_name = node_config["name"]
    actions = []

    try:
        if report["dns_mismatch"]:
            expected_dns = intent_data["global_settings"]["linux_services"]["expected_dns"]
            ssh.send_command(f"printf 'nameserver {expected_dns}\\n' > /etc/resolv.conf")
            actions.append(f"DNS restored to {expected_dns}")

        if report["vlan_missing"] or report["vlan_ip_wrong"]:
            vlan_id = node_config["vlan_id"]
            vlan_ip = node_config["vlan_ip"]
            vlan_gw = node_config["vlan_gw"]
            vlan_iface = f"eth1.{vlan_id}"
            ssh.send_command("ip link set eth1 up")
            ssh.send_command(
                f"ip link add link eth1 name {vlan_iface} type vlan id {vlan_id} 2>/dev/null || true"
            )
            ssh.send_command(f"ip link set {vlan_iface} up")
            ssh.send_command(
                f"ip addr flush dev {vlan_iface} 2>/dev/null || true; ip addr add {vlan_ip} dev {vlan_iface}"
            )
            ssh.send_command(f"ip route replace default via {vlan_gw} dev {vlan_iface}")
            actions.append(f"VLAN {vlan_iface} reconstructed")

        for account in report["unauthorized_accounts"]:
            if account != "root":
                ssh.send_command(f"deluser {account} 2>/dev/null || true")
                actions.append(f"Removed unauthorized account '{account}'")

        return True, "; ".join(actions) if actions else "Nothing actionable"
    except Exception as exc:
        logger.error("[REMEDIATION] %s failed: %s", node_name, exc)
        return False, str(exc)


def verify_alpine_compliance(
    ssh: ConnectHandler, node_config: Dict[str, Any], intent_data: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    report = detect_alpine_drift(ssh, node_config, intent_data)
    return not report["reasons"], report["reasons"]


# ============================================================
# Event handling
# ============================================================

def send_incident(host: str, event_type: str, summary: str, details: str = "") -> None:
    payload = (
        f"<b>IBN {event_type}</b><br>"
        f"{summary}"
        + (f"<br>{details}" if details else "")
    )
    send_zabbix_trap(host, "ibn.incident_report", payload)


def send_status_metrics(
    host: str,
    state: Dict[str, Any],
    compliant: bool,
    drift_count: int,
    reachable: bool = True,
    telemetry_ok: bool = True,
    remediation_status: int = REMEDIATION_STATUS_NONE,
    last_event: str = "",
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
        },
    )


def handle_compliance_result(
    host: str,
    state: Dict[str, Any],
    reasons: List[str],
    remediation_fn,
    verify_fn,
) -> None:
    """Common detect -> remediate -> verify state machine."""

    if not reasons:
        was_problem = state["state"] != DEVICE_STATE_COMPLIANT
        state["state"] = DEVICE_STATE_COMPLIANT
        state["remediation_attempts"] = 0
        state["finding_signature"] = None
        state["last_incident_signature"] = None

        send_status_metrics(
            host,
            state,
            True,
            0,
            reachable=True,
            telemetry_ok=True,
            remediation_status=(
                REMEDIATION_STATUS_RECOVERED
                if was_problem
                else REMEDIATION_STATUS_NONE
            ),
            last_event=(
                "Device recovered and is compliant"
                if was_problem
                else "Device compliant"
            ),
        )

        if was_problem:
            send_incident(
                host,
                "RECOVERY",
                "Device is compliant again; remediation cycle closed.",
            )
        return

    signature = finding_signature(reasons)
    new_finding = signature != state.get("finding_signature")

    # Do not reset remediation_attempts when a persistent finding changes
    # wording or gains/loses a secondary reason. The counter is reset only
    # after the device has actually returned to compliance.
    if new_finding:
        state["finding_signature"] = signature

    if state["state"] == DEVICE_STATE_MANUAL:
        send_status_metrics(
            host,
            state,
            False,
            len(reasons),
            reachable=True,
            telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_MANUAL_REVIEW,
            last_event="Manual review required",
        )
        return

    state["state"] = DEVICE_STATE_DRIFT
    state["remediation_attempts"] += 1
    attempt = state["remediation_attempts"]

    if attempt > MAX_REMEDIATION_ATTEMPTS:
        state["state"] = DEVICE_STATE_MANUAL
        send_status_metrics(
            host,
            state,
            False,
            len(reasons),
            reachable=True,
            telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_MANUAL_REVIEW,
            last_event="Autonomous remediation suspended",
        )

        if state.get("last_incident_signature") != "MANUAL_REVIEW":
            send_incident(
                host,
                "MANUAL REVIEW",
                "Autonomous remediation suspended.",
                f"Persistent drift: {signature}. Attempts: {MAX_REMEDIATION_ATTEMPTS}.",
            )
            state["last_incident_signature"] = "MANUAL_REVIEW"
        return

    if new_finding:
        send_incident(
            host,
            "DRIFT DETECTED",
            "The observed state differs from intent.",
            f"{signature}. Starting remediation attempt {attempt}/{MAX_REMEDIATION_ATTEMPTS}.",
        )

    state["state"] = DEVICE_STATE_REMEDIATING
    send_status_metrics(
        host,
        state,
        False,
        len(reasons),
        reachable=True,
        telemetry_ok=True,
        remediation_status=REMEDIATION_STATUS_IN_PROGRESS,
        last_event=f"Remediation attempt {attempt}",
    )

    applied, action_text = remediation_fn()

    if not applied:
        send_status_metrics(
            host,
            state,
            False,
            len(reasons),
            reachable=True,
            telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_FAILED,
            last_event="Remediation failed",
        )
        send_incident(host, "REMEDIATION FAILED", action_text, signature)
        return

    time.sleep(REMEDIATION_VERIFY_DELAY)
    verified, verification_reasons, verify_error = verify_fn()

    if verified:
        state["state"] = DEVICE_STATE_COMPLIANT
        state["remediation_attempts"] = 0
        state["finding_signature"] = None
        state["last_incident_signature"] = None

        send_status_metrics(
            host,
            state,
            True,
            0,
            reachable=True,
            telemetry_ok=True,
            remediation_status=REMEDIATION_STATUS_RECOVERED,
            last_event="Remediation verified successfully",
        )
        send_incident(
            host,
            "REMEDIATION RECOVERED",
            "Desired state verified after remediation.",
            action_text,
        )
        return

    state["state"] = DEVICE_STATE_DRIFT
    failed_count = len(verification_reasons) or len(reasons)

    send_status_metrics(
        host,
        state,
        False,
        failed_count,
        reachable=True,
        telemetry_ok=True,
        remediation_status=REMEDIATION_STATUS_FAILED,
        last_event="Remediation did not converge",
    )

    if verify_error:
        send_incident(
            host,
            "VERIFICATION FAILED",
            "Could not verify the remediation result.",
            verify_error,
        )
    else:
        new_signature = finding_signature(verification_reasons)
        if new_signature != signature:
            state["finding_signature"] = new_signature
        send_incident(
            host,
            "REMEDIATION DID NOT CONVERGE",
            "The device still differs from intent after the write.",
            new_signature or signature,
        )


def monitor_switch_telemetry(device: Dict[str, Any], intent_data: Dict[str, Any], day0_data: Dict[str, Any]) -> None:
    node_config = build_node_config(device, day0_data)
    node_ip = node_config["management_ip"]
    node_name = node_config["name"]
    state = get_device_state(node_name)

    if not node_config["router_id"]:
        logger.warning("[CONFIG] %s has no day-0 router-id", node_name)

    try:
        with gNMIclient(
            target=(node_ip, GNMI_PORT),
            username=SRL_USERNAME,
            password=SRL_PASSWORD,
            skip_verify=True,
        ) as gc:
            drift_reasons = detect_switch_drift(gc, node_config, intent_data)
            metrics = collect_switch_metrics(gc, node_ip)

        if metrics:
            send_zabbix_metrics(node_name, metrics)

        handle_compliance_result(
            node_name,
            state,
            drift_reasons,
            remediation_fn=lambda: remediate_switch_drift(node_config, intent_data, drift_reasons),
            verify_fn=lambda: verify_switch_compliance(node_config, intent_data),
        )

    except Exception as exc:
        state["state"] = DEVICE_STATE_TELEMETRY_ERROR
        logger.error("[gNMI] Telemetry/reconciliation failed for %s: %s", node_name, exc)
        send_status_metrics(
            node_name,
            state,
            False,
            0,
            reachable=False,
            telemetry_ok=False,
            remediation_status=REMEDIATION_STATUS_NONE,
            last_event="gNMI telemetry failure",
        )
        if state.get("last_incident_signature") != "TELEMETRY_ERROR":
            send_incident(node_name, "TELEMETRY ERROR", "gNMI reconciliation failed.", str(exc))
            state["last_incident_signature"] = "TELEMETRY_ERROR"


def monitor_alpine_node(device: Dict[str, Any], intent_data: Dict[str, Any], linux_init_data: Dict[str, Any]) -> None:
    node_config = build_alpine_node_config(device, linux_init_data)
    node_ip = node_config["management_ip"]
    node_name = node_config["name"]
    state = get_device_state(node_name)

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

            handle_compliance_result(
                node_name,
                state,
                report["reasons"],
                remediation_fn=lambda: remediate_alpine_drift(ssh, node_config, intent_data, report),
                verify_fn=lambda: verify_alpine_compliance(ssh, node_config, intent_data),
            )

    except Exception as exc:
        state["state"] = DEVICE_STATE_UNREACHABLE
        logger.error("[SSH] Monitoring failed for %s: %s", node_name, exc)
        send_status_metrics(
            node_name,
            state,
            False,
            0,
            reachable=False,
            telemetry_ok=False,
            remediation_status=REMEDIATION_STATUS_NONE,
            last_event="SSH monitoring failure",
        )
        if state.get("last_incident_signature") != "UNREACHABLE":
            send_incident(node_name, "ENDPOINT UNREACHABLE", "SSH monitoring failed.", str(exc))
            state["last_incident_signature"] = "UNREACHABLE"


# ============================================================
# Main loop
# ============================================================

def run_engine() -> None:
    logger.info(
        "Starting Autonomous Tier-1 IBN Drift Engine | poll=%ss | max_attempts=%s",
        POLL_INTERVAL,
        MAX_REMEDIATION_ATTEMPTS,
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
