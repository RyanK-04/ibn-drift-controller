"""Focused safety/regression tests for autonomous_engine.py.

Run from this directory with:
    python3 -m pytest -v test_autonomous_engine_hardened.py

The tests stub optional network-device libraries so they do not connect to devices.
"""
import importlib.util
import os
import sys
import types
import unittest
from unittest.mock import patch

BASE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(BASE, "autonomous_engine.py")

# Device libraries are not required for these pure-function safety tests.
netmiko = types.ModuleType("netmiko")
netmiko.ConnectHandler = object
sys.modules.setdefault("netmiko", netmiko)
pygnmi = types.ModuleType("pygnmi")
pygnmi_client = types.ModuleType("pygnmi.client")
pygnmi_client.gNMIclient = object
sys.modules.setdefault("pygnmi", pygnmi)
sys.modules.setdefault("pygnmi.client", pygnmi_client)

os.environ.setdefault("SRL_USERNAME", "unit-test-user")
os.environ.setdefault("SRL_PASSWORD", "unit-test-password")
os.environ.setdefault("ALPINE_PASSWORD", "unit-test-password")
os.environ.setdefault("ALLOW_INSECURE_JSON_RPC", "false")

spec = importlib.util.spec_from_file_location("autonomous_engine", MODULE_PATH)
engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = engine
assert spec.loader is not None
spec.loader.exec_module(engine)


class ValidationTests(unittest.TestCase):
    def test_validate_ip_normalizes_address(self):
        self.assertEqual(engine.validate_ip("192.0.2.10", "test"), "192.0.2.10")

    def test_validate_ip_rejects_invalid_address(self):
        with self.assertRaises(ValueError):
            engine.validate_ip("not-an-ip", "test")

    def test_validate_vlan_accepts_boundary_values(self):
        self.assertEqual(engine.validate_vlan_id(1), 1)
        self.assertEqual(engine.validate_vlan_id(4094), 4094)

    def test_validate_vlan_rejects_out_of_range(self):
        for value in (0, 4095, "abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                engine.validate_vlan_id(value)

    def test_zabbix_rejects_empty_or_injected_host_before_network_io(self):
        with patch.object(engine.socket, "socket") as sock:
            self.assertFalse(engine.send_zabbix_metrics("", {"test.key": 1}))
            self.assertFalse(engine.send_zabbix_metrics("host\nforged", {"test.key": 1}))
            sock.assert_not_called()

    def test_zabbix_rejects_invalid_item_key_before_network_io(self):
        with patch.object(engine.socket, "socket") as sock:
            self.assertFalse(engine.send_zabbix_metrics("host", {"bad\nkey": 1}))
            sock.assert_not_called()

    def test_null_metrics_are_skipped(self):
        # All-null input is a successful no-op; no socket is opened.
        with patch.object(engine.socket, "socket") as sock:
            self.assertTrue(engine.send_zabbix_metrics("host", {"test.key": None}))
            sock.assert_not_called()

    def test_http_remediation_requires_explicit_opt_in(self):
        engine.JSON_RPC_SCHEME = "http"
        engine.ALLOW_INSECURE_JSON_RPC = False
        with patch.object(engine.requests, "post") as post:
            with self.assertRaisesRegex(RuntimeError, "HTTP JSON-RPC disabled"):
                engine.json_rpc_set("192.0.2.10", [{"operation": "test"}])
            post.assert_not_called()


class SwitchMetricTests(unittest.TestCase):
    def test_switch_cpu_and_memory_metrics_are_percentages(self):
        def fake_get_value(_client, path):
            if "/cpu[index=all]/total/instant" in path:
                return 37.456
            if "/memory/utilization" in path:
                return 61.2
            if "/chassis/last-booted" in path:
                return None
            return None

        with (
            patch.object(engine, "gnmi_get_value", side_effect=fake_get_value),
            patch.object(engine, "gnmi_get_values", return_value=["52", 84.3, None]),
            patch.object(engine, "measure_latency_ms", return_value=2.5),
        ):
            metrics = engine.collect_switch_metrics(object(), "192.0.2.20")

        self.assertEqual(metrics["ibn.metrics.cpu_utilization_percent"], 37.46)
        self.assertEqual(metrics["ibn.metrics.memory_utilization_percent"], 61.2)
        self.assertEqual(metrics["ibn.metrics.latency_ms"], 2.5)

        # SR Linux disk utilization is intentionally not collected.
        self.assertNotIn("ibn.metrics.disk_utilization_percent", metrics)

    def test_percent_validation_rejects_invalid_values(self):
        for value in (None, True, "unknown", -1, 100.01, float("nan"), float("inf")):
            with self.subTest(value=value):
                self.assertIsNone(engine._coerce_percent(value))
        self.assertEqual(engine._coerce_percent("45.678"), 45.68)

    def test_gnmi_get_values_returns_all_wildcard_matches(self):
        client = type("FakeClient", (), {
            "get": lambda self, **kwargs: {
                "notification": [
                    {"update": [{"val": 20}, {"val": 45}, {"val": None}]},
                    {"update": [{"val": 70}]},
                ]
            }
        })()
        self.assertEqual(
            engine.gnmi_get_values(client, "/some/wildcard/path"), [20, 45, 70]
        )


if __name__ == "__main__":
    unittest.main()
