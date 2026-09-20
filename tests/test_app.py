import io
import json
import logging
import os
import time
import unittest
from unittest.mock import MagicMock, patch

# Configure environment variables before importing app
os.environ["TESTING"] = "true"
os.environ["LINODE_TOKEN"] = "dummy_token"
os.environ["ALLOWLIST_INTERVAL_MINUTES"] = "10"
os.environ["SERVER_PORT"] = "8080"
os.environ["FIREWALL_ID"] = "12345"
os.environ["SLOW_OP_THRESHOLD_MS"] = "100.0"

import app


class TestTempAllowlistApp(unittest.TestCase):
    def setUp(self):
        # Capture root logger output in an in-memory stream
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(
            app.CustomJsonFormatter(
                fmt="%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )
        self.root_logger = logging.getLogger()
        self.root_logger.handlers = [self.handler]
        self.client = app.app.test_client()

    def get_json_logs(self):
        output = self.log_stream.getvalue().strip()
        if not output:
            return []
        logs = []
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return logs

    def test_json_log_structure_without_caller(self):
        self.root_logger.setLevel(logging.INFO)
        app.logger.info("Test message", extra={"custom_metric": 42})

        logs = self.get_json_logs()
        self.assertEqual(len(logs), 1)
        entry = logs[0]

        self.assertEqual(entry["message"], "Test message")
        self.assertEqual(entry["logLevel"], "INFO")
        self.assertIn("timestamp", entry)
        self.assertEqual(entry["custom_metric"], 42)

        # Ensure caller* fields are stripped
        self.assertNotIn("callerLine", entry)
        self.assertNotIn("callerFunction", entry)
        self.assertNotIn("callerFile", entry)

    def test_debug_log_suppression_at_info_level(self):
        self.root_logger.setLevel(logging.INFO)
        mock_firewall = MagicMock()
        mock_firewall.rules.inbound = []
        mock_firewall.rules.outbound = []

        app.delete_temporary_firewall_rule(mock_firewall)

        logs = self.get_json_logs()
        debug_logs = [
            entry
            for entry in logs
            if "No expired firewall rules to clean up" in entry.get("message", "")
        ]
        self.assertEqual(len(debug_logs), 0)

    def test_debug_log_emitted_at_debug_level(self):
        self.root_logger.setLevel(logging.DEBUG)
        mock_firewall = MagicMock()
        mock_firewall.rules.inbound = []
        mock_firewall.rules.outbound = []

        app.delete_temporary_firewall_rule(mock_firewall)

        logs = self.get_json_logs()
        debug_logs = [
            entry
            for entry in logs
            if "No expired firewall rules to clean up" in entry.get("message", "")
        ]
        self.assertEqual(len(debug_logs), 1)
        self.assertEqual(debug_logs[0]["logLevel"], "DEBUG")

    def test_access_log_unregistered_routes_at_info_level(self):
        self.root_logger.setLevel(logging.INFO)
        response = self.client.get("/nonexistent-route")
        self.assertEqual(response.status_code, 404)

        logs = self.get_json_logs()
        access_logs = [
            entry for entry in logs if entry.get("path") == "/nonexistent-route"
        ]
        self.assertEqual(len(access_logs), 0)

    def test_access_log_unregistered_routes_at_debug_level(self):
        self.root_logger.setLevel(logging.DEBUG)
        response = self.client.get("/nonexistent-route")
        self.assertEqual(response.status_code, 404)

        logs = self.get_json_logs()
        access_logs = [
            entry for entry in logs if entry.get("path") == "/nonexistent-route"
        ]
        self.assertEqual(len(access_logs), 1)
        self.assertEqual(access_logs[0]["logLevel"], "DEBUG")
        self.assertEqual(access_logs[0]["status_code"], 404)

    @patch("app.Firewall")
    @patch("threading.Timer")
    def test_access_log_and_operation_timings_for_getaccess(
        self, mock_timer, mock_firewall_cls
    ):
        self.root_logger.setLevel(logging.INFO)

        mock_instance = MagicMock()
        mock_instance.rules.inbound = []
        mock_instance.rules.outbound = []
        mock_instance.rules.inbound_policy = "DROP"
        mock_instance.rules.outbound_policy = "ACCEPT"
        mock_firewall_cls.return_value = mock_instance

        response = self.client.get("/getaccess")
        self.assertEqual(response.status_code, 200)

        logs = self.get_json_logs()
        access_logs = [entry for entry in logs if entry.get("path") == "/getaccess"]
        self.assertEqual(len(access_logs), 1)
        entry = access_logs[0]

        self.assertEqual(entry["logLevel"], "INFO")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["status_code"], 200)
        self.assertIn("duration_ms", entry)
        self.assertGreaterEqual(entry["duration_ms"], 0)

        # Check operation timings breakdown
        self.assertIn("operations", entry)
        ops = entry["operations"]
        self.assertIn("acquire_lock_ms", ops)
        self.assertIn("fetch_firewall_rules_ms", ops)
        self.assertIn("process_rules_ms", ops)
        self.assertIn("update_firewall_rules_ms", ops)
        self.assertIn("schedule_timer_ms", ops)

    @patch("app.Firewall")
    @patch("threading.Timer")
    def test_ip_rule_rotation_deduplication(
        self, mock_timer, mock_firewall_cls
    ):
        """Verify that existing temporary rules for the client IP are rotated."""
        self.root_logger.setLevel(logging.INFO)
        recent_ts = int(time.time()) - 30

        # Create an existing active rule for 127.0.0.1
        existing_rule = MagicMock()
        existing_rule.label = f"tmpAllowList_{recent_ts}"
        existing_rule.action = "ACCEPT"
        existing_rule.protocol = "TCP"
        existing_rule.ports = "80, 443"
        existing_rule.addresses.ipv4 = ["127.0.0.1/32"]
        existing_rule.addresses.ipv6 = []
        existing_rule.description = "Old rule"

        # Create an existing rule for another IP
        other_rule = MagicMock()
        other_rule.label = f"tmpAllowList_{recent_ts + 10}"
        other_rule.action = "ACCEPT"
        other_rule.protocol = "TCP"
        other_rule.ports = "80, 443"
        other_rule.addresses.ipv4 = ["10.0.0.1/32"]
        other_rule.addresses.ipv6 = []
        other_rule.description = "Other IP rule"

        mock_instance = MagicMock()
        mock_instance.rules.inbound = [existing_rule, other_rule]
        mock_instance.rules.outbound = []
        mock_instance.rules.inbound_policy = "DROP"
        mock_instance.rules.outbound_policy = "ACCEPT"
        mock_firewall_cls.return_value = mock_instance

        response = self.client.get("/getaccess")
        self.assertEqual(response.status_code, 200)

        # Check update_rules payload
        mock_instance.update_rules.assert_called_once()
        call_kwargs = mock_instance.update_rules.call_args.kwargs
        updated_inbound = call_kwargs["rules"]["inbound"]

        # Ensure other rule is preserved and exactly ONE rule exists for 127.0.0.1/32
        rule_ips = [r["addresses"]["ipv4"][0] for r in updated_inbound]
        self.assertEqual(rule_ips.count("127.0.0.1/32"), 1)
        self.assertEqual(rule_ips.count("10.0.0.1/32"), 1)
        self.assertEqual(len(updated_inbound), 2)

        # Ensure the old label is rotated out
        rule_labels = [r.get("label") for r in updated_inbound]
        self.assertNotIn(f"tmpAllowList_{recent_ts}", rule_labels)
        self.assertIn(f"tmpAllowList_{recent_ts + 10}", rule_labels)

        # Verify rotation log was emitted
        logs = self.get_json_logs()
        rotation_logs = [
            entry
            for entry in logs
            if "Rotating existing temporary rule for 127.0.0.1"
            in entry.get("message", "")
        ]
        self.assertEqual(len(rotation_logs), 1)

    @patch("app.Firewall")
    @patch("threading.Timer")
    def test_expired_rules_cleaned_up_on_creation(
        self, mock_timer, mock_firewall_cls
    ):
        """Verify that expired temporary rules are pruned when a new rule is created."""
        self.root_logger.setLevel(logging.INFO)

        # Expired rule from timestamp 1000
        expired_rule = MagicMock()
        expired_rule.label = "tmpAllowList_1000"
        expired_rule.action = "ACCEPT"
        expired_rule.protocol = "TCP"
        expired_rule.ports = "80, 443"
        expired_rule.addresses.ipv4 = ["192.168.1.1/32"]
        expired_rule.addresses.ipv6 = []
        expired_rule.description = "Expired rule"

        mock_instance = MagicMock()
        mock_instance.rules.inbound = [expired_rule]
        mock_instance.rules.outbound = []
        mock_instance.rules.inbound_policy = "DROP"
        mock_instance.rules.outbound_policy = "ACCEPT"
        mock_firewall_cls.return_value = mock_instance

        response = self.client.get("/getaccess")
        self.assertEqual(response.status_code, 200)

        mock_instance.update_rules.assert_called_once()
        call_kwargs = mock_instance.update_rules.call_args.kwargs
        updated_inbound = call_kwargs["rules"]["inbound"]

        # Expired rule removed, only new rule present
        self.assertEqual(len(updated_inbound), 1)
        self.assertEqual(updated_inbound[0]["addresses"]["ipv4"], ["127.0.0.1/32"])

        logs = self.get_json_logs()
        cleanup_logs = [
            entry
            for entry in logs
            if "Cleaning up expired rule on creation: tmpAllowList_1000"
            in entry.get("message", "")
        ]
        self.assertEqual(len(cleanup_logs), 1)

    def test_slow_operation_warning(self):
        """Verify that operations exceeding threshold emit a structured warning."""
        self.root_logger.setLevel(logging.INFO)

        with app.measure_operation("simulated_slow_op"):
            time.sleep(0.12)  # Exceeds SLOW_OP_THRESHOLD_MS = 100.0 ms

        logs = self.get_json_logs()
        slow_logs = [
            entry
            for entry in logs
            if "Slow operation detected: simulated_slow_op"
            in entry.get("message", "")
        ]
        self.assertEqual(len(slow_logs), 1)
        self.assertEqual(slow_logs[0]["logLevel"], "WARNING")
        self.assertEqual(slow_logs[0]["operation"], "simulated_slow_op")
        self.assertGreater(slow_logs[0]["duration_ms"], 100.0)


if __name__ == "__main__":
    unittest.main()
