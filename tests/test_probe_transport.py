#!/usr/bin/env python3
"""Tests for ProbeTransport — the USB CDC JSON protocol layer."""
import json
import os
import sys
import threading
import unittest
from unittest.mock import patch, mock_open, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))

from edgeops_agent.probe_transport import ProbeTransport


class TestProbeTransport(unittest.TestCase):

    def _make_transport(self, dev="/tmp/fake_tty", timeout=5):
        """Create a ProbeTransport without running detection."""
        transport = ProbeTransport.__new__(ProbeTransport)
        transport._lock = threading.Lock()
        transport._dev_path = dev
        transport._timeout = timeout
        transport._fw_version = None
        transport._hardware = {}
        return transport

    def test_send_command_formats_json_correctly(self):
        transport = self._make_transport()
        read_response = json.dumps({"status": "ok", "id": "123"}) + "\n"

        m = mock_open(read_data=read_response)
        with patch("builtins.open", m):
            result = transport.send_command("probe.info", {}, cmd_id="123")

        self.assertEqual(result["status"], "ok")
        write_handle = m()
        written_data = "".join(
            call.args[0] for call in write_handle.write.call_args_list
        )
        parsed = json.loads(written_data.strip())
        self.assertEqual(parsed["cmd"], "probe.info")
        self.assertEqual(parsed["id"], "123")

    def test_send_command_returns_error_on_exception(self):
        transport = self._make_transport()

        with patch("builtins.open", side_effect=OSError("device gone")):
            result = transport.send_command("probe.info", {})

        self.assertEqual(result["status"], "error")
        self.assertIn("device gone", result["error"])

    def test_send_command_returns_error_when_no_device(self):
        transport = self._make_transport(dev=None)
        result = transport.send_command("probe.info", {})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "no_device")

    def test_thread_safety_lock_acquired(self):
        transport = self._make_transport()
        lock_events = []

        original_lock = transport._lock

        class TrackedLock:
            def __enter__(self):
                original_lock.acquire()
                lock_events.append("acquired")
                return self

            def __exit__(self, *args):
                lock_events.append("released")
                original_lock.release()

        transport._lock = TrackedLock()

        read_response = json.dumps({"status": "ok"}) + "\n"
        with patch("builtins.open", mock_open(read_data=read_response)):
            transport.send_command("test.cmd", {})

        self.assertEqual(lock_events, ["acquired", "released"])

    def test_detect_returns_none_when_no_devices(self):
        with patch("glob.glob", return_value=[]):
            transport = ProbeTransport()
            self.assertFalse(transport.is_connected())
            self.assertIsNone(transport.firmware_version)

    def test_is_connected_true_when_device_set(self):
        transport = self._make_transport(dev="/dev/ttyACM0")
        self.assertTrue(transport.is_connected())

    def test_hardware_status_returns_copy(self):
        transport = self._make_transport()
        transport._hardware = {"modbus": True, "can": False}
        status = transport.hardware_status
        self.assertEqual(status, {"modbus": True, "can": False})
        # Verify it's a copy
        status["modbus"] = False
        self.assertTrue(transport._hardware["modbus"])

    def test_default_params_and_id(self):
        transport = self._make_transport()
        read_response = json.dumps({"status": "ok"}) + "\n"

        m = mock_open(read_data=read_response)
        with patch("builtins.open", m):
            result = transport.send_command("test.cmd")

        self.assertEqual(result["status"], "ok")
        write_handle = m()
        written_data = "".join(
            call.args[0] for call in write_handle.write.call_args_list
        )
        parsed = json.loads(written_data.strip())
        self.assertEqual(parsed["cmd"], "test.cmd")
        self.assertEqual(parsed["params"], {})
        self.assertIn("id", parsed)  # auto-generated


if __name__ == "__main__":
    unittest.main()
