#!/usr/bin/env python3
"""Tests for protocol adapters."""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))

from edgeops_agent.adapters import ADAPTER_REGISTRY
from edgeops_agent.adapters.base import AdapterConfig, SignalConfig, RemoteCommand
from edgeops_agent.adapters.modbus_rtu import ModbusRTUAdapter
from edgeops_agent.adapters.can import CANAdapter
from edgeops_agent.adapters.dio import DIOAdapter
from edgeops_agent.adapters.current_output import CurrentOutputAdapter
from edgeops_agent.adapters.ethernet import EthernetAdapter


class TestAdapterRegistry(unittest.TestCase):
    def test_registry_has_all_types(self):
        self.assertIn("modbus-rtu", ADAPTER_REGISTRY)
        self.assertIn("can", ADAPTER_REGISTRY)
        self.assertIn("digital-io", ADAPTER_REGISTRY)
        self.assertIn("analog-output", ADAPTER_REGISTRY)
        self.assertIn("modbus-tcp", ADAPTER_REGISTRY)
        self.assertEqual(len(ADAPTER_REGISTRY), 5)


class TestModbusRTUAdapter(unittest.TestCase):
    def setUp(self):
        self.transport = MagicMock()
        self.adapter = ModbusRTUAdapter(self.transport)

    def test_discover_calls_scan_bus(self):
        self.transport.send_command.return_value = {"status": "ok", "slaves": [1, 3]}
        devices = self.adapter.discover()
        self.transport.send_command.assert_any_call(
            "modbus.scan_bus", {"range": [1, 247]}, timeout=60
        )
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].address, "1")
        self.assertEqual(devices[0].protocols, ["modbus-rtu"])

    def test_poll_reads_holding_registers(self):
        self.transport.send_command.return_value = {"status": "ok", "values": [1234]}
        signals = [SignalConfig(signal_id="temp", address="1:40001")]
        readings = self.adapter.poll(signals)
        self.assertEqual(len(readings), 1)
        self.assertEqual(readings[0].value, 1234)
        self.assertEqual(readings[0].quality, "good")

    def test_poll_bad_quality_on_error(self):
        self.transport.send_command.return_value = {"status": "error", "error": "timeout"}
        readings = self.adapter.poll([SignalConfig(signal_id="t", address="1:40001")])
        self.assertEqual(readings[0].quality, "bad")

    def test_poll_bad_quality_on_malformed_address(self):
        readings = self.adapter.poll([SignalConfig(signal_id="t", address="bad")])
        self.assertEqual(readings[0].quality, "bad")

    def test_execute_write_register(self):
        self.transport.send_command.return_value = {"status": "ok"}
        cmd = RemoteCommand(command_id="1", type="write_register", target="1",
                           params={"register": 40001, "value": 100})
        result = self.adapter.execute(cmd)
        self.assertTrue(result.success)

    def test_execute_unknown_type(self):
        result = self.adapter.execute(
            RemoteCommand(command_id="1", type="unknown", target="1")
        )
        self.assertFalse(result.success)


class TestCANAdapter(unittest.TestCase):
    def setUp(self):
        self.transport = MagicMock()
        self.adapter = CANAdapter(self.transport)

    def test_discover_calls_scan_ids(self):
        self.transport.send_command.return_value = {"status": "ok", "ids": ["0x7E0", "0x7E8"]}
        devices = self.adapter.discover()
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].address, "0x7E0")


class TestDIOAdapter(unittest.TestCase):
    def setUp(self):
        self.transport = MagicMock()
        self.adapter = DIOAdapter(self.transport)

    def test_poll_reads_channels(self):
        self.transport.send_command.return_value = {
            "status": "ok",
            "channels": [
                {"ch": 0, "mode": "input_t3", "value": 1},
                {"ch": 1, "mode": "input_t3", "value": 0},
            ]
        }
        signals = [
            SignalConfig(signal_id="valve", address="ch0"),
            SignalConfig(signal_id="pump", address="ch1"),
        ]
        readings = self.adapter.poll(signals)
        self.assertEqual(len(readings), 2)
        self.assertTrue(readings[0].value)
        self.assertFalse(readings[1].value)

    def test_parse_channel(self):
        self.assertEqual(DIOAdapter._parse_channel("ch0"), 0)
        self.assertEqual(DIOAdapter._parse_channel("ch3"), 3)
        self.assertIsNone(DIOAdapter._parse_channel("bad"))
        self.assertIsNone(DIOAdapter._parse_channel("chX"))


class TestCurrentOutputAdapter(unittest.TestCase):
    def setUp(self):
        self.transport = MagicMock()
        self.adapter = CurrentOutputAdapter(self.transport)

    def test_poll_returns_current_setpoint(self):
        self.transport.send_command.return_value = {"status": "ok", "ma": 12.5}
        signals = [SignalConfig(signal_id="loop_out", address="iout")]
        readings = self.adapter.poll(signals)
        self.assertEqual(readings[0].value, 12.5)

    def test_shutdown_sends_off(self):
        self.adapter.shutdown()
        self.transport.send_command.assert_called_with("iout.off", {})


class TestEthernetAdapter(unittest.TestCase):
    def setUp(self):
        self.transport = MagicMock()
        self.adapter = EthernetAdapter(self.transport)

    def test_initialize_checks_link(self):
        self.transport.send_command.return_value = {"status": "ok", "link": True}
        config = AdapterConfig(type="modbus-tcp", connection_params={"subnet": "10.0.0"})
        self.adapter.initialize(config)
        self.assertEqual(self.adapter._status.state, "running")

    def test_initialize_degraded_no_link(self):
        self.transport.send_command.return_value = {"status": "ok", "link": False}
        config = AdapterConfig(type="modbus-tcp", connection_params={"subnet": "10.0.0"})
        self.adapter.initialize(config)
        self.assertEqual(self.adapter._status.state, "degraded")


if __name__ == "__main__":
    unittest.main()
