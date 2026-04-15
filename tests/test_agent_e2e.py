#!/usr/bin/env python3
"""End-to-end smoke test with mocked probe and cloud."""
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent", "edgeops_agent", "vendor"))

from edgeops_agent.agent_core import AgentCore
from edgeops_agent.config import AgentConfig
from edgeops_agent.buffer import SQLiteBuffer
from edgeops_agent.probe_transport import ProbeTransport
from edgeops_agent.adapters.base import SignalReading


class TestAgentE2E(unittest.TestCase):

    def _make_agent(self):
        """Create an agent with mocked probe and in-memory buffer."""
        agent = AgentCore.__new__(AgentCore)
        agent.config = AgentConfig(
            device_id="test-pager-001",
            api_base_url="https://test.edgeops.cloud",
            auth_type="api_key",
            api_key="test_key",
            poll_interval_ms=100,
            flush_interval_s=1,
            buffer_max_mb=1,
            buffer_db_path=":memory:",
            log_level="warning",
            adapters=[
                {
                    "type": "modbus-rtu",
                    "connection_params": {},
                    "signals": [
                        {"signal_id": "temp_1", "address": "1:40001", "data_type": "float32"},
                    ],
                },
                {
                    "type": "digital-io",
                    "connection_params": {},
                    "signals": [
                        {"signal_id": "valve", "address": "ch0", "data_type": "bool"},
                    ],
                },
            ],
        )
        agent.transport = MagicMock(spec=ProbeTransport)
        agent.transport.is_connected.return_value = True
        agent.transport.firmware_version = "1.1.0"

        # Mock probe responses
        def mock_send(cmd, params=None, **kwargs):
            if cmd == "modbus.read_holding":
                return {"status": "ok", "values": [2345]}
            if cmd == "dio.read":
                return {"status": "ok", "channels": [
                    {"ch": 0, "mode": "input_t3", "value": 1},
                    {"ch": 1, "mode": "input_t3", "value": 0},
                ]}
            if cmd == "dio.configure":
                return {"status": "ok"}
            return {"status": "ok"}

        agent.transport.send_command.side_effect = mock_send

        agent.buffer = SQLiteBuffer(":memory:", max_mb=1)
        agent.adapters = []
        agent.client = None
        agent._running = False
        agent._poll_thread = None
        agent._flush_thread = None

        return agent

    def test_adapters_initialize_from_config(self):
        agent = self._make_agent()
        agent._init_adapters()
        self.assertEqual(len(agent.adapters), 2)
        self.assertEqual(agent.adapters[0].name, "modbus-rtu")
        self.assertEqual(agent.adapters[1].name, "digital-io")

    def test_poll_produces_readings(self):
        agent = self._make_agent()
        agent._init_adapters()

        # Manually poll
        for adapter in agent.adapters:
            signals = adapter._config.signals
            readings = adapter.poll(signals)
            for r in readings:
                agent.buffer.append(r.to_dict())

        self.assertEqual(agent.buffer.pending_count(), 2)
        batch = agent.buffer.flush(limit=10)
        self.assertEqual(len(batch), 2)

        # Check Modbus reading
        modbus_reading = next(r for r in batch if r["signalId"] == "temp_1")
        self.assertEqual(modbus_reading["value"], 2345)
        self.assertEqual(modbus_reading["quality"], "good")

        # Check DIO reading
        dio_reading = next(r for r in batch if r["signalId"] == "valve")
        self.assertTrue(dio_reading["value"])

    def test_start_and_stop(self):
        agent = self._make_agent()

        with patch.object(agent, "_write_status"):
            with patch.object(agent, "_init_cloud_client"):
                agent.start()
                self.assertTrue(agent._running)
                self.assertEqual(len(agent.adapters), 2)

                # Let it run one poll cycle
                time.sleep(0.3)

                # Should have buffered some readings
                count = agent.buffer.pending_count()
                self.assertGreater(count, 0)

                agent.stop()
                self.assertFalse(agent._running)

    def test_adapter_status_tracking(self):
        agent = self._make_agent()
        agent._init_adapters()

        for adapter in agent.adapters:
            status = adapter.get_status()
            self.assertEqual(status.state, "running")

        agent.adapters[0].shutdown()
        self.assertEqual(agent.adapters[0].get_status().state, "idle")

    def test_signal_reading_to_dict(self):
        reading = SignalReading(
            signal_id="test_signal",
            value=42.5,
            quality="good",
        )
        d = reading.to_dict()
        self.assertEqual(d["signalId"], "test_signal")
        self.assertEqual(d["value"], 42.5)
        self.assertEqual(d["quality"], "good")
        self.assertIn("timestamp", d)

    def test_no_crash_with_empty_adapter_list(self):
        agent = self._make_agent()
        agent.config.adapters = []
        agent._init_adapters()
        self.assertEqual(len(agent.adapters), 0)

    def test_unknown_adapter_type_skipped(self):
        agent = self._make_agent()
        agent.config.adapters = [{"type": "nonexistent", "signals": []}]
        agent._init_adapters()
        self.assertEqual(len(agent.adapters), 0)


if __name__ == "__main__":
    unittest.main()
