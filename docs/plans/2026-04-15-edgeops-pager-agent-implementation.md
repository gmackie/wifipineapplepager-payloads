# EdgeOps Pager Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Python EdgeOps gateway agent that runs on the Wi-Fi Pineapple Pager, uses the ICS probe as its I/O backend, and streams industrial telemetry to Controls Foundry.

**Architecture:** Multiple protocol adapters share a thread-safe `ProbeTransport` (USB CDC JSON) layer. The agent core polls adapters on a schedule, buffers readings in SQLite, and flushes to Controls Foundry via the EdgeOps Python SDK. A DuckyScript UI bridge shows status on the pager screen. See `docs/plans/2026-04-15-edgeops-pager-agent-design.md` for the full design.

**Tech Stack:** Python 3 (OpenWrt), EdgeOps Python SDK (vendored), SQLite3 (stdlib), paho-mqtt (vendored), bash/DuckyScript (payload entry points).

---

## Phase 1: Scaffolding & Vendor Dependencies

### Task 1.1: Create directory structure

**Files:**
- Create: `library/user/ics/agent/payload.sh` (placeholder)
- Create: `library/user/ics/agent/edgeops_agent/__init__.py`
- Create: `library/user/ics/agent/edgeops_agent/adapters/__init__.py`
- Create: `library/user/ics/agent/enrollment/enroll.sh` (placeholder)

**Step 1: Create the directory tree**

```bash
mkdir -p library/user/ics/agent/edgeops_agent/adapters
mkdir -p library/user/ics/agent/edgeops_agent/vendor
mkdir -p library/user/ics/agent/enrollment
```

**Step 2: Create placeholder `__init__.py`**

```python
# library/user/ics/agent/edgeops_agent/__init__.py
"""EdgeOps Gateway Agent for the Wi-Fi Pineapple Pager."""
__version__ = "0.1.0"
```

```python
# library/user/ics/agent/edgeops_agent/adapters/__init__.py
"""Protocol adapters for the ICS probe."""
```

**Step 3: Create placeholder `payload.sh`**

```bash
#!/bin/bash
# Title: EdgeOps Agent
# Description: EdgeOps gateway agent — streams ICS probe data to Controls Foundry
# Author: ICS Toolkit
# Version: 0.1
# Category: remote_access
# Net Mode: NAT
set -euo pipefail
LOG blue "EdgeOps Agent — not yet implemented"
```

**Step 4: Create placeholder `enroll.sh`**

```bash
#!/bin/bash
# Title: EdgeOps Enrollment
# Description: One-time enrollment of this pager as an EdgeOps edge node
# Author: ICS Toolkit
# Version: 0.1
# Category: remote_access
# Net Mode: NAT
set -euo pipefail
LOG blue "EdgeOps Enrollment — not yet implemented"
```

**Step 5: Syntax check**

```bash
bash -n library/user/ics/agent/payload.sh
bash -n library/user/ics/agent/enrollment/enroll.sh
python3 -c "import ast; ast.parse(open('library/user/ics/agent/edgeops_agent/__init__.py').read())"
```

**Step 6: Commit**

```bash
git add library/user/ics/agent/
git commit -m "feat(agent): scaffold EdgeOps pager agent directory structure"
```

### Task 1.2: Vendor EdgeOps Python SDK

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/vendor/edgeops_sdk/` (copy from `/Volumes/dev/edgeOps/packages/sdk-python/edgeops_sdk/`)
- Create: `library/user/ics/agent/edgeops_agent/vendor/__init__.py`

**Step 1: Copy the SDK source**

```bash
cp -r /Volumes/dev/edgeOps/packages/sdk-python/edgeops_sdk/ \
  library/user/ics/agent/edgeops_agent/vendor/edgeops_sdk/
touch library/user/ics/agent/edgeops_agent/vendor/__init__.py
```

**Step 2: Verify it imports cleanly**

```bash
cd library/user/ics/agent
python3 -c "
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname('edgeops_agent'), 'edgeops_agent', 'vendor'))
from edgeops_sdk import EdgeOpsClient, EdgeOpsConfig
print('SDK imported successfully')
print('Classes:', EdgeOpsClient, EdgeOpsConfig)
"
cd /Volumes/dev/wifipineapplepager-payloads
```

If import fails due to missing `requests` or `paho-mqtt`, that's expected —
those are runtime deps, not import-time. The import test just verifies the
module structure is sound.

**Step 3: Commit**

```bash
git add library/user/ics/agent/edgeops_agent/vendor/
git commit -m "feat(agent): vendor EdgeOps Python SDK"
```

---

## Phase 2: ProbeTransport

### Task 2.1: Write the failing test for ProbeTransport

**Files:**
- Create: `tests/test_probe_transport.py`

**Step 1: Write the test**

```python
#!/usr/bin/env python3
"""Tests for ProbeTransport — the USB CDC JSON protocol layer."""
import json
import os
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch, mock_open

# Add the agent package to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))

from edgeops_agent.probe_transport import ProbeTransport


class TestProbeTransport(unittest.TestCase):

    def test_send_command_formats_json_correctly(self):
        """send_command should write a newline-terminated JSON to the device."""
        transport = ProbeTransport.__new__(ProbeTransport)
        transport._lock = threading.Lock()
        transport._dev_path = "/tmp/fake_tty"
        transport._timeout = 5

        written = []
        read_response = json.dumps({"status": "ok", "id": "123"}) + "\n"

        m = mock_open(read_data=read_response)
        with patch("builtins.open", m):
            result = transport.send_command("probe.info", {}, cmd_id="123")

        self.assertEqual(result["status"], "ok")
        # Verify the write call sent valid JSON
        write_handle = m()
        written_data = "".join(
            call.args[0] for call in write_handle.write.call_args_list
        )
        parsed = json.loads(written_data.strip())
        self.assertEqual(parsed["cmd"], "probe.info")
        self.assertEqual(parsed["id"], "123")

    def test_send_command_returns_error_on_timeout(self):
        """send_command should return an error dict if the device doesn't respond."""
        transport = ProbeTransport.__new__(ProbeTransport)
        transport._lock = threading.Lock()
        transport._dev_path = "/tmp/fake_tty"
        transport._timeout = 0.01  # very short timeout

        with patch("builtins.open", side_effect=OSError("timeout")):
            result = transport.send_command("probe.info", {})

        self.assertEqual(result["status"], "error")

    def test_thread_safety(self):
        """Multiple threads calling send_command should not interleave."""
        transport = ProbeTransport.__new__(ProbeTransport)
        transport._lock = threading.Lock()
        transport._dev_path = "/tmp/fake_tty"
        transport._timeout = 5

        call_order = []

        original_lock = transport._lock

        class TrackedLock:
            def __enter__(self_lock):
                original_lock.acquire()
                call_order.append("lock")
                return self_lock

            def __exit__(self_lock, *args):
                call_order.append("unlock")
                original_lock.release()

        transport._lock = TrackedLock()

        read_response = json.dumps({"status": "ok"}) + "\n"
        with patch("builtins.open", mock_open(read_data=read_response)):
            transport.send_command("test.cmd", {})

        self.assertIn("lock", call_order)
        self.assertIn("unlock", call_order)

    def test_detect_returns_false_when_no_device(self):
        """detect should return False when no /dev/ttyACM* exists."""
        with patch("glob.glob", return_value=[]):
            transport = ProbeTransport()
            self.assertFalse(transport.is_connected())


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run it to verify it fails**

```bash
python3 -m pytest tests/test_probe_transport.py -v 2>&1 || python3 tests/test_probe_transport.py -v 2>&1
```

Expected: `ModuleNotFoundError: No module named 'edgeops_agent.probe_transport'`

**Step 3: Commit**

```bash
git add tests/test_probe_transport.py
git commit -m "test(agent): failing tests for ProbeTransport"
```

### Task 2.2: Implement ProbeTransport

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/probe_transport.py`

**Step 1: Write the implementation**

```python
"""
ProbeTransport — Thread-safe USB CDC JSON protocol for the ICS probe.

This is the Python equivalent of library/user/ics/lib/esp32.sh. It owns
the serial connection to the ESP32, sends JSON commands, and returns JSON
responses. Multiple protocol adapters share one ProbeTransport instance
via its threading.Lock.
"""
import glob
import json
import logging
import threading
import time

logger = logging.getLogger(__name__)

# Default timeout for probe commands (seconds)
DEFAULT_TIMEOUT = 5.0


class ProbeTransport:
    """Thread-safe interface to the ICS probe over USB CDC serial."""

    def __init__(self, dev_path: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self._lock = threading.Lock()
        self._dev_path = dev_path
        self._timeout = timeout
        self._fw_version: str | None = None

        if self._dev_path is None:
            self._dev_path = self._detect()

    def is_connected(self) -> bool:
        return self._dev_path is not None

    @property
    def firmware_version(self) -> str | None:
        return self._fw_version

    def _detect(self) -> str | None:
        """Scan /dev/ttyACM* for a responding ICS probe."""
        for dev in sorted(glob.glob("/dev/ttyACM*")):
            try:
                resp = self._raw_send(dev, "probe.info", {}, timeout=2.0)
                if resp.get("status") == "ok":
                    self._fw_version = resp.get("fw_version")
                    logger.info("Probe detected: %s (firmware %s)", dev, self._fw_version)
                    return dev
            except Exception as e:
                logger.debug("Probe not at %s: %s", dev, e)
        logger.warning("No ICS probe detected")
        return None

    def send_command(
        self,
        cmd: str,
        params: dict | None = None,
        cmd_id: str | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Send a JSON command to the probe and return the parsed response.

        Thread-safe — acquires the internal lock before accessing the serial
        device, so multiple adapters can call this concurrently.
        """
        if not self._dev_path:
            return {"status": "error", "error": "no_device"}

        if params is None:
            params = {}
        if cmd_id is None:
            cmd_id = str(int(time.time() * 1000))
        if timeout is None:
            timeout = self._timeout

        with self._lock:
            try:
                return self._raw_send(self._dev_path, cmd, params, cmd_id, timeout)
            except Exception as e:
                logger.error("Probe command failed: %s — %s", cmd, e)
                return {"status": "error", "error": str(e)}

    def _raw_send(
        self,
        dev_path: str,
        cmd: str,
        params: dict,
        cmd_id: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict:
        """Low-level send/receive. Caller must hold the lock."""
        request = {"cmd": cmd, "params": params}
        if cmd_id:
            request["id"] = cmd_id

        request_line = json.dumps(request, separators=(",", ":")) + "\n"

        # Write command
        with open(dev_path, "w") as f:
            f.write(request_line)
            f.flush()

        # Read response (blocking with timeout)
        deadline = time.monotonic() + timeout
        with open(dev_path, "r") as f:
            while time.monotonic() < deadline:
                line = f.readline()
                if line.strip():
                    return json.loads(line.strip())
                time.sleep(0.01)

        return {"status": "error", "error": "timeout"}

    def reconnect(self) -> bool:
        """Attempt to re-detect the probe (e.g., after USB replug)."""
        self._dev_path = self._detect()
        return self.is_connected()
```

**Step 2: Run the tests**

```bash
python3 tests/test_probe_transport.py -v
```

Expected: tests pass (some may need adjustment based on exact mock behavior).

**Step 3: Fix any failures, then commit**

```bash
git add library/user/ics/agent/edgeops_agent/probe_transport.py
git commit -m "feat(agent): ProbeTransport — thread-safe USB CDC JSON protocol"
```

---

## Phase 3: Protocol Adapter Base & Adapters

### Task 3.1: Write the ProtocolAdapter ABC

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/base.py`

**Step 1: Write the abstract base class**

```python
"""
ProtocolAdapter ABC — mirrors the TypeScript ProtocolAdapter interface from
edgeOps/edge/gateway-agent/src/adapters/types.ts.

Each adapter wraps a set of ICS probe JSON commands and translates between
the probe's raw responses and the EdgeOps signal/device data model.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional


@dataclass
class AdapterConfig:
    type: str
    connection_params: dict = field(default_factory=dict)
    poll_interval_ms: int = 5000
    signals: list = field(default_factory=list)


@dataclass
class SignalConfig:
    signal_id: str
    address: str
    data_type: str = "float32"


@dataclass
class SignalReading:
    signal_id: str
    value: object  # number, string, bool, or list
    quality: str = "good"  # "good" | "uncertain" | "bad"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DiscoveredDevice:
    address: str
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    protocols: list = field(default_factory=list)
    capabilities: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class RemoteCommand:
    command_id: str
    type: str
    target: str
    params: dict = field(default_factory=dict)


@dataclass
class CommandResult:
    command_id: str
    success: bool
    error: str = ""
    data: object = None


@dataclass
class AdapterStatus:
    state: str = "idle"  # "idle" | "running" | "degraded" | "error"
    device_count: int = 0
    last_poll_at: Optional[datetime] = None
    error_message: str = ""


class ProtocolAdapter(ABC):
    """Abstract base for all ICS probe protocol adapters."""

    def __init__(self, name: str, adapter_type: str, transport):
        self.name = name
        self.type = adapter_type
        self._transport = transport
        self._status = AdapterStatus()

    @abstractmethod
    def initialize(self, config: AdapterConfig) -> None:
        ...

    @abstractmethod
    def shutdown(self) -> None:
        ...

    @abstractmethod
    def discover(self) -> list[DiscoveredDevice]:
        ...

    @abstractmethod
    def poll(self, signals: list[SignalConfig]) -> list[SignalReading]:
        ...

    @abstractmethod
    def execute(self, command: RemoteCommand) -> CommandResult:
        ...

    def get_status(self) -> AdapterStatus:
        return self._status
```

**Step 2: Verify**

```bash
python3 -c "
import sys, os
sys.path.insert(0, 'library/user/ics/agent')
from edgeops_agent.adapters.base import ProtocolAdapter, SignalReading, DiscoveredDevice
print('ABC imported:', ProtocolAdapter)
"
```

**Step 3: Commit**

```bash
git add library/user/ics/agent/edgeops_agent/adapters/base.py
git commit -m "feat(agent): ProtocolAdapter ABC matching EdgeOps adapter interface"
```

### Task 3.2: Implement ModbusRTUAdapter

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/modbus_rtu.py`
- Create: `tests/test_modbus_rtu_adapter.py`

**Step 1: Write the failing test**

```python
#!/usr/bin/env python3
import os, sys, unittest
from unittest.mock import MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))

from edgeops_agent.adapters.modbus_rtu import ModbusRTUAdapter
from edgeops_agent.adapters.base import AdapterConfig, SignalConfig


class TestModbusRTUAdapter(unittest.TestCase):

    def setUp(self):
        self.transport = MagicMock()
        self.adapter = ModbusRTUAdapter(self.transport)

    def test_discover_calls_scan_bus(self):
        self.transport.send_command.return_value = {
            "status": "ok",
            "slaves": [1, 3, 7]
        }
        devices = self.adapter.discover()
        self.transport.send_command.assert_called_with(
            "modbus.scan_bus", {"range": [1, 247]}, timeout=60
        )
        self.assertEqual(len(devices), 3)
        self.assertEqual(devices[0].address, "1")

    def test_poll_reads_holding_registers(self):
        self.transport.send_command.return_value = {
            "status": "ok",
            "values": [1234]
        }
        signals = [SignalConfig(signal_id="temp", address="1:40001", data_type="int16")]
        readings = self.adapter.poll(signals)
        self.assertEqual(len(readings), 1)
        self.assertEqual(readings[0].signal_id, "temp")
        self.assertEqual(readings[0].value, 1234)
        self.assertEqual(readings[0].quality, "good")

    def test_poll_returns_bad_quality_on_error(self):
        self.transport.send_command.return_value = {
            "status": "error", "error": "timeout"
        }
        signals = [SignalConfig(signal_id="temp", address="1:40001")]
        readings = self.adapter.poll(signals)
        self.assertEqual(readings[0].quality, "bad")


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run to verify it fails**

```bash
python3 tests/test_modbus_rtu_adapter.py -v
```

Expected: `ModuleNotFoundError`

**Step 3: Implement ModbusRTUAdapter**

```python
"""Modbus RTU adapter — wraps modbus.* probe commands."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, AdapterConfig, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult, AdapterStatus,
)


class ModbusRTUAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("modbus-rtu", "modbus-rtu", transport)

    def initialize(self, config: AdapterConfig) -> None:
        self._status.state = "running"

    def shutdown(self) -> None:
        self._status.state = "idle"

    def discover(self) -> list[DiscoveredDevice]:
        resp = self._transport.send_command(
            "modbus.scan_bus", {"range": [1, 247]}, timeout=60
        )
        if resp.get("status") != "ok":
            return []

        devices = []
        for slave_id in resp.get("slaves", []):
            # Try to get device ID
            id_resp = self._transport.send_command(
                "modbus.device_id", {"addr": slave_id}
            )
            device = DiscoveredDevice(
                address=str(slave_id),
                protocols=["modbus-rtu"],
                manufacturer=id_resp.get("vendor", ""),
                model=id_resp.get("product", ""),
                firmware_version=id_resp.get("revision", ""),
            )
            devices.append(device)

        self._status.device_count = len(devices)
        return devices

    def poll(self, signals: list[SignalConfig]) -> list[SignalReading]:
        readings = []
        now = datetime.now(timezone.utc)

        for sig in signals:
            # Parse address as "slave_addr:register"
            parts = sig.address.split(":")
            if len(parts) != 2:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))
                continue

            addr = int(parts[0])
            reg = int(parts[1])

            # Determine function code from register range
            if 40001 <= reg <= 49999:
                cmd = "modbus.read_holding"
            elif 30001 <= reg <= 39999:
                cmd = "modbus.read_input"
            elif 1 <= reg <= 9999:
                cmd = "modbus.read_coils"
            else:
                cmd = "modbus.read_holding"

            resp = self._transport.send_command(
                cmd, {"addr": addr, "reg": reg, "count": 1}
            )

            if resp.get("status") == "ok":
                values = resp.get("values", [])
                readings.append(SignalReading(
                    signal_id=sig.signal_id,
                    value=values[0] if values else None,
                    quality="good",
                    timestamp=now,
                ))
            else:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))

        self._status.last_poll_at = now
        return readings

    def execute(self, command: RemoteCommand) -> CommandResult:
        if command.type == "write_register":
            resp = self._transport.send_command(
                "modbus.write_register", {
                    "addr": int(command.target),
                    "reg": command.params.get("register"),
                    "value": command.params.get("value"),
                    "confirm": True,
                }
            )
            return CommandResult(
                command_id=command.command_id,
                success=resp.get("status") == "ok",
                error=resp.get("error", ""),
            )
        return CommandResult(
            command_id=command.command_id,
            success=False,
            error=f"unknown command type: {command.type}",
        )
```

**Step 4: Run the tests**

```bash
python3 tests/test_modbus_rtu_adapter.py -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add library/user/ics/agent/edgeops_agent/adapters/modbus_rtu.py tests/test_modbus_rtu_adapter.py
git commit -m "feat(agent): ModbusRTUAdapter with discovery and polling"
```

### Task 3.3: Implement CANAdapter

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/can.py`

**Step 1: Implement**

Mirror `ModbusRTUAdapter` pattern. Key differences:
- `discover()` calls `can.scan_ids` with configurable baud, returns `DiscoveredDevice` per unique CAN ID
- `poll()` calls `can.listen` for a short duration, parses frames matching configured signal CAN IDs
- `execute()` calls `can.send` with `confirm: true`
- Signal address format: `"0x7E0"` (CAN arbitration ID)

**Step 2: Write a test, run it, commit**

```bash
git commit -m "feat(agent): CANAdapter with passive listen and ID scanning"
```

### Task 3.4: Implement DIOAdapter

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/dio.py`

**Step 1: Implement**

- `discover()` reads all 4 channels, returns one `DiscoveredDevice` with `protocols=["digital-io"]`
- `poll()` calls `dio.read`, maps channels to signals (address format: `"ch0"`, `"ch1"`, etc.)
- `execute()` handles `configure` and `write` commands, both require `confirm: true`

**Step 2: Test, commit**

```bash
git commit -m "feat(agent): DIOAdapter for MAX14906 digital I/O"
```

### Task 3.5: Implement CurrentOutputAdapter

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/current_output.py`

**Step 1: Implement**

- `discover()` returns one device if `iout` is ready on the probe
- `poll()` calls `iout.status`, returns current setpoint as a signal reading
- `execute()` handles `set_ma`, `ramp`, `off` commands, all confirm-gated

**Step 2: Test, commit**

```bash
git commit -m "feat(agent): CurrentOutputAdapter for AD5420 4-20mA"
```

### Task 3.6: Implement EthernetAdapter

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/adapters/ethernet.py`

**Step 1: Implement**

This adapter uses the probe's W5500 Ethernet for Modbus TCP and other
IP-based protocols. Unlike other adapters, it opens TCP sockets:
- `discover()` scans a subnet for Modbus TCP (port 502) via `net.tcp_connect` + FC17
- `poll()` opens TCP connections to known devices, sends Modbus TCP read requests
- Signal address format: `"192.168.1.10:502:40001"` (host:port:register)

**Step 2: Test, commit**

```bash
git commit -m "feat(agent): EthernetAdapter for Modbus TCP via probe W5500"
```

### Task 3.7: Register all adapters

**Files:**
- Modify: `library/user/ics/agent/edgeops_agent/adapters/__init__.py`

**Step 1: Create adapter registry**

```python
from .modbus_rtu import ModbusRTUAdapter
from .can import CANAdapter
from .dio import DIOAdapter
from .current_output import CurrentOutputAdapter
from .ethernet import EthernetAdapter

ADAPTER_REGISTRY = {
    "modbus-rtu": ModbusRTUAdapter,
    "can": CANAdapter,
    "digital-io": DIOAdapter,
    "analog-output": CurrentOutputAdapter,
    "modbus-tcp": EthernetAdapter,
}
```

**Step 2: Commit**

```bash
git commit -m "feat(agent): adapter registry mapping types to classes"
```

---

## Phase 4: Agent Core

### Task 4.1: Implement config loader

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/config.py`

**Step 1: Implement**

Loads `/root/edgeops/agent-config.json` (or path from `EDGEOPS_CONFIG_PATH` env var).
Format:

```json
{
  "device_id": "org-123-pager-001",
  "api_base_url": "https://api.edgeops.cloud",
  "auth": {
    "type": "api_key",
    "api_key": "ek_..."
  },
  "poll_interval_ms": 5000,
  "buffer_max_mb": 50,
  "adapters": [
    {"type": "modbus-rtu", "connection_params": {}, "signals": [
      {"signal_id": "temp_1", "address": "1:40001", "data_type": "float32"}
    ]},
    {"type": "digital-io", "connection_params": {}, "signals": [
      {"signal_id": "valve_open", "address": "ch0", "data_type": "bool"}
    ]}
  ]
}
```

Falls back to environment variables (`EDGEOPS_DEVICE_ID`, `EDGEOPS_API_KEY`, etc.)
if no config file exists. Validates required fields.

**Step 2: Commit**

```bash
git commit -m "feat(agent): config loader with file + env var fallback"
```

### Task 4.2: Implement SQLite telemetry buffer

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/buffer.py`
- Create: `tests/test_buffer.py`

**Step 1: Write failing test**

```python
class TestSQLiteBuffer(unittest.TestCase):
    def test_append_and_flush(self):
        buf = SQLiteBuffer(":memory:", max_mb=1)
        buf.append({"signal_id": "temp", "value": 42, "quality": "good"})
        batch = buf.flush(limit=10)
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["signal_id"], "temp")

    def test_evicts_oldest_when_full(self):
        buf = SQLiteBuffer(":memory:", max_mb=0.001)  # ~1KB
        for i in range(1000):
            buf.append({"i": i})
        count = buf.pending_count()
        self.assertLess(count, 1000)
```

**Step 2: Implement** `SQLiteBuffer` with `append()`, `flush(limit)`,
`pending_count()`, and auto-eviction.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(agent): SQLite telemetry buffer with size-based eviction"
```

### Task 4.3: Implement agent core

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/agent_core.py`

**Step 1: Implement**

The main agent class orchestrating everything:

```python
class AgentCore:
    def __init__(self, config_path: str | None = None):
        self.config = load_config(config_path)
        self.transport = ProbeTransport()
        self.buffer = SQLiteBuffer(...)
        self.adapters = []
        self.client = None  # EdgeOpsClient, initialized on connect
        self._running = False

    def start(self):
        """Initialize adapters, start poll loop, connect to cloud."""
        self._init_adapters()
        self._init_cloud_client()
        self._running = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._poll_thread.start()
        self._flush_thread.start()

    def stop(self):
        """Graceful shutdown."""
        self._running = False
        for adapter in self.adapters:
            adapter.shutdown()
        if self.client:
            self.client.disconnect()

    def _poll_loop(self):
        while self._running:
            for adapter in self.adapters:
                readings = adapter.poll(adapter._config.signals)
                for r in readings:
                    self.buffer.append(r.to_dict())
            time.sleep(self.config.poll_interval_ms / 1000)

    def _flush_loop(self):
        while self._running:
            batch = self.buffer.flush(limit=50)
            if batch and self.client:
                self.client.publish_telemetry({"readings": batch})
            time.sleep(5)
```

**Step 2: Commit**

```bash
git commit -m "feat(agent): agent core with poll loop, buffer flush, and cloud connection"
```

### Task 4.4: Implement `__main__.py` entry point

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/__main__.py`

**Step 1: Implement**

```python
"""Entry point: python3 -m edgeops_agent"""
import signal
import sys
from .agent_core import AgentCore

def main():
    agent = AgentCore()
    signal.signal(signal.SIGTERM, lambda *_: agent.stop())
    signal.signal(signal.SIGINT, lambda *_: agent.stop())
    agent.start()
    # Block until stopped
    try:
        while agent._running:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()

if __name__ == "__main__":
    main()
```

**Step 2: Commit**

```bash
git commit -m "feat(agent): __main__.py entry point for python3 -m edgeops_agent"
```

---

## Phase 5: DuckyScript UI & Payloads

### Task 5.1: Implement UI bridge

**Files:**
- Create: `library/user/ics/agent/edgeops_agent/ui_bridge.py`

**Step 1: Implement**

Wraps DuckyScript commands for subprocess calls from Python:

```python
"""DuckyScript UI bridge — call pager UI commands from Python."""
import subprocess

def log(color: str, msg: str) -> None:
    subprocess.run(["bash", "-c", f'LOG {color} "{msg}"'], check=False)

def alert(msg: str) -> None:
    subprocess.run(["bash", "-c", f'ALERT "{msg}"'], check=False)

def start_spinner(msg: str) -> str:
    result = subprocess.run(
        ["bash", "-c", f'START_SPINNER "{msg}"'],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip()

def stop_spinner(spinner_id: str) -> None:
    subprocess.run(["bash", "-c", f'STOP_SPINNER {spinner_id}'], check=False)

def write_status_file(status: dict) -> None:
    """Write agent status to /tmp/edgeops-status.json for payload.sh to read."""
    import json
    with open("/tmp/edgeops-status.json", "w") as f:
        json.dump(status, f)
```

**Step 2: Commit**

```bash
git commit -m "feat(agent): DuckyScript UI bridge for pager screen updates"
```

### Task 5.2: Implement payload.sh

**Files:**
- Modify: `library/user/ics/agent/payload.sh` (replace placeholder)

**Step 1: Write the full payload**

Menu-driven DuckyScript payload:
- **Start Agent** — launches `python3 -m edgeops_agent` as background process, saves PID
- **Stop Agent** — kills the background process
- **View Status** — reads `/tmp/edgeops-status.json`, displays on screen
- **Discover Devices** — runs agent discovery pass, shows results
- **Configure** — opens TEXT_PICKER for config file path or basic settings
- Checks for enrollment (`/root/edgeops/enrollment.json`), redirects to `enroll.sh` if missing

**Step 2: `bash -n` check, commit**

```bash
git commit -m "feat(agent): payload.sh DuckyScript menu UI"
```

### Task 5.3: Implement enroll.sh

**Files:**
- Modify: `library/user/ics/agent/enrollment/enroll.sh` (replace placeholder)

**Step 1: Write the enrollment payload**

Uses DuckyScript pickers to collect:
- API base URL (TEXT_PICKER, default `https://api.edgeops.cloud`)
- Device ID (TEXT_PICKER)
- Auth method: API Key or Certificate
- API Key (TEXT_PICKER) or provisioning token

Calls the EdgeOps Python SDK `provision_device()` if using provisioning,
or writes a direct config if using API key. Saves to
`/root/edgeops/enrollment.json` and `/root/edgeops/agent-config.json`.

**Step 2: `bash -n` check, commit**

```bash
git commit -m "feat(agent): enrollment payload for EdgeOps device registration"
```

---

## Phase 6: Integration & Testing

### Task 6.1: End-to-end smoke test (mocked probe)

**Files:**
- Create: `tests/test_agent_e2e.py`

**Step 1: Write integration test**

Mocks `ProbeTransport` to return canned responses. Creates an `AgentCore`,
starts it, verifies:
- Adapters initialize
- Poll loop produces readings
- Buffer accumulates readings
- Flush sends telemetry (mock the EdgeOps client)

**Step 2: Run, commit**

```bash
git commit -m "test(agent): end-to-end smoke test with mocked probe"
```

### Task 6.2: Batch syntax and import check

**Step 1: Verify all Python files import cleanly**

```bash
cd library/user/ics/agent
python3 -c "
from edgeops_agent.probe_transport import ProbeTransport
from edgeops_agent.adapters import ADAPTER_REGISTRY
from edgeops_agent.agent_core import AgentCore
from edgeops_agent.config import load_config
from edgeops_agent.buffer import SQLiteBuffer
from edgeops_agent.ui_bridge import log, alert
print('All imports OK')
print('Adapters:', list(ADAPTER_REGISTRY.keys()))
"
cd /Volumes/dev/wifipineapplepager-payloads
```

**Step 2: Verify shell payloads**

```bash
bash -n library/user/ics/agent/payload.sh
bash -n library/user/ics/agent/enrollment/enroll.sh
```

**Step 3: Run all Python tests**

```bash
python3 -m pytest tests/test_probe_transport.py tests/test_modbus_rtu_adapter.py tests/test_buffer.py tests/test_agent_e2e.py -v
```

**Step 4: Commit any fixes**

### Task 6.3: Update docs and payloads index

**Files:**
- Modify: `docs/updated-payloads.md` — add EdgeOps Agent and Enrollment payloads
- Modify: `library/user/ics/agent/edgeops_agent/__init__.py` — bump to `0.1.0`

**Step 1: Commit**

```bash
git commit -m "docs: add EdgeOps agent payload to catalog"
```

---

## Phase Rollup

| Phase | Tasks | Purpose | Gate |
|---|---|---|---|
| 1 | 2 | Scaffolding + vendor SDK | Imports clean |
| 2 | 2 | ProbeTransport | Unit tests pass |
| 3 | 7 | Protocol adapters | All 5 adapters + tests pass |
| 4 | 4 | Agent core | Poll + buffer + flush working |
| 5 | 3 | UI + payloads | `bash -n` clean, enrollment flow works |
| 6 | 3 | Integration testing | E2E test passes, all imports clean |

**Total tasks: 21.** Blocked on: ICS Probe v1.1 hardware for real-device testing.
Software work (mocked probe) can proceed immediately.
