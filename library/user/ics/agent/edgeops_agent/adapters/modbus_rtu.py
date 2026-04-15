"""Modbus RTU adapter — wraps modbus.* probe commands."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult,
)


class ModbusRTUAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("modbus-rtu", "modbus-rtu", transport)

    def initialize(self, config):
        self._config = config
        self._status.state = "running"

    def shutdown(self):
        self._status.state = "idle"

    def discover(self):
        resp = self._transport.send_command(
            "modbus.scan_bus", {"range": [1, 247]}, timeout=60
        )
        if resp.get("status") != "ok":
            return []

        devices = []
        for slave_id in resp.get("slaves", []):
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

    def poll(self, signals):
        readings = []
        now = datetime.now(timezone.utc)

        for sig in signals:
            parts = sig.address.split(":")
            if len(parts) != 2:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))
                continue

            addr, reg = int(parts[0]), int(parts[1])

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
                    quality="good", timestamp=now,
                ))
            else:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))

        self._status.last_poll_at = now
        return readings

    def execute(self, command):
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
            command_id=command.command_id, success=False,
            error=f"unknown command type: {command.type}",
        )
