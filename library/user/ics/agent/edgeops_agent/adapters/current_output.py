"""4-20mA current output adapter — wraps iout.* probe commands for the AD5420."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult,
)


class CurrentOutputAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("analog-output", "analog-output", transport)

    def initialize(self, config):
        self._config = config
        self._status.state = "running"

    def shutdown(self):
        self._transport.send_command("iout.off", {})
        self._status.state = "idle"

    def discover(self):
        resp = self._transport.send_command("iout.status", {})
        if resp.get("status") != "ok":
            return []

        self._status.device_count = 1
        return [DiscoveredDevice(
            address="ad5420",
            protocols=["analog-output"],
            capabilities=["4-20mA source"],
            metadata={"current_ma": resp.get("ma", 0)},
        )]

    def poll(self, signals):
        readings = []
        now = datetime.now(timezone.utc)

        resp = self._transport.send_command("iout.status", {})
        if resp.get("status") == "ok":
            for sig in signals:
                readings.append(SignalReading(
                    signal_id=sig.signal_id,
                    value=resp.get("ma", 0),
                    quality="good", timestamp=now,
                ))
        else:
            for sig in signals:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))

        self._status.last_poll_at = now
        return readings

    def execute(self, command):
        if command.type == "set_ma":
            resp = self._transport.send_command(
                "iout.set_ma", {
                    "ma": float(command.params.get("ma", 4.0)),
                    "confirm": True,
                }
            )
            return CommandResult(
                command_id=command.command_id,
                success=resp.get("status") == "ok",
                error=resp.get("error", ""),
            )
        if command.type == "ramp":
            resp = self._transport.send_command(
                "iout.ramp", {
                    "from_ma": float(command.params.get("from_ma", 4)),
                    "to_ma": float(command.params.get("to_ma", 20)),
                    "duration_s": int(command.params.get("duration_s", 10)),
                    "confirm": True,
                }
            )
            return CommandResult(
                command_id=command.command_id,
                success=resp.get("status") == "ok",
                error=resp.get("error", ""),
            )
        if command.type == "off":
            resp = self._transport.send_command("iout.off", {})
            return CommandResult(
                command_id=command.command_id,
                success=resp.get("status") == "ok",
                error=resp.get("error", ""),
            )
        return CommandResult(
            command_id=command.command_id, success=False,
            error=f"unknown command type: {command.type}",
        )
