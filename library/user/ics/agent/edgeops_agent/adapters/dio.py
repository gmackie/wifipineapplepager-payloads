"""Digital I/O adapter — wraps dio.* probe commands for the MAX14906."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult,
)

NUM_CHANNELS = 4


class DIOAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("digital-io", "digital-io", transport)

    def initialize(self, config):
        self._config = config
        # Configure channels based on signal configs
        for sig in config.signals:
            ch = self._parse_channel(sig.address)
            if ch is not None:
                mode = sig.data_type if sig.data_type in (
                    "input_t1", "input_t2", "input_t3", "output"
                ) else "input_t3"
                self._transport.send_command(
                    "dio.configure", {"ch": ch, "mode": mode}
                )
        self._status.state = "running"

    def shutdown(self):
        self._status.state = "idle"

    def discover(self):
        resp = self._transport.send_command("dio.read", {})
        if resp.get("status") != "ok":
            return []

        self._status.device_count = 1
        return [DiscoveredDevice(
            address="max14906",
            protocols=["digital-io"],
            capabilities=[f"ch{i}" for i in range(NUM_CHANNELS)],
            metadata={"channels": NUM_CHANNELS},
        )]

    def poll(self, signals):
        readings = []
        now = datetime.now(timezone.utc)

        resp = self._transport.send_command("dio.read", {})
        if resp.get("status") != "ok":
            for sig in signals:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))
            return readings

        channels = {ch["ch"]: ch for ch in resp.get("channels", [])}

        for sig in signals:
            ch = self._parse_channel(sig.address)
            if ch is not None and ch in channels:
                readings.append(SignalReading(
                    signal_id=sig.signal_id,
                    value=bool(channels[ch].get("value", 0)),
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
        if command.type == "write":
            ch = self._parse_channel(command.target)
            if ch is None:
                return CommandResult(
                    command_id=command.command_id, success=False,
                    error="invalid channel",
                )
            resp = self._transport.send_command(
                "dio.write", {
                    "ch": ch,
                    "value": int(command.params.get("value", 0)),
                    "confirm": True,
                }
            )
            return CommandResult(
                command_id=command.command_id,
                success=resp.get("status") == "ok",
                error=resp.get("error", ""),
            )
        if command.type == "configure":
            ch = self._parse_channel(command.target)
            mode = command.params.get("mode", "input_t3")
            resp = self._transport.send_command(
                "dio.configure", {"ch": ch, "mode": mode}
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

    @staticmethod
    def _parse_channel(address):
        """Parse 'ch0', 'ch1', etc. to int."""
        if isinstance(address, str) and address.startswith("ch"):
            try:
                return int(address[2:])
            except ValueError:
                pass
        return None
