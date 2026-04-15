"""CAN bus adapter — wraps can.* probe commands."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult,
)


class CANAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("can", "can", transport)
        self._baud = 500000

    def initialize(self, config):
        self._config = config
        self._baud = config.connection_params.get("baud", 500000)
        self._status.state = "running"

    def shutdown(self):
        self._status.state = "idle"

    def discover(self):
        resp = self._transport.send_command(
            "can.scan_ids", {"baud": self._baud, "duration_s": 10}, timeout=15
        )
        if resp.get("status") != "ok":
            return []

        devices = []
        for can_id in resp.get("ids", []):
            devices.append(DiscoveredDevice(
                address=can_id,
                protocols=["can"],
                metadata={"baud": self._baud},
            ))

        self._status.device_count = len(devices)
        return devices

    def poll(self, signals):
        readings = []
        now = datetime.now(timezone.utc)

        # Listen for a short window and match frames to signal IDs
        resp = self._transport.send_command(
            "can.listen", {"baud": self._baud, "duration_s": 2}, timeout=5
        )

        # Build lookup of CAN ID → signal config
        id_to_signal = {sig.address: sig for sig in signals}

        if resp.get("status") == "ok":
            for frame in resp.get("frames", []):
                frame_id = frame.get("id", "")
                if frame_id in id_to_signal:
                    sig = id_to_signal[frame_id]
                    readings.append(SignalReading(
                        signal_id=sig.signal_id,
                        value=frame.get("data", ""),
                        quality="good", timestamp=now,
                    ))
                    del id_to_signal[frame_id]

        # Signals not seen in the listen window get "uncertain"
        for sig in id_to_signal.values():
            readings.append(SignalReading(
                signal_id=sig.signal_id, value=None,
                quality="uncertain", timestamp=now,
            ))

        self._status.last_poll_at = now
        return readings

    def execute(self, command):
        if command.type == "send_frame":
            resp = self._transport.send_command(
                "can.send", {
                    "id": command.target,
                    "data": command.params.get("data", ""),
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
