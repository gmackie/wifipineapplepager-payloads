"""Ethernet adapter — Modbus TCP and other IP protocols via probe W5500."""
from datetime import datetime, timezone
from .base import (
    ProtocolAdapter, SignalConfig, SignalReading,
    DiscoveredDevice, RemoteCommand, CommandResult,
)

# Modbus TCP FC17 Report Slave ID request
# MBAP: txn=0001, proto=0000, length=0002, unit=01; PDU: FC=11
MODBUS_FC17_HEX = "000100000002011100"


class EthernetAdapter(ProtocolAdapter):

    def __init__(self, transport):
        super().__init__("modbus-tcp", "modbus-tcp", transport)
        self._subnet = ""
        self._known_devices = {}

    def initialize(self, config):
        self._config = config
        self._subnet = config.connection_params.get("subnet", "192.168.1")
        # Ensure probe Ethernet is configured
        net_status = self._transport.send_command("net.status", {})
        if net_status.get("link"):
            self._status.state = "running"
        else:
            self._status.state = "degraded"
            self._status.error_message = "Probe Ethernet link down"

    def shutdown(self):
        self._status.state = "idle"

    def discover(self):
        devices = []
        start = self._config.connection_params.get("scan_start", 1)
        end = self._config.connection_params.get("scan_end", 254)

        for host_num in range(start, end + 1):
            target = f"{self._subnet}.{host_num}"
            conn = self._transport.send_command(
                "net.tcp_connect", {"host": target, "port": 502}
            )
            if conn.get("status") != "ok":
                continue

            sock = conn.get("sock")
            self._transport.send_command(
                "net.tcp_send", {"sock": sock, "data": MODBUS_FC17_HEX}
            )
            recv = self._transport.send_command(
                "net.tcp_recv", {"sock": sock, "timeout_ms": 2000}
            )
            self._transport.send_command("net.tcp_close", {"sock": sock})

            if recv.get("data"):
                device = DiscoveredDevice(
                    address=f"{target}:502",
                    protocols=["modbus-tcp"],
                )
                devices.append(device)
                self._known_devices[target] = device

        self._status.device_count = len(devices)
        return devices

    def poll(self, signals):
        readings = []
        now = datetime.now(timezone.utc)

        for sig in signals:
            # Address format: "host:port:register"
            parts = sig.address.split(":")
            if len(parts) != 3:
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))
                continue

            host, port, reg = parts[0], int(parts[1]), int(parts[2])

            conn = self._transport.send_command(
                "net.tcp_connect", {"host": host, "port": port}
            )
            if conn.get("status") != "ok":
                readings.append(SignalReading(
                    signal_id=sig.signal_id, value=None,
                    quality="bad", timestamp=now,
                ))
                continue

            sock = conn.get("sock")

            # Build Modbus TCP read holding register request
            # MBAP: txn=0001, proto=0000, length=0006, unit=01
            # PDU: FC=03, start_reg (2 bytes), count=0001
            reg_offset = reg - 40001 if reg >= 40001 else reg
            req_hex = f"0001000000060103{reg_offset:04x}0001"

            self._transport.send_command(
                "net.tcp_send", {"sock": sock, "data": req_hex}
            )
            recv = self._transport.send_command(
                "net.tcp_recv", {"sock": sock, "timeout_ms": 2000}
            )
            self._transport.send_command("net.tcp_close", {"sock": sock})

            if recv.get("status") == "ok" and recv.get("data"):
                raw = recv["data"]
                # Response: MBAP (14 hex) + FC (2) + byte_count (2) + data (4)
                if len(raw) >= 22:
                    value_hex = raw[18:22]
                    value = int(value_hex, 16)
                    readings.append(SignalReading(
                        signal_id=sig.signal_id, value=value,
                        quality="good", timestamp=now,
                    ))
                    continue

            readings.append(SignalReading(
                signal_id=sig.signal_id, value=None,
                quality="bad", timestamp=now,
            ))

        self._status.last_poll_at = now
        return readings

    def execute(self, command):
        return CommandResult(
            command_id=command.command_id, success=False,
            error="ethernet adapter does not support remote commands in v1",
        )
