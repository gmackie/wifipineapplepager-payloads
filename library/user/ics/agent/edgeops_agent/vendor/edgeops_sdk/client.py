"""
EdgeOps Client - Main SDK class
"""

import json
import time
from typing import Optional, Dict, Any, Callable
from threading import Timer
from .types import (
    EdgeOpsConfig,
    ConnectionStatus,
    TelemetryMessage,
    Command,
    CommandHandler,
    HeartbeatData,
    DeviceShadow,
)
from .errors import EdgeOpsConnectionError, EdgeOpsAuthError
from .mqtt_client import MQTTClient
from .http_client import HTTPClient
from .telemetry_buffer import TelemetryBuffer


class EdgeOpsClient:
    """Main client for connecting to EdgeOps Cloud platform"""

    def __init__(self, config: EdgeOpsConfig):
        self.config = self._normalize_config(config)
        self.mqtt_client: Optional[MQTTClient] = None
        self.http_client: Optional[HTTPClient] = None
        self.telemetry_buffer = TelemetryBuffer(
            max_size=self.config.telemetry.get("buffer_size", 1000),
            batch_size=self.config.telemetry.get("batch_size", 10),
            batch_interval=self.config.telemetry.get("batch_interval", 5),
        )
        self.heartbeat_timer: Optional[Timer] = None
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.command_handlers: list[CommandHandler] = []

        # Set up telemetry buffer flush handler
        self.telemetry_buffer.on_flush = self._flush_telemetry_buffer

    def _normalize_config(self, config: EdgeOpsConfig) -> EdgeOpsConfig:
        """Normalize configuration with defaults"""
        normalized = EdgeOpsConfig(
            api_base_url=config.api_base_url,
            device_id=config.device_id,
            organization_id=config.organization_id,
            auth=config.auth,
            mqtt=config.mqtt.copy() if config.mqtt else {},
            http=config.http.copy() if config.http else {},
            telemetry=config.telemetry.copy() if config.telemetry else {},
            heartbeat=config.heartbeat.copy() if config.heartbeat else {},
        )

        # Determine default transport based on auth type
        if config.auth["type"] == "certificate":
            normalized.mqtt["enabled"] = normalized.mqtt.get("enabled", True)
            normalized.http["enabled"] = normalized.http.get("enabled", False)
        else:
            normalized.mqtt["enabled"] = normalized.mqtt.get("enabled", False)
            normalized.http["enabled"] = normalized.http.get("enabled", True)

        return normalized

    def connect(self) -> None:
        """Connect to EdgeOps Cloud platform"""
        if self.connection_status == ConnectionStatus.CONNECTED:
            return

        self.connection_status = ConnectionStatus.CONNECTING

        try:
            # Initialize MQTT client if enabled
            if self.config.mqtt.get("enabled"):
                if self.config.auth["type"] != "certificate":
                    raise EdgeOpsAuthError("MQTT requires certificate authentication")

                self.mqtt_client = MQTTClient(self.config)
                self.mqtt_client.on_status = self._on_mqtt_status
                self.mqtt_client.on_command = self._on_command
                self.mqtt_client.connect()

            # Initialize HTTP client if enabled
            if self.config.http.get("enabled"):
                self.http_client = HTTPClient(self.config)
                self.http_client.connect()

            # Start heartbeat if enabled
            if self.config.heartbeat.get("enabled", True):
                self._start_heartbeat()

            self.connection_status = ConnectionStatus.CONNECTED
        except Exception as error:
            self.connection_status = ConnectionStatus.ERROR
            raise error

    def disconnect(self) -> None:
        """Disconnect from EdgeOps Cloud platform"""
        if self.heartbeat_timer:
            self.heartbeat_timer.cancel()
            self.heartbeat_timer = None

        if self.mqtt_client:
            self.mqtt_client.disconnect()
            self.mqtt_client = None

        if self.http_client:
            self.http_client.disconnect()
            self.http_client = None

        self.connection_status = ConnectionStatus.DISCONNECTED

    def publish_telemetry(
        self, data: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Publish telemetry data"""
        message: TelemetryMessage = {
            "timestamp": self._get_timestamp(),
            "data": data,
            "metadata": metadata,
        }

        # If connected, try to send immediately
        if self.connection_status == ConnectionStatus.CONNECTED:
            try:
                if self.mqtt_client:
                    self.mqtt_client.publish_telemetry(message)
                    return
                elif self.http_client:
                    self.http_client.publish_telemetry(message)
                    return
            except Exception as error:
                # If send fails, buffer the message
                print(f"Warning: Failed to send telemetry, buffering: {error}")

        # Buffer the message if not connected or send failed
        self.telemetry_buffer.add(message)

    def update_shadow(self, reported: Dict[str, Any]) -> None:
        """Update device shadow (reported state)"""
        if not self.mqtt_client:
            raise EdgeOpsConnectionError(
                "MQTT client not available. Shadow updates require MQTT connection."
            )

        self.mqtt_client.update_shadow(reported)

    def get_shadow(self) -> DeviceShadow:
        """Get device shadow"""
        if self.mqtt_client:
            return self.mqtt_client.get_shadow()
        elif self.http_client:
            return self.http_client.get_shadow()

        raise EdgeOpsConnectionError("No connection available")

    def on_command(self, handler: CommandHandler) -> None:
        """Register command handler"""
        self.command_handlers.append(handler)

    def send_heartbeat(self, data: Optional[Dict[str, Any]] = None) -> None:
        """Send heartbeat"""
        heartbeat: Dict[str, Any] = {
            "timestamp": self._get_timestamp(),
            **(data or {}),
        }

        if self.mqtt_client:
            self.mqtt_client.send_heartbeat(heartbeat)
        elif self.http_client:
            self.http_client.send_heartbeat(heartbeat)

    def get_status(self) -> ConnectionStatus:
        """Get current connection status"""
        return self.connection_status

    def _on_mqtt_status(self, status: ConnectionStatus) -> None:
        """Handle MQTT status changes"""
        self.connection_status = status

    def _on_command(self, command: Command) -> None:
        """Handle incoming command"""
        for handler in self.command_handlers:
            try:
                handler(command)
            except Exception as error:
                print(f"Error in command handler: {error}")

    def _start_heartbeat(self) -> None:
        """Start heartbeat timer"""
        interval = self.config.heartbeat.get("interval", 60)

        def send_heartbeat():
            try:
                self.send_heartbeat()
            except Exception as e:
                print(f"Error sending heartbeat: {e}")

        try:
            from threading import Timer
            self.heartbeat_timer = Timer(interval, send_heartbeat)
            self.heartbeat_timer.start()
        except ImportError:
            # MicroPython/CircuitPython - use alternative timer
            pass

    def _flush_telemetry_buffer(self, messages: list[TelemetryMessage]) -> None:
        """Flush telemetry buffer"""
        if not messages:
            return

        try:
            if self.mqtt_client and self.connection_status == ConnectionStatus.CONNECTED:
                import asyncio

                asyncio.create_task(self.mqtt_client.publish_telemetry_batch(messages))
            elif self.http_client and self.connection_status == ConnectionStatus.CONNECTED:
                import asyncio

                asyncio.create_task(self.http_client.publish_telemetry_batch(messages))
        except ImportError:
            # MicroPython/CircuitPython - handle synchronously
            pass
        except Exception as error:
            # Re-buffer messages if send fails
            for msg in messages:
                self.telemetry_buffer.add(msg)
            print(f"Error flushing telemetry buffer: {error}")

    def _get_timestamp(self) -> str:
        """Get ISO 8601 timestamp"""
        try:
            from datetime import datetime, timezone

            return datetime.now(timezone.utc).isoformat()
        except ImportError:
            # MicroPython/CircuitPython fallback
            return f"{time.time()}"
