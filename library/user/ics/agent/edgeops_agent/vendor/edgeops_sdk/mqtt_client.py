"""
MQTT Client for AWS IoT Core
"""

import json
import ssl
from typing import Optional, Dict, Any
from .types import EdgeOpsConfig, ConnectionStatus, TelemetryMessage, DeviceShadow
from .errors import EdgeOpsConnectionError, EdgeOpsAuthError

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False


class MQTTClient:
    """MQTT client for AWS IoT Core"""

    def __init__(self, config: EdgeOpsConfig):
        if not PAHO_AVAILABLE:
            raise ImportError("paho-mqtt is required for MQTT support. Install with: pip install edgeops-sdk[mqtt]")

        self.config = config
        self.client: Optional[mqtt.Client] = None
        self.status = ConnectionStatus.DISCONNECTED
        self.on_status: Optional[callable] = None
        self.on_command: Optional[callable] = None

        # Build topic names
        org_id = config.organization_id or self._extract_org_id_from_device_id(config.device_id)
        self.telemetry_topic = f"edgeops/{org_id}/devices/{config.device_id}/telemetry"
        self.command_topic = f"edgeops/{org_id}/devices/{config.device_id}/commands/+"
        self.shadow_topic = f"$aws/things/{config.device_id}/shadow/update"

    def _extract_org_id_from_device_id(self, device_id: str) -> str:
        """Extract organization ID from device ID"""
        # Device ID format: orgId-deviceName
        parts = device_id.split("-")
        return parts[0] if parts else "default"

    def connect(self) -> None:
        """Connect to MQTT broker"""
        if self.config.auth["type"] != "certificate":
            raise EdgeOpsAuthError("MQTT client requires certificate authentication")

        auth = self.config.auth

        try:
            # Create MQTT client
            self.client = mqtt.Client(client_id=self.config.device_id)

            # Set up TLS
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            # Load certificates
            if isinstance(auth["certificate"], str):
                context.load_cert_chain(auth["certificate"], auth["private_key"])
            else:
                # Bytes - would need to write to temp file or use in-memory certs
                raise NotImplementedError("In-memory certificates not yet supported")

            if isinstance(auth["root_ca"], str):
                context.load_verify_locations(auth["root_ca"])
            else:
                raise NotImplementedError("In-memory root CA not yet supported")

            self.client.tls_set_context(context)

            # Set up callbacks
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message
            self.client.on_publish = self._on_publish

            # Get IoT endpoint
            endpoint = auth.get("iot_endpoint")
            if not endpoint:
                raise ValueError("iot_endpoint must be provided in auth config")

            # Connect
            self.client.connect(endpoint, 8883, keepalive=self.config.mqtt.get("keep_alive", 60))
            self.client.loop_start()

            self.status = ConnectionStatus.CONNECTED
            if self.on_status:
                self.on_status(self.status)

        except Exception as error:
            self.status = ConnectionStatus.ERROR
            if self.on_status:
                self.on_status(self.status)
            raise EdgeOpsConnectionError(f"Failed to connect to MQTT broker: {error}") from error

    def disconnect(self) -> None:
        """Disconnect from MQTT broker"""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.client = None
            self.status = ConnectionStatus.DISCONNECTED
            if self.on_status:
                self.on_status(self.status)

    def publish_telemetry(self, message: TelemetryMessage) -> None:
        """Publish telemetry message"""
        if not self.client or self.status != ConnectionStatus.CONNECTED:
            raise EdgeOpsConnectionError("MQTT client not connected")

        payload = json.dumps(message)
        result = self.client.publish(self.telemetry_topic, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise EdgeOpsConnectionError(f"Failed to publish telemetry: {result.rc}")

    def publish_telemetry_batch(self, messages: list[TelemetryMessage]) -> None:
        """Publish batch of telemetry messages"""
        for message in messages:
            self.publish_telemetry(message)

    def update_shadow(self, reported: Dict[str, Any]) -> None:
        """Update device shadow"""
        if not self.client or self.status != ConnectionStatus.CONNECTED:
            raise EdgeOpsConnectionError("MQTT client not connected")

        shadow_update = {
            "state": {
                "reported": reported,
            }
        }

        payload = json.dumps(shadow_update)
        result = self.client.publish(self.shadow_topic, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise EdgeOpsConnectionError(f"Failed to update shadow: {result.rc}")

    def get_shadow(self) -> DeviceShadow:
        """Get device shadow (not yet implemented for MQTT)"""
        raise NotImplementedError("get_shadow not yet implemented for MQTT client")

    def send_heartbeat(self, data: Dict[str, Any]) -> None:
        """Send heartbeat"""
        heartbeat_topic = self.telemetry_topic.replace("/telemetry", "/heartbeat")
        payload = json.dumps(data)
        result = self.client.publish(heartbeat_topic, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise EdgeOpsConnectionError(f"Failed to send heartbeat: {result.rc}")

    def _on_connect(self, client, userdata, flags, rc) -> None:
        """Handle MQTT connect"""
        if rc == 0:
            self.status = ConnectionStatus.CONNECTED
            if self.on_status:
                self.on_status(self.status)
            # Subscribe to commands
            client.subscribe(self.command_topic, qos=1)
        else:
            self.status = ConnectionStatus.ERROR
            if self.on_status:
                self.on_status(self.status)

    def _on_disconnect(self, client, userdata, rc) -> None:
        """Handle MQTT disconnect"""
        self.status = ConnectionStatus.DISCONNECTED
        if self.on_status:
            self.on_status(self.status)

    def _on_message(self, client, userdata, msg) -> None:
        """Handle MQTT message"""
        try:
            command = json.loads(msg.payload.decode())
            if self.on_command:
                self.on_command(command)
        except Exception as error:
            print(f"Error parsing command: {error}")

    def _on_publish(self, client, userdata, mid) -> None:
        """Handle MQTT publish"""
        pass
