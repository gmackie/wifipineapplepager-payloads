"""
HTTP Client for REST API communication
"""

from typing import Dict, Any, Optional
from .types import EdgeOpsConfig, ConnectionStatus, TelemetryMessage, DeviceShadow
from .errors import EdgeOpsConnectionError, EdgeOpsAuthError

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class HTTPClient:
    """HTTP client for REST API communication"""

    def __init__(self, config: EdgeOpsConfig):
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required for HTTP support")

        self.config = config
        self.session = requests.Session()
        self.status = ConnectionStatus.DISCONNECTED

        # Set up base URL and timeout
        self.base_url = config.api_base_url
        self.timeout = config.http.get("timeout", 30)

        # Set up authentication
        self._setup_auth()

    def _setup_auth(self) -> None:
        """Set up authentication"""
        auth = self.config.auth

        if auth["type"] == "api_key":
            self.session.headers.update({"x-api-key": auth["api_key"]})
        elif auth["type"] == "oauth2":
            # OAuth2 token will be fetched and refreshed automatically
            raise NotImplementedError("OAuth2 authentication not yet implemented")
        else:
            raise EdgeOpsAuthError("HTTP client requires api_key or oauth2 authentication")

    def connect(self) -> None:
        """Test connection by sending a heartbeat"""
        try:
            self.send_heartbeat()
            self.status = ConnectionStatus.CONNECTED
        except Exception as error:
            self.status = ConnectionStatus.ERROR
            raise EdgeOpsConnectionError(f"Failed to connect: {error}") from error

    def disconnect(self) -> None:
        """Disconnect (close session)"""
        self.session.close()
        self.status = ConnectionStatus.DISCONNECTED

    def publish_telemetry(self, message: TelemetryMessage) -> None:
        """Publish telemetry via HTTP"""
        if self.status != ConnectionStatus.CONNECTED:
            raise EdgeOpsConnectionError("HTTP client not connected")

        try:
            url = f"{self.base_url}/api/devices/{self.config.device_id}/data"
            response = self.session.post(url, json=message, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            if error.response.status_code in (401, 403):
                raise EdgeOpsAuthError("Authentication failed", {"response": error.response.text}) from error
            raise EdgeOpsConnectionError(f"Failed to publish telemetry: {error}") from error
        except Exception as error:
            raise EdgeOpsConnectionError(f"Failed to publish telemetry: {error}") from error

    def publish_telemetry_batch(self, messages: list[TelemetryMessage]) -> None:
        """Publish batch of telemetry messages"""
        for message in messages:
            self.publish_telemetry(message)

    def update_shadow(self, reported: Dict[str, Any]) -> None:
        """Update device shadow via HTTP"""
        # HTTP doesn't support shadow updates directly
        # We can use the device data endpoint with a special flag
        self.publish_telemetry({"data": {"_shadow": {"reported": reported}}})

    def get_shadow(self) -> DeviceShadow:
        """Get device shadow via HTTP"""
        try:
            url = f"{self.base_url}/api/devices/provision"
            params = {"deviceId": self.config.device_id}
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("shadow", {"state": {}})
        except Exception as error:
            raise EdgeOpsConnectionError(f"Failed to get shadow: {error}") from error

    def send_heartbeat(self, data: Optional[Dict[str, Any]] = None) -> None:
        """Send heartbeat via HTTP"""
        try:
            url = f"{self.base_url}/api/devices/{self.config.device_id}/heartbeat"
            payload = {"timestamp": self._get_timestamp(), **(data or {})}
            response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            if error.response.status_code in (401, 403):
                raise EdgeOpsAuthError("Authentication failed", {"response": error.response.text}) from error
            raise EdgeOpsConnectionError(f"Failed to send heartbeat: {error}") from error
        except Exception as error:
            raise EdgeOpsConnectionError(f"Failed to send heartbeat: {error}") from error

    def _get_timestamp(self) -> str:
        """Get ISO 8601 timestamp"""
        try:
            from datetime import datetime, timezone
            return datetime.now(timezone.utc).isoformat()
        except ImportError:
            import time
            return f"{time.time()}"
