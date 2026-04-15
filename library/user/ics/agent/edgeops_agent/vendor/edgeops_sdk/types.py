"""
Type definitions for EdgeOps SDK
"""

from typing import Dict, Any, Optional, Union, Literal, Callable
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

# Try to use typing_extensions for older Python versions
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict

AuthType = Literal["certificate", "api_key", "oauth2"]


class CertificateAuth(TypedDict):
    type: Literal["certificate"]
    certificate: Union[str, bytes]  # PEM certificate (file path or content)
    private_key: Union[str, bytes]  # PEM private key (file path or content)
    root_ca: Union[str, bytes]  # Root CA certificate (file path or content)
    iot_endpoint: Optional[str]  # AWS IoT endpoint (optional)


class ApiKeyAuth(TypedDict):
    type: Literal["api_key"]
    api_key: str


class OAuth2Auth(TypedDict):
    type: Literal["oauth2"]
    client_id: str
    client_secret: str
    token_url: str
    scope: Optional[str]


AuthConfig = Union[CertificateAuth, ApiKeyAuth, OAuth2Auth]


@dataclass
class EdgeOpsConfig:
    api_base_url: str  # e.g., 'https://api.edgeops.cloud'
    device_id: str
    organization_id: Optional[str] = None  # Optional, can be inferred from device_id
    auth: AuthConfig = None
    mqtt: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    telemetry: Optional[Dict[str, Any]] = None
    heartbeat: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.mqtt is None:
            self.mqtt = {}
        if self.http is None:
            self.http = {}
        if self.telemetry is None:
            self.telemetry = {}
        if self.heartbeat is None:
            self.heartbeat = {}


class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


TelemetryData = Dict[str, Any]


class TelemetryMessage(TypedDict, total=False):
    timestamp: str  # ISO 8601 timestamp (auto-generated if not provided)
    data: TelemetryData
    metadata: Optional[Dict[str, Any]]  # Data quality, source, etc.


class DeviceShadow(TypedDict, total=False):
    state: Dict[str, Any]  # Contains 'desired' and 'reported' keys
    metadata: Optional[Dict[str, Any]]
    version: Optional[int]
    timestamp: Optional[int]


class Command(TypedDict):
    command_id: str
    command_type: str
    payload: Dict[str, Any]
    timestamp: str


CommandHandler = Callable[[Command], None]


class HeartbeatData(TypedDict, total=False):
    timestamp: str
    rssi: Optional[int]  # WiFi signal strength
    uptime: Optional[int]  # Uptime in seconds
    free_memory: Optional[int]  # Free memory in bytes
    cpu_usage: Optional[float]  # CPU usage percentage


class DeviceProvisioningRequest(TypedDict, total=False):
    device_name: str
    device_type: Literal["edge-gateway", "plc", "sensor", "actuator"]
    metadata: Optional[Dict[str, Any]]


class DeviceProvisioningResponse(TypedDict):
    device: Dict[str, Any]
    provisioning: Dict[str, Any]
    instructions: Dict[str, Any]
