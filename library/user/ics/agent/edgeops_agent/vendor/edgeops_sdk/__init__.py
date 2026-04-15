"""
EdgeOps SDK for Python

Provides a simple interface for devices to connect to EdgeOps Cloud platform
via MQTT (AWS IoT Core) or HTTP REST API.

Compatible with:
- CPython 3.7+
- MicroPython (with limitations)
- CircuitPython (with limitations)
"""

from .client import EdgeOpsClient
from .types import (
    EdgeOpsConfig,
    AuthConfig,
    CertificateAuth,
    ApiKeyAuth,
    OAuth2Auth,
    TelemetryData,
    TelemetryMessage,
    DeviceShadow,
    Command,
    ConnectionStatus,
)
from .errors import (
    EdgeOpsError,
    EdgeOpsConnectionError,
    EdgeOpsAuthError,
    EdgeOpsProvisioningError,
)
from .provisioning import (
    ProvisioningOptions,
    provision_device,
    provision_and_create_config,
    create_config_from_provisioning,
    get_device_status,
)

__version__ = "0.1.0"
__all__ = [
    "EdgeOpsClient",
    "EdgeOpsConfig",
    "AuthConfig",
    "CertificateAuth",
    "ApiKeyAuth",
    "OAuth2Auth",
    "TelemetryData",
    "TelemetryMessage",
    "DeviceShadow",
    "Command",
    "ConnectionStatus",
    "EdgeOpsError",
    "EdgeOpsConnectionError",
    "EdgeOpsAuthError",
    "EdgeOpsProvisioningError",
    "ProvisioningOptions",
    "provision_device",
    "provision_and_create_config",
    "create_config_from_provisioning",
    "get_device_status",
]
