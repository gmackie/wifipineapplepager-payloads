"""
ProtocolAdapter ABC — mirrors the TypeScript ProtocolAdapter interface from
edgeOps/edge/gateway-agent/src/adapters/types.ts.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AdapterConfig:
    type: str
    connection_params: dict = field(default_factory=dict)
    poll_interval_ms: int = 5000
    signals: list = field(default_factory=list)


@dataclass
class SignalConfig:
    signal_id: str
    address: str
    data_type: str = "float32"


@dataclass
class SignalReading:
    signal_id: str
    value: object
    quality: str = "good"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "signalId": self.signal_id,
            "value": self.value,
            "quality": self.quality,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class DiscoveredDevice:
    address: str
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    protocols: list = field(default_factory=list)
    capabilities: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "address": self.address,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmwareVersion": self.firmware_version,
            "protocols": self.protocols,
            "capabilities": self.capabilities,
            "metadata": self.metadata,
        }


@dataclass
class RemoteCommand:
    command_id: str
    type: str
    target: str
    params: dict = field(default_factory=dict)


@dataclass
class CommandResult:
    command_id: str
    success: bool
    error: str = ""
    data: object = None


@dataclass
class AdapterStatus:
    state: str = "idle"
    device_count: int = 0
    last_poll_at: Optional[datetime] = None
    error_message: str = ""


class ProtocolAdapter(ABC):
    """Abstract base for all ICS probe protocol adapters."""

    def __init__(self, name, adapter_type, transport):
        self.name = name
        self.type = adapter_type
        self._transport = transport
        self._status = AdapterStatus()
        self._config = None

    @abstractmethod
    def initialize(self, config):
        ...

    @abstractmethod
    def shutdown(self):
        ...

    @abstractmethod
    def discover(self):
        ...

    @abstractmethod
    def poll(self, signals):
        ...

    @abstractmethod
    def execute(self, command):
        ...

    def get_status(self):
        return self._status
