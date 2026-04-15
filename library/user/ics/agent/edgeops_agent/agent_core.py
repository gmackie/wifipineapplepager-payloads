"""Agent core — poll loop, buffer management, cloud connection."""
import logging
import sys
import os
import threading
import time

# Add vendored SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vendor"))

from .config import load_config, AgentConfig
from .probe_transport import ProbeTransport
from .buffer import SQLiteBuffer
from .adapters import ADAPTER_REGISTRY
from .adapters.base import AdapterConfig, SignalConfig

logger = logging.getLogger(__name__)


class AgentCore:
    """Orchestrates probe communication, adapter polling, and cloud telemetry."""

    def __init__(self, config_path=None):
        self.config = load_config(config_path)
        self.transport = ProbeTransport()
        self.buffer = SQLiteBuffer(
            db_path=self.config.buffer_db_path,
            max_mb=self.config.buffer_max_mb,
        )
        self.adapters = []
        self.client = None
        self._running = False
        self._poll_thread = None
        self._flush_thread = None

    def start(self):
        """Initialize adapters, start poll loop, connect to cloud."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper(), logging.INFO),
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )

        if not self.transport.is_connected():
            logger.error("ICS probe not detected — starting in degraded mode")

        self._init_adapters()
        self._init_cloud_client()

        self._running = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="poll")
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="flush")
        self._poll_thread.start()
        self._flush_thread.start()

        logger.info("Agent started — %d adapter(s), poll every %dms",
                     len(self.adapters), self.config.poll_interval_ms)

        self._write_status("running")

    def stop(self):
        """Graceful shutdown."""
        logger.info("Agent stopping")
        self._running = False

        for adapter in self.adapters:
            try:
                adapter.shutdown()
            except Exception as e:
                logger.warning("Adapter %s shutdown error: %s", adapter.name, e)

        if self.client:
            try:
                self.client.disconnect()
            except Exception:
                pass

        self.buffer.close()
        self._write_status("stopped")
        logger.info("Agent stopped")

    def _init_adapters(self):
        """Create and initialize protocol adapters from config."""
        for adapter_cfg in self.config.adapters:
            adapter_type = adapter_cfg.get("type", "")
            cls = ADAPTER_REGISTRY.get(adapter_type)
            if cls is None:
                logger.warning("Unknown adapter type: %s — skipping", adapter_type)
                continue

            adapter = cls(self.transport)
            config = AdapterConfig(
                type=adapter_type,
                connection_params=adapter_cfg.get("connection_params", {}),
                poll_interval_ms=adapter_cfg.get("poll_interval_ms", self.config.poll_interval_ms),
                signals=[
                    SignalConfig(
                        signal_id=s.get("signal_id", ""),
                        address=s.get("address", ""),
                        data_type=s.get("data_type", "float32"),
                    )
                    for s in adapter_cfg.get("signals", [])
                ],
            )

            try:
                adapter.initialize(config)
                adapter._config = config
                self.adapters.append(adapter)
                logger.info("Adapter %s initialized (%d signals)",
                           adapter.name, len(config.signals))
            except Exception as e:
                logger.error("Adapter %s init failed: %s", adapter_type, e)

    def _init_cloud_client(self):
        """Connect to Controls Foundry via the EdgeOps Python SDK."""
        if not self.config.device_id:
            logger.warning("No device_id — running in local-only mode")
            return

        try:
            from edgeops_sdk import EdgeOpsClient
            from edgeops_sdk.types import EdgeOpsConfig, ApiKeyAuth, CertificateAuth

            if self.config.auth_type == "certificate":
                auth = CertificateAuth(
                    type="certificate",
                    certificate=self.config.certificate_path,
                    private_key=self.config.private_key_path,
                    root_ca=self.config.root_ca_path,
                    iot_endpoint=self.config.iot_endpoint,
                )
            else:
                auth = ApiKeyAuth(
                    type="api_key",
                    api_key=self.config.api_key,
                )

            sdk_config = EdgeOpsConfig(
                api_base_url=self.config.api_base_url,
                device_id=self.config.device_id,
                auth=auth,
            )

            self.client = EdgeOpsClient(sdk_config)
            self.client.connect()
            logger.info("Connected to Controls Foundry as %s", self.config.device_id)
        except ImportError:
            logger.warning("EdgeOps SDK not available — running in local-only mode")
        except Exception as e:
            logger.error("Cloud connection failed: %s — running in local-only mode", e)

    def _poll_loop(self):
        """Poll all adapters on schedule."""
        while self._running:
            for adapter in self.adapters:
                if not self._running:
                    break
                try:
                    signals = adapter._config.signals if adapter._config else []
                    if not signals:
                        continue
                    readings = adapter.poll(signals)
                    for r in readings:
                        self.buffer.append(r.to_dict())
                except Exception as e:
                    logger.error("Poll error on %s: %s", adapter.name, e)

            self._write_status("running")
            time.sleep(self.config.poll_interval_ms / 1000.0)

    def _flush_loop(self):
        """Flush buffered readings to the cloud."""
        while self._running:
            try:
                batch = self.buffer.flush(limit=50)
                if batch and self.client:
                    self.client.publish_telemetry({"readings": batch})
                    logger.debug("Flushed %d readings to cloud", len(batch))
            except Exception as e:
                logger.warning("Flush error: %s", e)

            time.sleep(self.config.flush_interval_s)

    def _write_status(self, state):
        """Write status to /tmp for the DuckyScript UI to read."""
        import json
        status = {
            "state": state,
            "probe_connected": self.transport.is_connected(),
            "probe_firmware": self.transport.firmware_version,
            "cloud_connected": self.client is not None,
            "device_id": self.config.device_id,
            "adapter_count": len(self.adapters),
            "buffer_pending": self.buffer.pending_count() if state != "stopped" else 0,
            "adapters": [
                {"name": a.name, "type": a.type, "state": a.get_status().state}
                for a in self.adapters
            ],
        }
        try:
            with open("/tmp/edgeops-status.json", "w") as f:
                json.dump(status, f)
        except Exception:
            pass
