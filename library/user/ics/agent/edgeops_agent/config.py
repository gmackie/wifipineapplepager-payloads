"""Configuration loader for the EdgeOps pager agent."""
import json
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/root/edgeops/agent-config.json"
DEFAULT_POLL_INTERVAL_MS = 5000
DEFAULT_BUFFER_MAX_MB = 50
DEFAULT_FLUSH_INTERVAL_S = 5


@dataclass
class AgentConfig:
    device_id: str = ""
    api_base_url: str = "https://api.edgeops.cloud"
    auth_type: str = "api_key"
    api_key: str = ""
    certificate_path: str = ""
    private_key_path: str = ""
    root_ca_path: str = ""
    iot_endpoint: str = ""
    poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS
    flush_interval_s: int = DEFAULT_FLUSH_INTERVAL_S
    buffer_max_mb: int = DEFAULT_BUFFER_MAX_MB
    buffer_db_path: str = "/root/edgeops/buffer.db"
    adapters: list = field(default_factory=list)
    log_level: str = "info"


def load_config(config_path=None):
    """Load config from file, falling back to env vars."""
    if config_path is None:
        config_path = os.environ.get("EDGEOPS_CONFIG_PATH", DEFAULT_CONFIG_PATH)

    config = AgentConfig()

    # Try file first
    if os.path.exists(config_path):
        logger.info("Loading config from %s", config_path)
        with open(config_path, "r") as f:
            data = json.load(f)

        config.device_id = data.get("device_id", config.device_id)
        config.api_base_url = data.get("api_base_url", config.api_base_url)
        config.poll_interval_ms = data.get("poll_interval_ms", config.poll_interval_ms)
        config.flush_interval_s = data.get("flush_interval_s", config.flush_interval_s)
        config.buffer_max_mb = data.get("buffer_max_mb", config.buffer_max_mb)
        config.buffer_db_path = data.get("buffer_db_path", config.buffer_db_path)
        config.log_level = data.get("log_level", config.log_level)
        config.adapters = data.get("adapters", [])

        auth = data.get("auth", {})
        config.auth_type = auth.get("type", "api_key")
        config.api_key = auth.get("api_key", "")
        config.certificate_path = auth.get("certificate", "")
        config.private_key_path = auth.get("private_key", "")
        config.root_ca_path = auth.get("root_ca", "")
        config.iot_endpoint = auth.get("iot_endpoint", "")
    else:
        logger.info("No config file at %s, falling back to env vars", config_path)

    # Env var overrides
    config.device_id = os.environ.get("EDGEOPS_DEVICE_ID", config.device_id)
    config.api_base_url = os.environ.get("EDGEOPS_API_BASE_URL", config.api_base_url)
    config.api_key = os.environ.get("EDGEOPS_API_KEY", config.api_key)
    config.log_level = os.environ.get("EDGEOPS_LOG_LEVEL", config.log_level)

    if not config.device_id:
        logger.warning("No device_id configured — agent will not connect to cloud")

    return config
