"""
ProbeTransport — Thread-safe USB CDC JSON protocol for the ICS probe.

This is the Python equivalent of library/user/ics/lib/esp32.sh. It owns
the serial connection to the ESP32, sends JSON commands, and returns JSON
responses. Multiple protocol adapters share one ProbeTransport instance
via its threading.Lock.
"""
import glob
import json
import logging
import threading
import time

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0


class ProbeTransport:
    """Thread-safe interface to the ICS probe over USB CDC serial."""

    def __init__(self, dev_path=None, timeout=DEFAULT_TIMEOUT):
        self._lock = threading.Lock()
        self._dev_path = dev_path
        self._timeout = timeout
        self._fw_version = None
        self._hardware = {}

        if self._dev_path is None:
            self._dev_path = self._detect()

    def is_connected(self):
        return self._dev_path is not None

    @property
    def firmware_version(self):
        return self._fw_version

    @property
    def hardware_status(self):
        return dict(self._hardware)

    def _detect(self):
        """Scan /dev/ttyACM* for a responding ICS probe."""
        for dev in sorted(glob.glob("/dev/ttyACM*")):
            try:
                resp = self._raw_send(dev, "probe.info", {}, timeout=2.0)
                if resp.get("status") == "ok":
                    self._fw_version = resp.get("fw_version")
                    self._hardware = resp.get("hardware", {})
                    logger.info("Probe detected: %s (firmware %s)", dev, self._fw_version)
                    return dev
            except Exception as e:
                logger.debug("Probe not at %s: %s", dev, e)
        logger.warning("No ICS probe detected")
        return None

    def send_command(self, cmd, params=None, cmd_id=None, timeout=None):
        """Send a JSON command to the probe and return the parsed response.

        Thread-safe — acquires the internal lock before accessing the serial
        device, so multiple adapters can call this concurrently.
        """
        if not self._dev_path:
            return {"status": "error", "error": "no_device"}

        if params is None:
            params = {}
        if cmd_id is None:
            cmd_id = str(int(time.time() * 1000))
        if timeout is None:
            timeout = self._timeout

        with self._lock:
            try:
                return self._raw_send(self._dev_path, cmd, params, cmd_id, timeout)
            except Exception as e:
                logger.error("Probe command failed: %s — %s", cmd, e)
                return {"status": "error", "error": str(e)}

    def _raw_send(self, dev_path, cmd, params, cmd_id=None, timeout=DEFAULT_TIMEOUT):
        """Low-level send/receive. Caller must hold the lock."""
        request = {"cmd": cmd, "params": params}
        if cmd_id:
            request["id"] = cmd_id

        request_line = json.dumps(request, separators=(",", ":")) + "\n"

        with open(dev_path, "w") as f:
            f.write(request_line)
            f.flush()

        deadline = time.monotonic() + timeout
        with open(dev_path, "r") as f:
            while time.monotonic() < deadline:
                line = f.readline()
                if line.strip():
                    return json.loads(line.strip())
                time.sleep(0.01)

        return {"status": "error", "error": "timeout"}

    def reconnect(self):
        """Attempt to re-detect the probe (e.g., after USB replug)."""
        self._dev_path = self._detect()
        return self.is_connected()
