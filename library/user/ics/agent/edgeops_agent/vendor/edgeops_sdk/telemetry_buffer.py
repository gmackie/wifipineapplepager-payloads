"""
Telemetry Buffer - Handles offline message buffering and batching
"""

from typing import List, Optional, Callable
from .types import TelemetryMessage


class TelemetryBuffer:
    """Buffer for telemetry messages when offline"""

    def __init__(self, max_size: int = 1000, batch_size: int = 10, batch_interval: float = 5.0):
        self.max_size = max_size
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.buffer: List[TelemetryMessage] = []
        self.on_flush: Optional[callable] = None

        # Start batch timer
        self._start_batch_timer()

    def add(self, message: TelemetryMessage) -> None:
        """Add message to buffer"""
        # Remove oldest messages if buffer is full
        if len(self.buffer) >= self.max_size:
            self.buffer.pop(0)

        self.buffer.append(message)

        # Flush if batch size reached
        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> List[TelemetryMessage]:
        """Flush buffer and return messages"""
        messages = self.buffer[: self.batch_size]
        self.buffer = self.buffer[self.batch_size :]

        if messages and self.on_flush:
            self.on_flush(messages)

        return messages

    def clear(self) -> None:
        """Clear buffer"""
        self.buffer = []

    def get_size(self) -> int:
        """Get current buffer size"""
        return len(self.buffer)

    def is_full(self) -> bool:
        """Check if buffer is full"""
        return len(self.buffer) >= self.max_size

    def _start_batch_timer(self) -> None:
        """Start batch timer"""
        try:
            import threading
            timer = threading.Timer(self.batch_interval, self._on_batch_timer)
            timer.start()
        except ImportError:
            # MicroPython/CircuitPython - use alternative timer
            pass

    def _on_batch_timer(self) -> None:
        """Handle batch timer"""
        if self.buffer:
            self.flush()
        self._start_batch_timer()
