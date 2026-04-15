"""SQLite-backed telemetry buffer for offline resilience."""
import json
import logging
import sqlite3
import threading

logger = logging.getLogger(__name__)


class SQLiteBuffer:
    """Append-only buffer backed by SQLite. Thread-safe."""

    def __init__(self, db_path=":memory:", max_mb=50):
        self._db_path = db_path
        self._max_bytes = max_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        self._conn.commit()

    def append(self, reading_dict):
        """Append a reading to the buffer."""
        import time
        payload = json.dumps(reading_dict, default=str)
        with self._lock:
            self._conn.execute(
                "INSERT INTO readings (payload, created_at) VALUES (?, ?)",
                (payload, time.time()),
            )
            self._conn.commit()
            self._maybe_evict()

    def flush(self, limit=50):
        """Remove and return up to `limit` oldest readings."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT id, payload FROM readings ORDER BY id ASC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            if not rows:
                return []

            ids = [r[0] for r in rows]
            placeholders = ",".join("?" * len(ids))
            self._conn.execute(
                f"DELETE FROM readings WHERE id IN ({placeholders})", ids
            )
            self._conn.commit()

            return [json.loads(r[1]) for r in rows]

    def pending_count(self):
        """Number of buffered readings."""
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM readings")
            return cursor.fetchone()[0]

    def _maybe_evict(self):
        """Drop oldest readings if DB exceeds max size."""
        if self._max_bytes <= 0:
            return
        # Approximate size check via page_count * page_size
        cursor = self._conn.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor = self._conn.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        db_size = page_count * page_size

        if db_size > self._max_bytes:
            # Delete oldest 10% of rows
            total = self.pending_count()
            delete_count = max(1, total // 10)
            self._conn.execute(
                "DELETE FROM readings WHERE id IN "
                "(SELECT id FROM readings ORDER BY id ASC LIMIT ?)",
                (delete_count,),
            )
            self._conn.commit()
            logger.warning("Buffer evicted %d oldest readings (db_size=%d)", delete_count, db_size)

    def close(self):
        self._conn.close()
