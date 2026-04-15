#!/usr/bin/env python3
"""Tests for SQLiteBuffer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "library", "user", "ics", "agent"))

from edgeops_agent.buffer import SQLiteBuffer


class TestSQLiteBuffer(unittest.TestCase):

    def test_append_and_flush(self):
        buf = SQLiteBuffer(":memory:", max_mb=1)
        buf.append({"signal_id": "temp", "value": 42, "quality": "good"})
        buf.append({"signal_id": "temp", "value": 43, "quality": "good"})
        batch = buf.flush(limit=10)
        self.assertEqual(len(batch), 2)
        self.assertEqual(batch[0]["signal_id"], "temp")
        self.assertEqual(batch[0]["value"], 42)
        buf.close()

    def test_flush_removes_returned_rows(self):
        buf = SQLiteBuffer(":memory:")
        for i in range(5):
            buf.append({"i": i})
        batch1 = buf.flush(limit=3)
        self.assertEqual(len(batch1), 3)
        self.assertEqual(buf.pending_count(), 2)
        batch2 = buf.flush(limit=10)
        self.assertEqual(len(batch2), 2)
        self.assertEqual(buf.pending_count(), 0)
        buf.close()

    def test_flush_empty_returns_empty_list(self):
        buf = SQLiteBuffer(":memory:")
        self.assertEqual(buf.flush(limit=10), [])
        buf.close()

    def test_pending_count(self):
        buf = SQLiteBuffer(":memory:")
        self.assertEqual(buf.pending_count(), 0)
        buf.append({"a": 1})
        buf.append({"b": 2})
        self.assertEqual(buf.pending_count(), 2)
        buf.close()

    def test_flush_preserves_order(self):
        buf = SQLiteBuffer(":memory:")
        for i in range(10):
            buf.append({"seq": i})
        batch = buf.flush(limit=10)
        seqs = [r["seq"] for r in batch]
        self.assertEqual(seqs, list(range(10)))
        buf.close()

    def test_limit_respected(self):
        buf = SQLiteBuffer(":memory:")
        for i in range(20):
            buf.append({"i": i})
        batch = buf.flush(limit=5)
        self.assertEqual(len(batch), 5)
        self.assertEqual(buf.pending_count(), 15)
        buf.close()


if __name__ == "__main__":
    unittest.main()
