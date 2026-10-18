"""Tests agent queue — bounded, dedup, ack (reproductible, non-destructif)."""
import tempfile
import pathlib
import json
from agent.sentinel_agent.queue import BoundedQueue


def test_bounded_queue_basic():
    with tempfile.TemporaryDirectory() as td:
        q = BoundedQueue(str(pathlib.Path(td) / "queue.jsonl"), max_events=5, max_bytes=1024*1024)
        assert q.size() == 0
        q.append({"seq": 1, "a": 1})
        assert q.size() == 1
        batch = q.load_batch(10)
        assert len(batch) == 1
        q.ack(1)
        assert q.size() == 0


def test_dedup_local():
    with tempfile.TemporaryDirectory() as td:
        q = BoundedQueue(str(pathlib.Path(td) / "queue.jsonl"), max_events=10)
        ev = {"detail": "same", "ts": "2026-01-01"}
        q.append(ev)
        q.append(ev)  # duplicate → not added
        assert q.size() == 1


def test_fifo_evict_when_full():
    with tempfile.TemporaryDirectory() as td:
        q = BoundedQueue(str(pathlib.Path(td) / "queue.jsonl"), max_events=3)
        for i in range(5):
            q.append({"seq": i})
        assert q.size() == 3
        batch = q.load_batch(10)
        # Should keep last 3
        assert batch[0]["seq"] == 2
