"""File locale bornée — JSONL, reprise après coupure, déduplication simple."""
import hashlib
import json
import pathlib
import time
import os


def _event_hash(event: dict) -> str:
    """Hash pour déduplication locale (évite d'envoyer 2x le même event dans le même batch)."""
    canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class BoundedQueue:
    """
    Queue fichier JSONL bornée (max_events, max_bytes).
    - append(event): ajoute si pas déjà présent dans le batch + respecte bornes
    - load_batch(n): lit n premiers événements
    - ack(seq): supprime jusqu'à seq (appelé après ack serveur)
    - persist / recover
    """
    def __init__(self, path: str, max_events: int = 5000, max_bytes: int = 20 * 1024 * 1024):
        self.path = pathlib.Path(path)
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        self._seen_hashes = set()

    def size(self) -> int:
        try:
            return sum(1 for _ in open(self.path, encoding="utf-8") if _.strip())
        except Exception:
            return 0

    def bytes_used(self) -> int:
        try:
            return self.path.stat().st_size
        except Exception:
            return 0

    def append(self, event: dict) -> bool:
        """Append avec déduplication locale. Retourne True si ajouté."""
        h = _event_hash(event)
        if h in self._seen_hashes:
            return False
        # Check bornes
        if self.size() >= self.max_events:
            # Evict oldest (FIFO)
            self._evict_one()
        if self.bytes_used() >= self.max_bytes:
            self._evict_one()
        line = json.dumps(event, ensure_ascii=False, default=str)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._seen_hashes.add(h)
        # keep bounded in memory too
        if len(self._seen_hashes) > 10000:
            self._seen_hashes.clear()
        return True

    def append_many(self, events: list[dict]) -> int:
        added = 0
        for ev in events:
            if self.append(ev):
                added += 1
        return added

    def load_batch(self, n: int) -> list[dict]:
        out = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
                    if len(out) >= n:
                        break
        except FileNotFoundError:
            pass
        return out

    def ack(self, n: int) -> int:
        """Supprime les n premiers événements (après ack serveur)."""
        if n <= 0:
            return 0
        try:
            lines = open(self.path, "r", encoding="utf-8").read().splitlines()
        except FileNotFoundError:
            return 0
        remaining = lines[n:]
        self.path.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
        self._seen_hashes.clear()
        return min(n, len(lines))

    def ack_seq(self, ack_seq: int, current_seq: int) -> int:
        """Compat: ack via seq — pour l'instant on ack tout le batch si ack_seq >= current_seq."""
        # If server returns ack_seq >= seq we sent, we can clear the batch we just sent.
        # Simplified: caller tracks batch size and calls ack(batch_size) when ack_seq ok.
        return 0

    def _evict_one(self):
        try:
            lines = open(self.path, "r", encoding="utf-8").read().splitlines()
            if lines:
                remaining = lines[1:]
                self.path.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
        except Exception:
            pass

    def clear(self):
        self.path.write_text("", encoding="utf-8")
        self._seen_hashes.clear()
