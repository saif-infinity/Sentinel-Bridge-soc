"""F1 — Corrélateur fenêtré : séquences de conditions sur une fenêtre temporelle (in-memory)."""
import json
import logging
import threading
import time
from collections import deque
from typing import Any, Dict, List

from .evaluator import evaluate_conditions

logger = logging.getLogger(__name__)


class WindowedCorrelator:
    def __init__(self, maxlen: int = 2000):
        self._events: deque = deque(maxlen=maxlen)
        self._fired: Dict[str, float] = {}   # correlation_key -> timestamp (TTL = fenêtre)
        self._lock = threading.RLock()

    def push(self, normalized: Dict[str, Any]) -> None:
        with self._lock:
            self._events.append(normalized)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._fired.clear()

    def evaluate(self, rule: Any, normalized: Dict[str, Any],
                 conditions: List[Dict[str, Any]]) -> bool:
        """True si l'événement courant COMPLÈTE la séquence du rule.

        rule.correlation (JSON) : {"window_seconds": int, "sequence": [indices...],
                                   "require_same_src": bool, "require_same_dest": bool}
        """
        try:
            corr = json.loads(rule.correlation or "{}")
        except (TypeError, ValueError):
            corr = {}
        if not corr:
            return False
        try:
            window = int(corr.get("window_seconds", 60))
            sequence = [int(i) for i in (corr.get("sequence") or [])]
        except (TypeError, ValueError):
            return False
        if len(sequence) < 2:
            return False

        last_idx = sequence[-1]
        if last_idx not in evaluate_conditions(conditions, normalized):
            return False

        now = time.time()
        with self._lock:
            # purge des fire keys expirées
            stale = [k for k, ts in self._fired.items() if now - ts > window]
            for k in stale:
                del self._fired[k]

            src = normalized.get("src_ip")
            dst = normalized.get("dest_ip")
            bucket = int(now // window)
            fire_key = f"{rule.id}|{src}|{dst}|{bucket}"
            if fire_key in self._fired:
                return False

            # marche arrière sur la séquence : chaque étape doit être satisfaite
            # par un événement antérieur dans la fenêtre (même tenant)
            cursor_ts = _ts_of(normalized, now)
            for step in reversed(sequence[:-1]):
                found = None
                for ev in reversed(list(self._events)):
                    if ev is normalized:
                        continue
                    if ev.get("tenant_id") != normalized.get("tenant_id"):
                        continue
                    ev_ts = _ts_of(ev, now)
                    if now - ev_ts > window:
                        continue
                    if ev_ts >= cursor_ts:
                        continue
                    if step not in evaluate_conditions(conditions, ev):
                        continue
                    if corr.get("require_same_src") and ev.get("src_ip") != src:
                        continue
                    if corr.get("require_same_dest") and ev.get("dest_ip") != dst:
                        continue
                    found = ev
                    break
                if found is None:
                    return False
                cursor_ts = _ts_of(found, now)

            self._fired[fire_key] = now
            return True


def _ts_of(normalized: Dict[str, Any], fallback: float) -> float:
    ts = normalized.get("timestamp")
    if ts:
        try:
            from dateutil import parser as _dp
            return _dp.isoparse(ts).timestamp()
        except Exception:
            return fallback
    return fallback
