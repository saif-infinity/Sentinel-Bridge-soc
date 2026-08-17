"""F1/R13 — Corrélateur fenêtré PERSISTANT : séquences et agrégats (count).

L'état vit dans la table `correlation_state` (au lieu d'un deque in-memory) :
les fenêtres de séquence et les compteurs de seuil survivent au restart.

Sémantique conservée : sequence, require_same_src/dest, window_seconds.
Nouveau (R13) : correlation.count (seuil) + correlation.threshold_window_seconds
(défaut = window_seconds) — la règle ne déclenche qu'après `count` matches
dans la fenêtre.

Le corrélateur utilise SA PROPRE session (jamais celle du moteur) : les commits
d'état n'expirent pas les objets Rule mis en cache par engine.py.
"""
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from ...db import SessionLocal
from ...domain.rule_models import CorrelationState
from .evaluator import evaluate_conditions

logger = logging.getLogger(__name__)


def _ts_of(normalized: Dict[str, Any], fallback: float) -> float:
    ts = normalized.get("timestamp")
    if ts:
        try:
            from dateutil import parser as _dp
            return _dp.isoparse(ts).timestamp()
        except Exception:
            return fallback
    return fallback


def _naive(ts: float) -> datetime:
    """Epoch -> datetime UTC aware (PostgreSQL TIMESTAMPTZ ; SQLite ignore le tz)."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _is_postgresql(db) -> bool:
    """True si le dialecte courant est PostgreSQL (row-locking FOR UPDATE supporté)."""
    try:
        return db.get_bind().dialect.name == "postgresql"
    except Exception:
        return False


def _for_update(db, query):
    """Ajoute SELECT ... FOR UPDATE (PostgreSQL) au query ; no-op sur SQLite (tests)."""
    if _is_postgresql(db):
        return query.with_for_update()
    return query


def _delete_expired(db, *filters) -> None:
    """DELETE des lignes expirées ; sur PostgreSQL verrouille d'abord (FOR UPDATE)
    pour éviter les purges concurrentes, puis supprime ligne à ligne."""
    query = db.query(CorrelationState).filter(*filters)
    if _is_postgresql(db):
        for row in query.with_for_update().all():
            db.delete(row)
    else:
        query.delete(synchronize_session=False)


class WindowedCorrelator:
    def __init__(self):
        self._lock = threading.RLock()

    def clear(self) -> None:
        db = SessionLocal()
        try:
            db.query(CorrelationState).delete()
            db.commit()
        except Exception as e:
            logger.warning("Correlator clear échoué: %s", e)
        finally:
            db.close()

    def push(self, normalized: Dict[str, Any]) -> None:
        """Rétro-compat : la persistance est assurée par evaluate() lui-même."""
        return None

    def evaluate(self, rule: Any, normalized: Dict[str, Any],
                 conditions: List[Dict[str, Any]]) -> bool:
        """True si l'événement courant déclenche la corrélation du rule.

        rule.correlation (JSON) :
          {"window_seconds": int, "sequence": [indices...],
           "require_same_src": bool, "require_same_dest": bool,
           "count": int, "threshold_window_seconds": int}
        """
        try:
            corr = json.loads(rule.correlation or "{}")
        except (TypeError, ValueError):
            corr = {}
        if not corr:
            return False
        if corr.get("count"):
            return self._evaluate_count(rule, corr, normalized, conditions)
        return self._evaluate_sequence(rule, corr, normalized, conditions)

    # ── Agrégat (count / threshold_window_seconds) ────────────────────
    def _evaluate_count(self, rule, corr, normalized, conditions) -> bool:
        try:
            threshold = int(corr.get("count"))
            window = int(corr.get("threshold_window_seconds") or corr.get("window_seconds") or 60)
        except (TypeError, ValueError):
            return False
        if threshold < 1 or window < 1:
            return False
        matched = evaluate_conditions(conditions, normalized)
        if not conditions or len(matched) < len(conditions):
            return False

        db = SessionLocal()
        try:
            now = _ts_of(normalized, time.time())
            tenant = normalized.get("tenant_id", "default")
            src = normalized.get("src_ip")
            dst = normalized.get("dest_ip")
            bucket = int(now // window)
            key = f"{rule.id}"
            if corr.get("require_same_src"):
                key += f"|{src}"
            if corr.get("require_same_dest"):
                key += f"|{dst}"
            key += f"|{bucket}"

            # purge des fenêtres expirées de cette règle (même tenant)
            cutoff = _naive(time.time() - window)
            _delete_expired(
                db,
                CorrelationState.kind == "count",
                CorrelationState.rule_id == rule.id,
                CorrelationState.tenant_id == tenant,
                CorrelationState.window_end < cutoff,
            )

            # lecture verrouillée (PostgreSQL) : incrément + seuil + delete dans le
            # même contexte transactionnel pour éviter le double-fire concurrent.
            row = _for_update(
                db,
                db.query(CorrelationState)
                .filter(CorrelationState.kind == "count",
                        CorrelationState.rule_id == rule.id,
                        CorrelationState.tenant_id == tenant,
                        CorrelationState.correlation_key == key),
            ).first()
            if row is None:
                row = CorrelationState(
                    tenant_id=tenant,
                    rule_id=rule.id,
                    kind="count",
                    correlation_key=key,
                    window_start=_naive(bucket * window),
                    window_end=_naive((bucket + 1) * window),
                    count=0,
                    payload="{}",
                )
                db.add(row)
            row.count = (row.count or 0) + 1
            row.payload = json.dumps({
                "matched_conditions": matched,
                "alert_id": normalized.get("alert_id"),
            }, ensure_ascii=False, default=str)
            if row.count >= threshold:
                # fenêtre consommée : réinitialise pour la prochaine fenêtre
                db.delete(row)
                db.commit()
                return True
            db.commit()
            return False
        finally:
            db.close()

    # ── Séquence (window_seconds / sequence / require_same_src|dest) ──
    def _evaluate_sequence(self, rule, corr, normalized, conditions) -> bool:
        try:
            window = int(corr.get("window_seconds", 60))
            sequence = [int(i) for i in (corr.get("sequence") or [])]
        except (TypeError, ValueError):
            return False
        if len(sequence) < 2:
            return False

        matched = evaluate_conditions(conditions, normalized)
        if not matched:
            return False
        last_idx = sequence[-1]

        db = SessionLocal()
        try:
            tenant = normalized.get("tenant_id", "default")
            src = normalized.get("src_ip")
            dst = normalized.get("dest_ip")
            ev_ts = _ts_of(normalized, time.time())
            ev_naive = _naive(ev_ts)
            seq_key = f"{rule.id}"
            if corr.get("require_same_src"):
                seq_key += f"|{src}"
            if corr.get("require_same_dest"):
                seq_key += f"|{dst}"

            # purge des événements/fired expirés de cette règle (même tenant)
            cutoff = _naive(time.time() - window)
            _delete_expired(
                db,
                CorrelationState.kind == "sequence_event",
                CorrelationState.rule_id == rule.id,
                CorrelationState.tenant_id == tenant,
                CorrelationState.window_start < cutoff,
            )
            _delete_expired(
                db,
                CorrelationState.kind == "sequence_fired",
                CorrelationState.rule_id == rule.id,
                CorrelationState.tenant_id == tenant,
                CorrelationState.window_end < cutoff,
            )

            # enregistre l'événement courant (satisfait ≥1 étape de la séquence)
            ev_row = CorrelationState(
                tenant_id=tenant,
                rule_id=rule.id,
                kind="sequence_event",
                correlation_key=seq_key,
                window_start=ev_naive,
                window_end=ev_naive + timedelta(seconds=window),
                count=0,
                payload=json.dumps(normalized, ensure_ascii=False, default=str),
            )
            db.add(ev_row)
            db.flush()

            # l'événement ne complète pas la séquence : il reste enregistré
            # pour les étapes futures.
            if last_idx not in matched:
                db.commit()
                return False

            # anti re-fire : même sémantique que l'ancien fire_key (règle|src|dst|bucket)
            bucket = int(ev_ts // window)
            fire_key = f"{rule.id}|{src}|{dst}|{bucket}"
            fired = (
                db.query(CorrelationState)
                .filter(CorrelationState.kind == "sequence_fired",
                        CorrelationState.rule_id == rule.id,
                        CorrelationState.tenant_id == tenant,
                        CorrelationState.correlation_key == fire_key)
                .first()
            )
            if fired is not None:
                db.commit()
                return False

            # marche arrière sur la séquence : chaque étape antérieure doit être
            # satisfaite par un événement persisté dans la fenêtre (même tenant).
            cursor_naive = ev_naive
            for step in reversed(sequence[:-1]):
                found = None
                candidates = (
                    db.query(CorrelationState)
                    .filter(CorrelationState.kind == "sequence_event",
                            CorrelationState.rule_id == rule.id,
                            CorrelationState.tenant_id == tenant,
                            CorrelationState.correlation_key == seq_key,
                            CorrelationState.id != ev_row.id,
                            CorrelationState.window_start < cursor_naive,
                            CorrelationState.window_start >= ev_naive - timedelta(seconds=window))
                    .order_by(CorrelationState.window_start.desc())
                    .all()
                )
                for row in candidates:
                    ev = json.loads(row.payload or "{}")
                    if step not in evaluate_conditions(conditions, ev):
                        continue
                    if corr.get("require_same_src") and ev.get("src_ip") != src:
                        continue
                    if corr.get("require_same_dest") and ev.get("dest_ip") != dst:
                        continue
                    found = row
                    break
                if found is None:
                    db.commit()  # l'événement reste enregistré pour les étapes futures
                    return False
                cursor_naive = found.window_start

            # séquence complète -> marquer fired pour la fenêtre
            db.add(CorrelationState(
                tenant_id=tenant,
                rule_id=rule.id,
                kind="sequence_fired",
                correlation_key=fire_key,
                window_start=_naive(bucket * window),
                window_end=_naive((bucket + 1) * window),
                count=0,
                payload="{}",
            ))
            db.commit()
            return True
        finally:
            db.close()