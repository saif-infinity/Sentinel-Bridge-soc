"""F1 — Pipeline d'ingestion bufferisé : ring buffer + dédup/suppression + normalisation.

Point d'entrée unique : ingest_alert(). Consommé par :
  - webhook Suricata / sync Wazuh (autres lanes) → appellent ingest_alert(..., alert_id=id_créé)
  - ingestion manuelle POST /api/pipeline/ingest (crée la ligne si alert_id absent)
  - sweep de rattrapage (rules/engine.run_catch_up_sweep) → re-lit la DB
"""
import hashlib
import json
import logging
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text

from ..db import SessionLocal, engine
from ..domain.models import Alert, SuricataAlert, SystemConfig
from ..domain.pipeline_models import PipelineEvent
from .system_config import get_config_value
from .rules.evaluator import DEFAULT_SEVERITY_MAPPING, build_normalized_alert, normalize_severity

logger = logging.getLogger(__name__)

DEFAULT_PIPELINE_CONFIG = {
    "dedup_window_seconds": "60",
    "buffer_size": "10000",
    "suppress_after": "5",
    "persist_events": "false",
    "severity_mapping": json.dumps(DEFAULT_SEVERITY_MAPPING),
}

PIPELINE_CONFIG_LABELS = {
    "dedup_window_seconds": "Fenêtre de déduplication (secondes)",
    "buffer_size": "Taille du buffer (événements)",
    "suppress_after": "Supprimer après N occurrences dans la fenêtre",
    "persist_events": "Persister les événements en base (pipeline_events)",
    "severity_mapping": "Mapping de sévérité (JSON)",
}


# ── Ring buffer + tracker de dédup + compteurs (in-process) ──────────

class RingBuffer:
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._buf: deque = deque(maxlen=capacity)
        self._lock = threading.RLock()

    def push(self, event: dict):
        with self._lock:
            self._buf.append(event)

    def clear(self):
        with self._lock:
            self._buf.clear()

    def snapshot(self) -> list:
        with self._lock:
            return list(self._buf)

    @property
    def current(self) -> int:
        return len(self._buf)


class DedupTracker:
    def __init__(self):
        self._seen: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def check(self, key: str, window_seconds: int, suppress_after: int) -> str:
        """Retourne "emit" | "deduped" | "suppressed"."""
        now = time.time()
        with self._lock:
            entry = self._seen.get(key)
            if entry is None:
                self._seen[key] = {"first_seen": now, "count": 1}
                return "emit"
            if now - entry["first_seen"] > window_seconds:
                entry["first_seen"] = now
                entry["count"] = 1
                return "emit"
            entry["count"] += 1
            return "suppressed" if entry["count"] > suppress_after else "deduped"

    def prune(self, window_seconds: int) -> int:
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._seen.items() if now - v["first_seen"] > window_seconds]
            for k in stale:
                del self._seen[k]
            return len(stale)

    def clear(self):
        with self._lock:
            self._seen.clear()


_buffer = RingBuffer()
_dedup = DedupTracker()
_stats = {
    "received_total": 0,
    "deduped_total": 0,
    "suppressed_total": 0,
    "emitted_total": 0,
    "rule_matches_total": 0,
    "last_ingest_at": None,
}
_cfg_cache: Dict[str, Any] = {"ts": 0.0, "data": {}}
_CFG_TTL = 30.0


def make_dedup_key(src_ip: Optional[str], dest_ip: Optional[str], signature: Optional[str]) -> str:
    raw = "|".join([str(src_ip or ""), str(dest_ip or ""), str(signature or "")])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── Config (SystemConfig section "pipeline", fallback intégré) ───────

def load_config(db) -> dict:
    now = time.time()
    if now - _cfg_cache["ts"] < _CFG_TTL:
        return _cfg_cache["data"]
    cfg: Dict[str, Any] = {}
    for key, fallback in DEFAULT_PIPELINE_CONFIG.items():
        cfg[key] = get_config_value(db, "pipeline", key, fallback)
    try:
        cfg["severity_mapping"] = json.loads(cfg["severity_mapping"])
    except (TypeError, ValueError):
        cfg["severity_mapping"] = dict(DEFAULT_SEVERITY_MAPPING)
    cfg["dedup_window_seconds"] = max(1, int(float(cfg["dedup_window_seconds"])))
    cfg["buffer_size"] = max(100, int(float(cfg["buffer_size"])))
    cfg["suppress_after"] = max(1, int(float(cfg["suppress_after"])))
    cfg["persist_events"] = str(cfg["persist_events"]).lower() in ("1", "true", "yes", "on")
    _cfg_cache["ts"] = now
    _cfg_cache["data"] = cfg
    return cfg


def ensure_defaults(db, tenant_id: str = "default"):
    """Seed la section 'pipeline' dans SystemConfig (visible dans l'UI settings)."""
    existing = {r.key for r in db.query(SystemConfig).filter(
        SystemConfig.section == "pipeline", SystemConfig.tenant_id == tenant_id).all()}
    for key, value in DEFAULT_PIPELINE_CONFIG.items():
        if key not in existing:
            db.add(SystemConfig(
                section="pipeline", key=key, value=value, is_secret=False,
                label=PIPELINE_CONFIG_LABELS.get(key, key), tenant_id=tenant_id))
    db.commit()


def ensure_columns(engine):
    """ADD COLUMN additif pour tables existantes (create_all ne modifie pas les tables existantes).

    SQLite-safe : vérifie PRAGMA table_info via l'inspecteur avant chaque ALTER.
    """
    inspector = sa_inspect(engine)
    adds = {
        "alerts": [
            ("normalized_severity", "INTEGER DEFAULT 5"),
            ("pipeline_source", "VARCHAR(30)"),
            ("pipeline_processed_at", "TIMESTAMP WITH TIME ZONE"),
        ],
        "suricata_alerts": [
            ("normalized_severity", "INTEGER DEFAULT 5"),
            ("pipeline_source", "VARCHAR(30)"),
            ("pipeline_processed_at", "TIMESTAMP WITH TIME ZONE"),
        ],
    }
    with engine.begin() as conn:
        for table, cols in adds.items():
            if table not in inspector.get_table_names():
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for col, ddl in cols:
                if col in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                    logger.info("Pipeline: colonne ajoutée %s.%s", table, col)
                except Exception as e:
                    logger.warning("Pipeline: ADD COLUMN %s.%s échoué: %s", table, col, e)
                    conn.rollback()


# ── Persistance ─────────────────────────────────────────────────────

def _create_alert_row(db, payload: dict, source: str, normalized_severity: int) -> int:
    ts = payload.get("timestamp")
    try:
        from dateutil import parser as _dp
        ts = _dp.isoparse(ts) if ts else datetime.now(timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)
    processed_at = datetime.now(timezone.utc)
    desc = str(payload.get("description") or payload.get("signature") or "Alerte")[:500]
    if source == "suricata":
        row = SuricataAlert(
            tenant_id=payload.get("tenant_id", "default"),
            timestamp=ts,
            event_type=str(payload.get("category") or "alert")[:50],
            src_ip=str(payload.get("src_ip") or "")[:45] or None,
            dest_ip=str(payload.get("dest_ip") or "")[:45] or None,
            proto=str(payload.get("proto") or "")[:20] or None,
            alert_msg=desc[:255] or None,
            severity=int(payload.get("severity") or 3),
            normalized_severity=normalized_severity,
            pipeline_source=source,
            pipeline_processed_at=processed_at,
            payload=json.dumps(payload.get("raw") or payload, ensure_ascii=False, default=str)[:3000] or None,
        )
    else:
        row = Alert(
            tenant_id=payload.get("tenant_id", "default"),
            timestamp=ts,
            description=desc,
            severity=int(payload.get("severity") or 5),
            src_ip=str(payload.get("src_ip") or "")[:45] or None,
            agent_id=str(payload.get("agent_id") or "")[:10] or None,
            normalized_severity=normalized_severity,
            pipeline_source=source,
            pipeline_processed_at=processed_at,
        )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row.id


def _mark_normalized(db, source: str, alert_id: int, normalized_severity: int):
    model = SuricataAlert if source == "suricata" else Alert
    row = db.query(model).filter(model.id == alert_id).first()
    if row is not None:
        row.normalized_severity = normalized_severity
        row.pipeline_source = source
        row.pipeline_processed_at = datetime.now(timezone.utc)
        db.commit()


def _persist_pipeline_event(db, payload: dict, normalized_severity: int, key: str,
                            deduped: bool = False, alert_id: Optional[int] = None):
    try:
        db.add(PipelineEvent(
            tenant_id=payload.get("tenant_id", "default"),
            source=str(payload.get("source") or "manual")[:30],
            signature=str(payload.get("signature") or payload.get("description") or "")[:255] or None,
            src_ip=str(payload.get("src_ip") or "")[:45] or None,
            dest_ip=str(payload.get("dest_ip") or "")[:45] or None,
            severity=int(payload.get("severity") or 5),
            normalized_severity=normalized_severity,
            dedup_key=key,
            deduped=deduped,
            alert_id=alert_id,
            payload=json.dumps(payload, ensure_ascii=False, default=str)[:4000] or None,
        ))
        db.commit()
    except Exception as e:
        logger.warning("Pipeline: persistance PipelineEvent échouée: %s", e)


# ── Point d'entrée principal ────────────────────────────────────────

def ingest_alert(payload: dict, db=None, alert_id: Optional[int] = None) -> dict:
    """Ingère une alerte. Payload attendu :
    {source, severity, signature, description, src_ip, dest_ip, proto, agent_id,
     category, timestamp, raw, tenant_id}
    Retourne {status: accepted|deduped|suppressed, dedup_key, normalized_severity,
              buffer_size, matched_rules, rule_matches}
    """
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        cfg = load_config(db)
        source = str(payload.get("source") or "manual").lower()
        signature = str(payload.get("signature") or payload.get("description") or "unknown")[:255]
        src_ip = str(payload.get("src_ip") or "")[:45] or None
        dest_ip = str(payload.get("dest_ip") or "")[:45] or None
        mapping = cfg.get("severity_mapping", DEFAULT_SEVERITY_MAPPING)
        normalized_severity = normalize_severity(source, payload.get("severity"), mapping)

        key = make_dedup_key(src_ip, dest_ip, signature)
        verdict = _dedup.check(key, cfg["dedup_window_seconds"], cfg["suppress_after"])

        _stats["received_total"] += 1
        _stats["last_ingest_at"] = datetime.now(timezone.utc).isoformat()

        if verdict == "deduped":
            _stats["deduped_total"] += 1
            if cfg["persist_events"]:
                _persist_pipeline_event(db, payload, normalized_severity, key, deduped=True, alert_id=alert_id)
            return {"status": "deduped", "dedup_key": key,
                    "normalized_severity": normalized_severity, "rule_matches": 0}
        if verdict == "suppressed":
            _stats["suppressed_total"] += 1
            return {"status": "suppressed", "dedup_key": key,
                    "normalized_severity": normalized_severity, "rule_matches": 0}
        _stats["emitted_total"] += 1

        resolved_alert_id = alert_id
        if alert_id is None:
            resolved_alert_id = _create_alert_row(db, payload, source, normalized_severity)
        else:
            _mark_normalized(db, source, alert_id, normalized_severity)

        normalized = build_normalized_alert({
            **payload,
            "alert_id": resolved_alert_id,
            "source": source,
            "normalized_severity": normalized_severity,
        }, mapping)

        _buffer.push(normalized)
        if cfg["persist_events"]:
            _persist_pipeline_event(db, payload, normalized_severity, key, deduped=False,
                                    alert_id=resolved_alert_id)

        matched: list = []
        rule_count = 0
        try:
            from .rules.engine import evaluate_normalized_alert  # import local : évite le cycle
            matched, rule_count = evaluate_normalized_alert(normalized, source="pipeline")
            _stats["rule_matches_total"] += rule_count
        except Exception as e:
            logger.warning("Pipeline: évaluation des règles échouée: %s", e)

        return {
            "status": "accepted",
            "dedup_key": key,
            "normalized_severity": normalized_severity,
            "buffer_size": _buffer.current,
            "matched_rules": matched,
            "rule_matches": rule_count,
        }
    finally:
        if own_db:
            db.close()


# ── Stats / reset ───────────────────────────────────────────────────

def get_pipeline_stats(tenant_id: Optional[str] = None) -> dict:
    snapshot = _buffer.snapshot()
    if tenant_id:
        snapshot = [e for e in snapshot if e.get("tenant_id") == tenant_id]
    src_counter = Counter(e.get("src_ip") for e in snapshot if e.get("src_ip"))
    sev_counter = Counter(int(e.get("normalized_severity", 0)) for e in snapshot)
    received = _stats["received_total"]
    deduped = _stats["deduped_total"]
    return {
        "buffer": {"current": len(snapshot), "capacity": _buffer.capacity},
        "dedup": {
            "received_total": received,
            "deduped_total": deduped,
            "suppressed_total": _stats["suppressed_total"],
            "emitted_total": _stats["emitted_total"],
            "dedup_rate": round(deduped / received, 4) if received else 0.0,
        },
        "top_sources": [{"ip": ip, "count": c} for ip, c in src_counter.most_common(10)],
        "severity_distribution": dict(sev_counter),
        "rule_matches_total": _stats["rule_matches_total"],
        "last_ingest_at": _stats["last_ingest_at"],
        "config": dict(DEFAULT_PIPELINE_CONFIG),
    }


def reset_pipeline():
    _buffer.clear()
    _dedup.clear()
    for k in _stats:
        _stats[k] = 0 if isinstance(_stats[k], int) else None
    _cfg_cache["ts"] = 0.0
