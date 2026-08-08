"""F1 — Moteur de règles : évaluation synchrone à l'ingestion + sweep de rattrapage."""
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...db import SessionLocal
from ...domain.models import Alert, SuricataAlert
from ...domain.rule_models import Rule
from ..events import CHANNEL_RULE_MATCH, event_bus, make_rule_match_event
from .correlator import WindowedCorrelator
from .evaluator import build_normalized_alert, evaluate_conditions

logger = logging.getLogger(__name__)

_RULES_CACHE: Dict[str, Any] = {"ts": 0.0, "rules": {}}
_RULES_TTL = 60.0
_correlator = WindowedCorrelator()


def invalidate_rules_cache() -> None:
    """À appeler après tout CRUD de règle (router rules.py)."""
    _RULES_CACHE["ts"] = 0.0
    _RULES_CACHE["rules"] = {}


def load_rules(db, tenant_id: str) -> List[Rule]:
    """Règles actives visibles du tenant : règles globales (tenant_id NULL) + règles du tenant."""
    now = time.time()
    if now - _RULES_CACHE["ts"] < _RULES_TTL and tenant_id in _RULES_CACHE["rules"]:
        return _RULES_CACHE["rules"][tenant_id]
    rules = (
        db.query(Rule)
        .filter(Rule.enabled == True)  # noqa: E712
        .filter((Rule.tenant_id == tenant_id) | (Rule.tenant_id.is_(None)))
        .all()
    )
    _RULES_CACHE["ts"] = now
    _RULES_CACHE["rules"] = {tenant_id: rules}
    return rules


def visible_rules(db, tenant_id: str) -> List[Rule]:
    """Toutes les règles visibles (actives ou non) — pour le CRUD API."""
    return (
        db.query(Rule)
        .filter((Rule.tenant_id == tenant_id) | (Rule.tenant_id.is_(None)))
        .all()
    )


def evaluate_normalized_alert(normalized: Dict[str, Any],
                              source: str = "pipeline") -> Tuple[List[Dict[str, Any]], int]:
    """Évalue une alerte normalisée contre les règles visibles du tenant.

    Publie un RuleMatchEvent si au moins une règle matche.
    Retourne (résumé des règles matchées, nombre de règles matchées).
    """
    tenant_id = normalized.get("tenant_id", "default")
    db = SessionLocal()
    try:
        rules = load_rules(db, tenant_id)
        matched: List[Dict[str, Any]] = []
        for rule in rules:
            try:
                conditions = json.loads(rule.conditions or "[]")
            except (TypeError, ValueError):
                conditions = []
            if not isinstance(conditions, list):
                conditions = []

            try:
                corr = json.loads(rule.correlation or "{}")
                has_corr = bool(corr and corr.get("sequence"))
            except (TypeError, ValueError):
                has_corr = False

            if has_corr:
                if not _correlator.evaluate(rule, normalized, conditions):
                    continue
                matched_conditions = evaluate_conditions(conditions, normalized)
                is_correlation = True
            else:
                matched_conditions = evaluate_conditions(conditions, normalized)
                if not conditions or len(matched_conditions) < len(conditions):
                    continue
                is_correlation = False

            try:
                tags = json.loads(rule.tags or "[]")
            except (TypeError, ValueError):
                tags = []
            if not isinstance(tags, list):
                tags = []
            matched.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_severity": int(rule.severity or 5),
                "tags": tags,
                "correlation": is_correlation,
                "matched_conditions": matched_conditions,
            })

        _correlator.push(normalized)  # historique pour les corrélations futures
        if matched:
            event = make_rule_match_event(tenant_id, normalized, matched, source=source)
            event_bus.publish_sync(CHANNEL_RULE_MATCH, event)
        return matched, len(matched)
    finally:
        db.close()


def build_normalized_from_row(row: Any, mapping: Optional[dict] = None) -> Dict[str, Any]:
    """Construit l'alerte normalisée depuis une ligne Alert ou SuricataAlert.

    normalized_severity est recalculé (payload à None) pour corriger les lignes pré-F1.
    """
    ts = row.timestamp.isoformat() if getattr(row, "timestamp", None) else None
    if isinstance(row, SuricataAlert):
        return build_normalized_alert({
            "alert_id": row.id,
            "tenant_id": row.tenant_id,
            "timestamp": ts,
            "source": (row.pipeline_source or "suricata"),
            "severity": row.severity,
            "normalized_severity": None,
            "signature": row.alert_msg,
            "category": row.event_type,
            "description": row.alert_msg,
            "src_ip": row.src_ip,
            "dest_ip": row.dest_ip,
            "proto": row.proto,
            "raw": {"payload": row.payload} if row.payload else {},
        }, mapping)
    return build_normalized_alert({
        "alert_id": row.id,
        "tenant_id": row.tenant_id,
        "timestamp": ts,
        "source": (row.pipeline_source or "wazuh"),
        "severity": row.severity,
        "normalized_severity": None,
        "signature": row.description,
        "category": None,
        "description": row.description,
        "src_ip": row.src_ip,
        "dest_ip": None,
        "agent_id": row.agent_id,
        "proto": None,
        "raw": {},
    }, mapping)


def run_catch_up_sweep(db, tenant_id: str = "default", since_minutes: int = 60) -> dict:
    """Sweep de rattrapage : évalue les alertes DB non encore traitées (pipeline_processed_at NULL)."""
    from ..pipeline import load_config  # import local : évite le cycle pipeline↔engine
    mapping = load_config(db).get("severity_mapping")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    report = {"tenant_id": tenant_id, "processed": 0, "matched": 0, "skipped": 0}

    for model in (Alert, SuricataAlert):
        rows = (
            db.query(model)
            .filter(model.tenant_id == tenant_id,
                    model.pipeline_processed_at.is_(None),
                    model.timestamp >= cutoff)
            .limit(200)
            .all()
        )
        for row in rows:
            try:
                normalized = build_normalized_from_row(row, mapping)
                row.normalized_severity = normalized["normalized_severity"]
                matched, n = evaluate_normalized_alert(normalized, source="catch_up")
                row.pipeline_processed_at = datetime.now(timezone.utc)
                report["processed"] += 1
                report["matched"] += n
            except Exception as e:
                logger.warning("Sweep: %s id=%s ignoré: %s",
                               model.__name__, getattr(row, "id", "?"), e)
                report["skipped"] += 1
        db.commit()
    return report
