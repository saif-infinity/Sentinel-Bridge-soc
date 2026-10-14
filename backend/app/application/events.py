"""F1 — CONTRAT D'ÉVÉNEMENTS (moteur de règles → mini-SOAR).

CECI EST LE CONTRAT. Les autres lanes consomment RuleMatchEvent uniquement via :
  1. event_bus.subscribe(CHANNEL_RULE_MATCH, handler)  — live in-process (handler sync OU async)
  2. table rule_match_events (outbox)                  — poll status='pending'
NE PAS importer rules/engine/* depuis d'autres lanes.

Champ "source" de l'événement : "pipeline" (ingestion synchrone) | "catch_up" (sweep périodique).
"""
import asyncio
import inspect
import json
import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from ..db import SessionLocal
from ..domain.rule_models import RuleMatchOutbox

logger = logging.getLogger(__name__)

CHANNEL_RULE_MATCH = "rules.match"
CHANNEL_INVESTIGATION_COMPLETE = "investigations.complete"
CHANNEL_ALERT_INGESTED = "alerts.ingested"
EVENT_VERSION = 1


@dataclass
class RuleMatchEvent:
    """Événement publié quand une ou plusieurs règles matchent une alerte normalisée."""
    event_id: str
    timestamp: str                       # ISO-8601 UTC
    tenant_id: str
    channel: str                         # toujours CHANNEL_RULE_MATCH
    version: int                         # 1
    source: str                          # "pipeline" | "catch_up"
    normalized_alert: dict[str, Any]     # forme canonique F1 (voir evaluator.NORMALIZED_KEYS)
    matched_rules: list[dict[str, Any]]  # [{rule_id, rule_name, rule_severity, tags, correlation, matched_conditions}]


@dataclass
class InvestigationCompleteEvent:
    """Event published when an investigation reaches awaiting_response status."""
    event_id: str
    timestamp: str
    tenant_id: str
    channel: str
    version: int
    source: str
    investigation_id: int
    case_id: int | None
    risk_level: str | None
    matched_rules: list[dict[str, Any]] | None = None

    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []
        if not self.channel:
            self.channel = CHANNEL_INVESTIGATION_COMPLETE
        if not self.version:
            self.version = EVENT_VERSION
        if not self.source:
            self.source = "response_agent"
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()


class EventBus:
    def __init__(self):
        self._handlers: dict[str, list[Callable]] = {}
        self._lock = threading.RLock()

    def subscribe(self, channel: str, handler: Callable) -> None:
        with self._lock:
            self._handlers.setdefault(channel, []).append(handler)

    def unsubscribe(self, channel: str, handler: Callable) -> None:
        with self._lock:
            if channel in self._handlers:
                try:
                    self._handlers[channel].remove(handler)
                except ValueError:
                    pass

    def _dispatch(self, channel: str, event: Any) -> None:
        with self._lock:
            handlers = list(self._handlers.get(channel, []))
        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    loop = _get_running_loop()
                    if loop is not None:
                        loop.create_task(handler(channel, event))
                    else:
                        logger.warning("events: handler async %s sans loop actif — dispatch local",
                                        getattr(handler, "__name__", handler))
                else:
                    handler(channel, event)
            except Exception as e:
                logger.warning("events: handler %s a échoué: %s",
                                getattr(handler, "__name__", handler), e)

    async def publish(self, channel: str, event: RuleMatchEvent) -> None:
        """Publication depuis un contexte async : écrit l'outbox puis dispatch."""
        try:
            _insert_outbox(channel, event)
        except Exception as e:
            logger.warning("events: écriture outbox échouée: %s", e)
        self._dispatch(channel, event)

    def publish_sync(self, channel: str, event: RuleMatchEvent) -> None:
        """Publication depuis un contexte sync (celery, webhook sync) : outbox puis dispatch."""
        try:
            _insert_outbox(channel, event)
        except Exception as e:
            logger.warning("events: écriture outbox échouée: %s", e)
        self._dispatch(channel, event)

    def publish_local(self, channel: str, event: Any) -> None:
        """Dispatch in-process uniquement, sans outbox."""
        self._dispatch(channel, event)


def _get_running_loop():
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _insert_outbox(channel: str, event: RuleMatchEvent) -> None:
    db = SessionLocal()
    try:
        dup = db.query(RuleMatchOutbox).filter(RuleMatchOutbox.event_id == event.event_id).first()
        if dup:
            return
        db.add(RuleMatchOutbox(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            channel=channel,
            payload=json.dumps(asdict(event), ensure_ascii=False, default=str),
            status="pending",
        ))
        db.commit()
    finally:
        db.close()


def make_rule_match_event(tenant_id: str, normalized_alert: dict, matched_rules: list,
                          source: str = "pipeline") -> RuleMatchEvent:
    return RuleMatchEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        tenant_id=tenant_id,
        channel=CHANNEL_RULE_MATCH,
        version=EVENT_VERSION,
        source=source,
        normalized_alert=normalized_alert,
        matched_rules=matched_rules,
    )


# Singleton partagé (in-process)
event_bus = EventBus()
