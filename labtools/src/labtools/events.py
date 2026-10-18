"""Modèle d'événement et génération déterministe des scénarios."""

from __future__ import annotations

import random
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")

# Échelles utilisées par les différents formats de sortie.
SEVERITY_TO_SENTINEL = {"low": 3, "medium": 6, "high": 9, "critical": 12}
SEVERITY_TO_CEF = {"low": 3, "medium": 5, "high": 8, "critical": 10}
SEVERITY_TO_SYSLOG = {"low": 6, "medium": 5, "high": 4, "critical": 3}

MAX_COUNT = 100_000


@dataclass
class Event:
    """Événement synthétique normalisé, indépendant du format de sortie."""

    timestamp: str
    event_id: str
    scenario: str
    category: str
    action: str
    outcome: str
    severity: str
    host: str
    message: str
    source: str = "labtools"
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    mitre: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GenContext:
    """Paramètres transmis à un générateur de scénario."""

    count: int
    seed: int
    host: str
    scenario: Scenario
    rng: random.Random


@dataclass(frozen=True)
class Scenario:
    """Définition d'un scénario : métadonnées + générateur."""

    name: str
    title: str
    description: str
    mitre: tuple[str, ...]
    default_host: str
    default_interval: float
    generate: Callable[[GenContext], list[dict[str, Any]]]


def iso_z(moment: datetime) -> str:
    """Formate une date en RFC 3339 UTC avec un suffixe ``Z``."""

    return (
        moment.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def parse_time(value: str | datetime | None) -> datetime | None:
    """Analyse une date ISO 8601 (``Z`` accepté) et la convertit en UTC."""

    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip()
        if not text:
            raise ValueError("date vide : utilisez le format ISO 8601")
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"date ISO 8601 invalide : {value!r}") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _validate_count(count: int) -> None:
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("le nombre d'événements doit être un entier")
    if count < 1 or count > MAX_COUNT:
        raise ValueError(f"le nombre d'événements doit être compris entre 1 et {MAX_COUNT}")


def _build_event(
    scenario: Scenario,
    spec: dict[str, Any],
    *,
    index: int,
    seed: int,
    timestamp: str,
    default_host: str,
) -> Event:
    severity = spec.get("severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError(
            f"gravité invalide {severity!r} pour {scenario.name} : "
            f"attendu {', '.join(SEVERITIES)}"
        )
    details = spec.get("details", {})
    if not isinstance(details, dict):
        raise ValueError(f"« details » doit être un objet JSON ({scenario.name})")
    mitre = spec.get("mitre", scenario.mitre)
    if not isinstance(mitre, (list, tuple)):
        raise ValueError(f"« mitre » doit être une liste ({scenario.name})")
    tags = [scenario.name, *spec.get("tags", [])]
    deduped_tags = list(dict.fromkeys(str(tag) for tag in tags))

    return Event(
        timestamp=timestamp,
        event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"labtools/{scenario.name}/{seed}/{index}")),
        scenario=scenario.name,
        source="labtools",
        category=str(spec.get("category", "lab")),
        action=str(spec.get("action", "custom")),
        outcome=str(spec.get("outcome", "unknown")),
        severity=severity,
        host=str(spec.get("host") or default_host),
        user=spec.get("user"),
        src_ip=spec.get("src_ip"),
        src_port=spec.get("src_port"),
        dst_ip=spec.get("dst_ip"),
        dst_port=spec.get("dst_port"),
        protocol=spec.get("protocol"),
        mitre=[str(item) for item in mitre],
        tags=deduped_tags,
        message=str(spec["message"]),
        details=details,
    )


def generate_events(
    scenario: Scenario,
    *,
    count: int = 10,
    seed: int = 42,
    host: str | None = None,
    interval: float | None = None,
    start: str | datetime | None = None,
) -> list[Event]:
    """Génère une liste d'événements chronologiques pour ``scenario``.

    La génération est déterministe pour un couple (scénario, graine, date de
    début, intervalle) : les identifiants et les champs pseudo-aléatoires sont
    reproductibles.
    """

    _validate_count(count)
    effective_interval = scenario.default_interval if interval is None else float(interval)
    if effective_interval < 0:
        raise ValueError("l'intervalle doit être positif ou nul")

    start_dt = parse_time(start)
    if start_dt is None:
        start_dt = datetime.now(timezone.utc) - timedelta(
            seconds=effective_interval * (count - 1)
        )
    start_dt = start_dt.replace(microsecond=0)

    default_host = host or scenario.default_host
    context = GenContext(
        count=count,
        seed=seed,
        host=default_host,
        scenario=scenario,
        rng=random.Random(seed),
    )
    specs = scenario.generate(context)
    if not isinstance(specs, list):
        raise ValueError(f"le générateur de {scenario.name} n'a pas renvoyé de liste")
    if len(specs) != count:
        raise ValueError(
            f"le générateur de {scenario.name} a produit {len(specs)} événements "
            f"au lieu de {count}"
        )

    events: list[Event] = []
    for index, spec in enumerate(specs):
        if not isinstance(spec, dict):
            raise ValueError(f"événement invalide #{index} pour {scenario.name}")
        for required in ("category", "action", "message"):
            if not spec.get(required):
                raise ValueError(
                    f"champ obligatoire manquant « {required} » dans l'événement #{index} "
                    f"du scénario {scenario.name}"
                )
        moment = start_dt + timedelta(seconds=effective_interval * index)
        event = _build_event(
            scenario,
            spec,
            index=index,
            seed=seed,
            timestamp=iso_z(moment),
            default_host=default_host,
        )
        if host:
            # --host remplace l'hôte du scénario, y compris quand le générateur
            # en a fixé un : c'est la cible choisie par l'utilisateur.
            event.host = host
        events.append(event)
    return events
