"""Garde-fous réseau : par défaut, seules les cibles de laboratoire sont autorisées.

La politique est volontairement simple et vérifiable :

* boucle locale, adresses privées, lien-local et plages de documentation
  (RFC 5737) : autorisées sans option ;
* toute adresse publique : refusée, sauf ``--allow-public`` ou
  ``LABTOOLS_ALLOW_PUBLIC=1`` ;
* un nom qui ne se résout pas est traité comme non vérifiable : refusé sauf
  ``--allow-public`` ;
* sur une cible publique, un balayage de plus de 20 ports exige en plus
  ``--allow-many-ports``.

Ces règles ne remplacent pas une autorisation explicite : ne ciblez que des
systèmes que vous avez le droit de tester.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_PUBLIC_PORTS = 20


class SafetyError(RuntimeError):
    """Cible refusée par la politique de sécurité de LabTools."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def allow_public_default() -> bool:
    """Indique si les cibles publiques sont autorisées par l'environnement."""

    return _env_flag("LABTOOLS_ALLOW_PUBLIC")


@dataclass(frozen=True)
class TargetScope:
    """Résultat de la classification d'une cible."""

    host: str
    addresses: tuple[str, ...]
    zone: str  # loopback | private | public | mixed | unresolved
    detail: str = ""

    @property
    def is_lab(self) -> bool:
        return self.zone in {"loopback", "private"}

    @property
    def is_public(self) -> bool:
        return self.zone in {"public", "mixed"}

    def addresses_text(self) -> str:
        if not self.addresses:
            return "—"
        shown = ", ".join(self.addresses[:4])
        if len(self.addresses) > 4:
            shown += f", … ({len(self.addresses)} adresses)"
        return shown


def classify_address(address: str) -> str:
    """Classe une adresse IP en ``loopback``, ``private`` ou ``public``."""

    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return "private"
    return "public"


def resolve_target(host: str, port: int | None = None) -> TargetScope:
    """Résout ``host`` puis classe l'ensemble de ses adresses."""

    candidate = (host or "").strip().strip("[]")
    if not candidate:
        raise SafetyError("cible vide : indiquez un nom d'hôte ou une adresse IP")

    try:
        ipaddress.ip_address(candidate)
        addresses: tuple[str, ...] = (candidate,)
    except ValueError:
        try:
            infos = socket.getaddrinfo(candidate, port or 0, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            return TargetScope(
                host=candidate,
                addresses=(),
                zone="unresolved",
                detail=str(exc),
            )
        addresses = tuple(sorted({info[4][0] for info in infos}))
        if not addresses:
            return TargetScope(
                host=candidate,
                addresses=(),
                zone="unresolved",
                detail="aucune adresse retournée par le résolveur",
            )

    zones = {classify_address(address) for address in addresses}
    if zones == {"loopback"}:
        zone = "loopback"
    elif zones <= {"loopback", "private"}:
        zone = "private"
    elif zones == {"public"}:
        zone = "public"
    else:
        zone = "mixed"
    return TargetScope(host=candidate, addresses=addresses, zone=zone)


def ensure_lab_target(
    host: str,
    *,
    allow_public: bool | None = None,
    port_count: int = 1,
    allow_many_ports: bool = False,
    purpose: str = "",
) -> TargetScope:
    """Vérifie qu'une cible est autorisée, sinon lève :class:`SafetyError`."""

    if allow_public is None:
        allow_public = allow_public_default()
    scope = resolve_target(host)
    context = f" ({purpose})" if purpose else ""

    if scope.zone == "unresolved":
        if allow_public:
            return scope
        raise SafetyError(
            f"Impossible de vérifier la cible « {host} »{context} : {scope.detail}. "
            "Utilisez une adresse de laboratoire, ou --allow-public si vous êtes "
            "autorisé à joindre cette cible."
        )

    if scope.is_public and not allow_public:
        raise SafetyError(
            f"Cible publique refusée : « {host} » ({scope.addresses_text()}){context}. "
            "LabTools n'envoie rien vers Internet par défaut. Relancez avec "
            "--allow-public (ou LABTOOLS_ALLOW_PUBLIC=1) après avoir vérifié que "
            "vous êtes autorisé à tester cette cible."
        )

    if scope.is_public and port_count > MAX_PUBLIC_PORTS and not allow_many_ports:
        raise SafetyError(
            f"Balayage de {port_count} ports sur une cible publique refusé{context}. "
            f"La limite est de {MAX_PUBLIC_PORTS} ports ; ajoutez --allow-many-ports "
            "si le propriétaire de la cible vous y a explicitement autorisé."
        )

    return scope


def ensure_url_allowed(
    url: str,
    *,
    allow_public: bool | None = None,
    purpose: str = "envoi HTTP",
) -> TargetScope:
    """Valide une URL HTTP(S) avant tout envoi."""

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SafetyError(f"URL refusée : seuls http et https sont acceptés ({url!r})")
    if parts.username or parts.password:
        raise SafetyError(
            "URL refusée : les identifiants intégrés à l'URL fuiteraient dans les "
            "logs. Utilisez plutôt l'option --header."
        )
    if not parts.hostname:
        raise SafetyError(f"URL invalide : nom d'hôte manquant ({url!r})")
    return ensure_lab_target(
        parts.hostname,
        allow_public=allow_public,
        purpose=purpose,
    )
