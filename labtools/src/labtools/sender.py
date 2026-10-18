"""Envoi HTTP des événements, sans dépendance externe.

Le module réutilise :mod:`urllib.request` et applique la politique de
sécurité de :mod:`labtools.safety` avant chaque envoi.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .safety import ensure_url_allowed

DEFAULT_TIMEOUT = 5.0
MAX_BODY_BYTES = 8 * 1024 * 1024


class SendError(RuntimeError):
    """Échec d'un envoi HTTP (réseau, statut, corps trop volumineux)."""


@dataclass
class DeliveryResult:
    """Résultat d'un envoi : statut HTTP et durée observée."""

    status: int
    duration_ms: float


class HttpDeliverer:
    """Envoie des enregistrements JSON vers un endpoint HTTP.

    La cible est validée une seule fois, à la construction : le but est
    d'échouer tôt et clairement si l'URL est hors périmètre.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        allow_public: bool | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("le délai d'attente doit être positif")
        self.url = url
        self.timeout = timeout
        self.scope = ensure_url_allowed(url, allow_public=allow_public)
        self.headers = {
            "User-Agent": "LabTools/0.1 (+lab-only)",
            "Content-Type": "application/json; charset=utf-8",
        }
        if headers:
            self.headers.update({str(key): str(value) for key, value in headers.items()})

    def _post(self, body: bytes) -> DeliveryResult:
        if len(body) > MAX_BODY_BYTES:
            raise SendError(
                f"corps de {len(body)} octets supérieur à la limite de "
                f"{MAX_BODY_BYTES} octets ; utilisez --batch ou réduisez le lot"
            )
        request = urllib.request.Request(
            self.url,
            data=body,
            headers=self.headers,
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = int(response.status)
                response.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(300).decode("utf-8", "replace").strip()
            except Exception:  # pragma: no cover - lecture best effort
                detail = ""
            suffix = f" — {detail}" if detail else ""
            raise SendError(f"HTTP {exc.code} de {self.url}{suffix}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise SendError(f"envoi impossible vers {self.url} : {reason}") from exc
        elapsed_ms = (time.monotonic() - started) * 1000
        return DeliveryResult(status=status, duration_ms=elapsed_ms)

    def send_record(self, record: Mapping[str, Any]) -> DeliveryResult:
        """Envoie un enregistrement unique."""

        body = json.dumps(dict(record), ensure_ascii=False).encode("utf-8")
        return self._post(body)

    def send_batch(self, records: Sequence[Mapping[str, Any]]) -> DeliveryResult:
        """Envoie un lot d'enregistrements en un seul POST (tableau JSON)."""

        body = json.dumps(
            [dict(record) for record in records], ensure_ascii=False
        ).encode("utf-8")
        return self._post(body)

    def send_lines(self, lines: Sequence[str]) -> DeliveryResult:
        """Envoie des lignes déjà sérialisées jointes par des sauts de ligne."""

        body = "\n".join(lines).encode("utf-8")
        return self._post(body)


def parse_headers(pairs: Sequence[str]) -> dict[str, str]:
    """Analyse des en-têtes de la forme ``Nom: valeur``."""

    headers: dict[str, str] = {}
    for raw in pairs:
        name, separator, value = raw.partition(":")
        if not separator or not name.strip():
            raise ValueError(f"en-tête invalide « {raw} » ; format attendu : Nom: valeur")
        headers[name.strip()] = value.strip()
    return headers
