"""Sondes TCP non intrusives : test de port unique et balayage borné."""

from __future__ import annotations

import errno
import socket
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from .safety import TargetScope, ensure_lab_target

DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 32
MAX_WORKERS = 200
TOP_PORTS = (
    22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306,
    3389, 5432, 5601, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
)


@dataclass(frozen=True)
class ProbeResult:
    host: str
    port: int
    status: str  # open | closed | filtered
    latency_ms: float | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "latency_ms": (
                round(self.latency_ms, 1) if self.latency_ms is not None else None
            ),
            "error": self.error,
        }


def parse_ports(spec: str) -> list[int]:
    """Analyse ``22,80,1000-1005,top`` en liste de ports triée et dédoublonnée."""

    if not spec or not spec.strip():
        raise ValueError("liste de ports vide")
    ports: set[int] = set()
    for chunk in spec.split(","):
        item = chunk.strip().lower()
        if not item:
            continue
        if item in {"top", "common"}:
            ports.update(TOP_PORTS)
            continue
        if "-" in item:
            start_text, _, end_text = item.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError:
                raise ValueError(f"plage de ports invalide : « {item} »") from None
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError(f"plage de ports hors bornes (1-65535) : « {item} »")
            if end - start > 10_000:
                raise ValueError(
                    f"plage trop large ({end - start + 1} ports) ; maximum 10 001 ports"
                )
            ports.update(range(start, end + 1))
            continue
        try:
            port = int(item)
        except ValueError:
            raise ValueError(f"port invalide : « {item} »") from None
        if port < 1 or port > 65535:
            raise ValueError(f"port hors bornes (1-65535) : {port}")
        ports.add(port)
    if not ports:
        raise ValueError("aucun port valide fourni")
    return sorted(ports)


def _connect(host: str, port: int, timeout: float) -> ProbeResult:
    started = time.monotonic()
    family_candidates = (socket.AF_INET, socket.AF_INET6)
    last_error: OSError | None = None
    for family in family_candidates:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                code = sock.connect_ex((host, port))
        except OSError as exc:  # famille non supportée, etc.
            last_error = exc
            continue
        elapsed = (time.monotonic() - started) * 1000
        if code == 0:
            return ProbeResult(host, port, "open", elapsed)
        if code in {errno.ECONNREFUSED, errno.ECONNRESET}:
            return ProbeResult(host, port, "closed", elapsed)
        if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM}:
            return ProbeResult(host, port, "filtered", elapsed, error=errno.errorcode.get(code))
        return ProbeResult(host, port, "filtered", elapsed, error=errno.errorcode.get(code))
    return ProbeResult(
        host,
        port,
        "filtered",
        error=str(last_error) if last_error else "inconnu",
    )


def probe_port(
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    allow_public: bool | None = None,
) -> ProbeResult:
    """Teste un port TCP unique après validation de la cible."""

    if not 1 <= port <= 65535:
        raise ValueError(f"port hors bornes (1-65535) : {port}")
    if timeout <= 0:
        raise ValueError("le délai d'attente doit être positif")
    scope = ensure_lab_target(host, allow_public=allow_public, purpose=f"port {port}")
    return _probe_scope(scope, port, timeout)


def _probe_scope(scope: TargetScope, port: int, timeout: float) -> ProbeResult:
    address = scope.addresses[0] if scope.addresses else scope.host
    return _connect(address, port, timeout)


def scan_ports(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
    allow_public: bool | None = None,
    allow_many_ports: bool = False,
) -> list[ProbeResult]:
    """Balaye ``ports`` sur ``host`` en parallèle, résultats triés par port."""

    port_list = sorted({int(port) for port in ports})
    if not port_list:
        raise ValueError("aucun port à balayer")
    if workers < 1 or workers > MAX_WORKERS:
        raise ValueError(f"workers doit être compris entre 1 et {MAX_WORKERS}")
    scope = ensure_lab_target(
        host,
        allow_public=allow_public,
        port_count=len(port_list),
        allow_many_ports=allow_many_ports,
        purpose=f"balayage de {len(port_list)} ports",
    )
    address = scope.addresses[0] if scope.addresses else scope.host

    results: list[ProbeResult] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(port_list))) as pool:
        futures = {
            pool.submit(_connect, address, port, timeout): port for port in port_list
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item.port)


def format_results(results: Sequence[ProbeResult], *, open_only: bool = False) -> str:
    """Met en forme les résultats sous forme de tableau lisible."""

    rows = [result for result in results if not open_only or result.status == "open"]
    if not rows:
        return "Aucun résultat."
    width = max(len(result.host) for result in rows)
    lines = [f"{'HÔTE'.ljust(width)}  PORT   ÉTAT        LATENCE"]
    for result in rows:
        latency = (
            f"{result.latency_ms:.1f} ms" if result.latency_ms is not None else "—"
        )
        lines.append(
            f"{result.host.ljust(width)}  {result.port:<5}  {result.status:<10}  {latency}"
        )
    return "\n".join(lines)
