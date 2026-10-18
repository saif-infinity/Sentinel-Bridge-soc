"""Interface en ligne de commande de LabTools.

Sous-commandes : ``create``, ``send``, ``list``, ``validate``, ``probe``,
``scan`` et ``catalog``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import CatalogError, format_details, format_table, load_catalog
from .events import MAX_COUNT, Event, generate_events, parse_time
from .formats import FORMATS, format_event, sentinel_payload
from .probes import (
    DEFAULT_TIMEOUT,
    format_results,
    parse_ports,
    probe_port,
    scan_ports,
)
from .safety import SafetyError
from .scenarios import SCENARIOS, Scenario, get_scenario, load_custom_scenario
from .sender import HttpDeliverer, SendError, parse_headers

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

EPILOG = """\
Garde-fous : seules les cibles de laboratoire (boucle locale, plages privées)
sont autorisées par défaut. --allow-public est requis pour une adresse
publique, et --allow-many-ports pour en balayer plus de 20.

Ne testez que des systèmes que vous êtes autorisé à tester.
"""


# ── Analyse d'arguments ────────────────────────────────────────────
def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"entier attendu, reçu {text!r}") from None
    if value < 1 or value > MAX_COUNT:
        raise argparse.ArgumentTypeError(f"valeur attendue entre 1 et {MAX_COUNT}")
    return value


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"nombre attendu, reçu {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("valeur strictement positive attendue")
    return value


def _non_negative_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"nombre attendu, reçu {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("valeur positive ou nulle attendue")
    return value


def _port_number(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port invalide : {text!r}") from None
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("port attendu entre 1 et 65535")
    return value


def _add_generation_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-s", "--scenario",
        help=f"scénario intégré : {', '.join(sorted(SCENARIOS))}",
    )
    group.add_argument(
        "--scenario-file",
        type=Path,
        help="scénario personnalisé au format JSON",
    )
    parser.add_argument(
        "-n", "--count",
        type=_positive_int,
        default=10,
        help="nombre d'événements à générer (défaut : 10)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="graine de reproductibilité (défaut : 42)",
    )
    parser.add_argument(
        "--host",
        help="hôte cible à inscrire dans les événements (défaut : celui du scénario)",
    )
    parser.add_argument(
        "--interval",
        type=_non_negative_float,
        help="secondes entre deux événements (défaut : celui du scénario)",
    )
    parser.add_argument(
        "--start",
        help="début ISO 8601 des événements (défaut : maintenant)",
    )


def _resolve_scenario(args: argparse.Namespace) -> Scenario:
    if getattr(args, "scenario_file", None):
        return load_custom_scenario(args.scenario_file)
    return get_scenario(args.scenario)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="labtools",
        description=(
            "Boîte à outils de laboratoire : scénarios d'événements SOC, "
            "envoi HTTP, sondes réseau bornées et inventaire d'outils."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"labtools {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMANDE")

    # create ───────────────────────────────────────────────────────
    create = subparsers.add_parser(
        "create",
        help="générer des événements et les écrire sur la sortie standard",
        description="Génère des événements de laboratoire dans le format choisi.",
    )
    _add_generation_arguments(create)
    create.add_argument(
        "--format",
        choices=FORMATS,
        default="jsonl",
        help="format de sortie (défaut : jsonl)",
    )
    create.add_argument(
        "-o", "--output",
        type=Path,
        help="fichier de sortie (défaut : sortie standard)",
    )

    # send ─────────────────────────────────────────────────────────
    send = subparsers.add_parser(
        "send",
        help="envoyer des événements générés vers un collecteur HTTP",
        description=(
            "Génère puis POSTe les événements vers une URL. Les formats jsonl "
            "et sentinel sont acceptés ; cef et syslog nécessitent un transport "
            "dédié (voir README)."
        ),
    )
    _add_generation_arguments(send)
    send.add_argument(
        "--format",
        choices=("sentinel", "jsonl"),
        default="sentinel",
        help="corps envoyé (défaut : sentinel, compatible Sentinel Bridge)",
    )
    send.add_argument(
        "--url",
        default=os.environ.get("LABTOOLS_URL"),
        help="URL du collecteur (défaut : LABTOOLS_URL)",
    )
    send.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NOM: VALEUR",
        help="en-tête HTTP additionnel, répétable",
    )
    send.add_argument(
        "--timeout",
        type=_positive_float,
        default=5.0,
        help="délai d'attente HTTP en secondes (défaut : 5)",
    )
    send.add_argument(
        "--delay",
        type=_non_negative_float,
        default=0.0,
        help="pause entre deux envois en secondes (défaut : 0)",
    )
    send.add_argument(
        "--batch",
        action="store_true",
        help="envoyer tous les événements en un seul POST",
    )
    send.add_argument(
        "--dry-run",
        action="store_true",
        help="afficher le corps du premier envoi sans contacter le réseau",
    )
    send.add_argument(
        "--allow-public",
        action="store_true",
        help="autoriser une cible publique (déconseillé)",
    )

    # list ─────────────────────────────────────────────────────────
    list_cmd = subparsers.add_parser(
        "list",
        help="lister les scénarios intégrés",
        description="Liste les scénarios intégrés et leurs métadonnées.",
    )
    list_cmd.add_argument(
        "--json", action="store_true", help="sortie JSON"
    )

    # validate ─────────────────────────────────────────────────────
    validate = subparsers.add_parser(
        "validate",
        help="valider un scénario personnalisé",
        description="Charge un scénario JSON, vérifie sa structure et génère un échantillon.",
    )
    validate.add_argument("file", type=Path, help="fichier JSON du scénario")
    validate.add_argument(
        "-n", "--count",
        type=_positive_int,
        default=3,
        help="taille de l'échantillon généré (défaut : 3)",
    )

    # probe ────────────────────────────────────────────────────────
    probe = subparsers.add_parser(
        "probe",
        help="tester un port TCP unique",
        description="Teste la joignabilité d'un port TCP (aucune donnée applicative envoyée).",
    )
    probe.add_argument(
        "target",
        help="hôte, hôte:port ou URL http(s)://…",
    )
    probe.add_argument("--port", type=_port_number, help="port à tester")
    probe.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"délai par tentative en secondes (défaut : {DEFAULT_TIMEOUT})",
    )
    probe.add_argument(
        "--allow-public",
        action="store_true",
        help="autoriser une cible publique (déconseillé)",
    )
    probe.add_argument("--json", action="store_true", help="sortie JSON")

    # scan ─────────────────────────────────────────────────────────
    scan = subparsers.add_parser(
        "scan",
        help="balayer une liste bornée de ports TCP",
        description=(
            "Balaye des ports TCP en parallèle. Par défaut, seules les cibles "
            "privées sont autorisées."
        ),
    )
    scan.add_argument("host", help="hôte ou adresse IP de laboratoire")
    scan.add_argument(
        "--ports",
        default="top",
        help="ports à balayer, ex. « 22,80,443 » ou « 1-1024 » (défaut : top)",
    )
    scan.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"délai par port en secondes (défaut : {DEFAULT_TIMEOUT})",
    )
    scan.add_argument(
        "--workers",
        type=_positive_int,
        default=32,
        help="connexions simultanées (défaut : 32, maximum 200)",
    )
    scan.add_argument(
        "--open-only", action="store_true", help="n'afficher que les ports ouverts"
    )
    scan.add_argument(
        "--allow-public", action="store_true", help="autoriser une cible publique"
    )
    scan.add_argument(
        "--allow-many-ports",
        action="store_true",
        help="lever la limite de 20 ports sur une cible publique",
    )
    scan.add_argument("--json", action="store_true", help="sortie JSON")

    # catalog ──────────────────────────────────────────────────────
    catalog = subparsers.add_parser(
        "catalog",
        help="consulter l'inventaire des outils de laboratoire",
        description="Recherche dans l'inventaire embarqué, ou dans un fichier JSON fourni.",
    )
    catalog.add_argument(
        "--category",
        help="filtrer par catégorie (collecte, reseau, endpoint, detection, …)",
    )
    catalog.add_argument(
        "-q", "--search", help="recherche plein texte (tous les termes doivent correspondre)"
    )
    catalog.add_argument(
        "--lab-safe",
        action="store_true",
        help="n'afficher que les outils utilisables sans précaution particulière",
    )
    catalog.add_argument("--id", help="afficher la fiche détaillée d'un outil")
    catalog.add_argument(
        "--inventory", type=Path, help="inventaire JSON alternatif"
    )
    catalog.add_argument("--json", action="store_true", help="sortie JSON")

    return parser


# ── Utilitaires ────────────────────────────────────────────────────
def _records(events: Sequence[Event]) -> list[dict[str, Any]]:
    return [event.to_dict() for event in events]


def _emit(text: str, output: Path | None, command: str) -> None:
    if output is None:
        sys.stdout.write(text + "\n")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text + "\n", encoding="utf-8")
    print(
        f"{command} : {len(text.splitlines())} ligne(s) écrite(s) dans {output}",
        file=sys.stderr,
    )


def _parse_target(raw: str) -> tuple[str, int | None]:
    from urllib.parse import urlsplit

    target = raw.strip()
    if "://" in target:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"}:
            raise ValueError(f"schéma non supporté : {parts.scheme!r}")
        default_port = 443 if parts.scheme == "https" else 80
        return parts.hostname or "", parts.port or default_port
    if target.startswith("[") and "]" in target:
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if target.count(":") == 1:
        host, _, port_text = target.partition(":")
        if port_text.isdigit():
            return host, _port_number(port_text)
    return target, None


def _now() -> float:
    return time.monotonic()


# ── Commandes ──────────────────────────────────────────────────────
def _cmd_create(args: argparse.Namespace) -> int:
    scenario = _resolve_scenario(args)
    events = generate_events(
        scenario,
        count=args.count,
        seed=args.seed,
        host=args.host,
        interval=args.interval,
        start=parse_time(args.start),
    )
    text = "\n".join(format_event(event, args.format) for event in events)
    _emit(text, args.output, "create")
    return EXIT_OK


def _cmd_send(args: argparse.Namespace) -> int:
    if not args.url:
        raise SystemExit(
            "labtools : URL requise. Utilisez --url ou la variable LABTOOLS_URL "
            "(ex. http://localhost:8000/api/pipeline/ingest)."
        )
    scenario = _resolve_scenario(args)
    events = generate_events(
        scenario,
        count=args.count,
        seed=args.seed,
        host=args.host,
        interval=args.interval,
        start=parse_time(args.start),
    )
    headers = parse_headers(args.header)
    if args.format == "sentinel" and "X-API-Key" not in headers:
        api_key = os.environ.get("LABTOOLS_API_KEY")
        if api_key:
            headers["X-API-Key"] = api_key

    records = [
        sentinel_payload(event.to_dict()) if args.format == "sentinel" else event.to_dict()
        for event in events
    ]

    if args.dry_run:
        print(json.dumps(records[0], ensure_ascii=False, indent=2))
        print(
            f"dry-run : {len(records)} événement(s) prêt(s) pour {args.url} "
            f"(format {args.format}, {'lot' if args.batch else 'unitaire'})",
            file=sys.stderr,
        )
        return EXIT_OK

    deliverer = HttpDeliverer(
        args.url,
        headers=headers,
        timeout=args.timeout,
        allow_public=args.allow_public,
    )
    started = _now()
    failures: list[str] = []
    sent = 0
    if args.batch:
        try:
            if args.format == "sentinel":
                result = deliverer.send_batch(records)
            else:
                result = deliverer.send_lines(
                    [json.dumps(record, ensure_ascii=False) for record in records]
                )
            sent = len(records)
            print(
                f"send : {sent} événement(s) envoyé(s) en un lot vers {args.url} "
                f"(HTTP {result.status}, {result.duration_ms:.0f} ms)"
            )
        except SendError as exc:
            failures.append(str(exc))
    else:
        for index, record in enumerate(records, start=1):
            if index > 1 and args.delay:
                time.sleep(args.delay)
            try:
                result = deliverer.send_record(record)
            except SendError as exc:
                failures.append(f"événement {index} : {exc}")
                continue
            sent += 1
            if index == 1 or index == len(records) or index % 50 == 0:
                print(
                    f"send : {index}/{len(records)} (HTTP {result.status}, "
                    f"{result.duration_ms:.0f} ms)",
                    file=sys.stderr,
                )

    elapsed = _now() - started
    if failures:
        print(
            f"send : {sent}/{len(records)} envoyé(s), {len(failures)} échec(s) "
            f"en {elapsed:.1f} s",
            file=sys.stderr,
        )
        for message in failures[:3]:
            print(f"  - {message}", file=sys.stderr)
        if len(failures) > 3:
            print(f"  … et {len(failures) - 3} autre(s)", file=sys.stderr)
        return EXIT_ERROR
    if not args.batch:
        print(
            f"send : {sent} événement(s) envoyé(s) vers {args.url} en {elapsed:.1f} s"
        )
    return EXIT_OK


def _cmd_list(args: argparse.Namespace) -> int:
    scenarios = [SCENARIOS[name] for name in sorted(SCENARIOS)]
    if args.json:
        payload = [
            {
                "name": item.name,
                "title": item.title,
                "description": item.description,
                "mitre": list(item.mitre),
                "default_host": item.default_host,
                "default_interval": item.default_interval,
            }
            for item in scenarios
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK
    width = max(len(item.name) for item in scenarios)
    print(f"{'SCÉNARIO'.ljust(width)}  INTERVALLE  MITRE        TITRE")
    for item in scenarios:
        mitre = ",".join(item.mitre)
        print(
            f"{item.name.ljust(width)}  {item.default_interval:>8.1f}s  "
            f"{mitre:<11}  {item.title}"
        )
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    scenario = load_custom_scenario(args.file)
    events = generate_events(scenario, count=args.count, seed=1)
    print(f"OK — scénario « {scenario.name} » : {scenario.title}")
    print(f"  hôte par défaut   : {scenario.default_host}")
    print(f"  intervalle        : {scenario.default_interval} s")
    print(f"  techniques MITRE  : {', '.join(scenario.mitre) or '—'}")
    print(f"  échantillon       : {len(events)} événement(s) généré(s)")
    for event in events:
        print(f"    [{event.severity}] {event.message}")
    return EXIT_OK


def _cmd_probe(args: argparse.Namespace) -> int:
    host, url_port = _parse_target(args.target)
    port = args.port or url_port
    if port is None:
        raise SystemExit(
            "labtools : port requis. Utilisez --port ou la forme hôte:port "
            "(ex. lab-web.local:8080)."
        )
    result = probe_port(
        host, port, timeout=args.timeout, allow_public=args.allow_public
    )
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False))
    else:
        latency = f" — {result.latency_ms:.1f} ms" if result.latency_ms is not None else ""
        print(f"{result.host}:{result.port} : {result.status}{latency}")
        if result.error and result.status != "open":
            print(f"  détail : {result.error}", file=sys.stderr)
    return EXIT_OK if result.status == "open" else EXIT_ERROR


def _cmd_scan(args: argparse.Namespace) -> int:
    ports = parse_ports(args.ports)
    results = scan_ports(
        args.host,
        ports,
        timeout=args.timeout,
        workers=args.workers,
        allow_public=args.allow_public,
        allow_many_ports=args.allow_many_ports,
    )
    if args.json:
        print(json.dumps([item.as_dict() for item in results], ensure_ascii=False, indent=2))
    else:
        print(format_results(results, open_only=args.open_only))
        opened = sum(1 for item in results if item.status == "open")
        print(f"\n{opened}/{len(results)} port(s) ouvert(s) sur {args.host}")
    return EXIT_OK


def _cmd_catalog(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.inventory)
    if args.id:
        tool = catalog.find(args.id)
        if tool is None:
            print(
                f"catalog : outil inconnu « {args.id} ». Essayez --search.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        if args.json:
            print(json.dumps(tool.as_dict(), ensure_ascii=False, indent=2))
        else:
            print(format_details(tool))
        return EXIT_OK
    tools = catalog.filter(
        category=args.category, query=args.search, lab_safe_only=args.lab_safe
    )
    if args.json:
        print(json.dumps([tool.as_dict() for tool in tools], ensure_ascii=False, indent=2))
    else:
        print(format_table(tools))
        counts = catalog.categories()
        summary = " · ".join(f"{name} {count}" for name, count in counts.items())
        print(f"\n{len(tools)} outil(s) affiché(s) — {summary}")
    return EXIT_OK


COMMANDS = {
    "create": _cmd_create,
    "send": _cmd_send,
    "list": _cmd_list,
    "validate": _cmd_validate,
    "probe": _cmd_probe,
    "scan": _cmd_scan,
    "catalog": _cmd_catalog,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée console ; retourne un code de sortie."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # pragma: no cover - flux non reconfigurable
                pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    handler = COMMANDS[args.command]
    try:
        return handler(args)
    except (SafetyError, SendError, CatalogError) as exc:
        print(f"labtools : {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"labtools : {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrompu", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
