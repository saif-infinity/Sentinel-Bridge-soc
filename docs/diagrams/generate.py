#!/usr/bin/env python3
"""Build the four documentation diagrams using only the Python standard library.

Usage, from any directory:
    python3 docs/diagrams/generate.py
    python3 docs/diagrams/generate.py --check

The SVGs contain no scripts, external fonts or remote resources. The existing
Sentinel Bridge banner and guide icon are hand-authored and not regenerated here.
"""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "assets"
BG = "#081521"
PANEL = "#102433"
BORDER = "#294253"
TEXT = "#edf5fb"
MUTED = "#b3c6d4"
TEAL = "#5eead4"
BLUE = "#7dd3fc"
VIOLET = "#c4b5fd"
AMBER = "#fcd34d"


class Diagram:
    def __init__(self, title: str, description: str, height: int, eyebrow: str, subtitle: str):
        self.root = ET.Element(
            "svg",
            {
                "xmlns": "http://www.w3.org/2000/svg",
                "width": "1280",
                "height": str(height),
                "viewBox": f"0 0 1280 {height}",
                "role": "img",
                "aria-labelledby": "title description",
            },
        )
        ET.SubElement(self.root, "title", {"id": "title"}).text = title
        ET.SubElement(self.root, "desc", {"id": "description"}).text = description
        defs = ET.SubElement(self.root, "defs")
        gradient = ET.SubElement(
            defs,
            "linearGradient",
            {
                "id": "background",
                "x1": "0",
                "y1": "0",
                "x2": "1",
                "y2": "1",
            },
        )
        ET.SubElement(gradient, "stop", {"offset": "0", "stop-color": BG})
        ET.SubElement(gradient, "stop", {"offset": "1", "stop-color": "#102b37"})
        for name, color in (("teal", TEAL), ("blue", BLUE), ("amber", AMBER)):
            for prefix, ref_x, shape in (
                ("arrow", "9", "M0 0L10 5L0 10Z"),
                ("arrow-start", "1", "M10 0L0 5L10 10Z"),
            ):
                marker = ET.SubElement(
                    defs,
                    "marker",
                    {
                        "id": f"{prefix}-{name}",
                        "viewBox": "0 0 10 10",
                        "refX": ref_x,
                        "refY": "5",
                        "markerWidth": "6",
                        "markerHeight": "6",
                        "orient": "auto",
                    },
                )
                ET.SubElement(marker, "path", {"d": shape, "fill": color})
        self.rect(0, 0, 1280, height, fill="url(#background)", radius=20, stroke="none")
        self.rect(40, 28, 4, 28, fill=TEAL, radius=2, stroke="none")
        self.text(58, 47, eyebrow, size=12, color=TEAL, weight="700", spacing="1.6")
        self.text(40, 101, title, size=36, weight="700")
        self.text(40, 137, subtitle, size=18, color=MUTED)

    def rect(self, x, y, width, height, *, fill=PANEL, stroke=BORDER, radius=14):
        return ET.SubElement(
            self.root,
            "rect",
            {
                "x": str(x),
                "y": str(y),
                "width": str(width),
                "height": str(height),
                "rx": str(radius),
                "fill": fill,
                "stroke": stroke,
            },
        )

    def text(self, x, y, lines, *, size=18, color=TEXT, weight="400", leading=None, spacing=None):
        if isinstance(lines, str):
            lines = [lines]
        attributes = {
            "x": str(x),
            "y": str(y),
            "fill": color,
            "font-size": str(size),
            "font-family": "DejaVu Sans, Arial, sans-serif",
            "font-weight": weight,
        }
        if spacing:
            attributes["letter-spacing"] = spacing
        element = ET.SubElement(self.root, "text", attributes)
        for index, line in enumerate(lines):
            ET.SubElement(
                element,
                "tspan",
                {
                    "x": str(x),
                    "dy": "0" if index == 0 else str(leading or size + 8),
                },
            ).text = line
        return element

    def path(self, data, *, color=TEAL, arrow=False, start_arrow=False, dashed=False, width=2):
        attributes = {"d": data, "fill": "none", "stroke": color, "stroke-width": str(width)}
        name = "blue" if color == BLUE else "amber" if color == AMBER else "teal"
        if arrow:
            attributes["marker-end"] = f"url(#arrow-{name})"
        if start_arrow:
            attributes["marker-start"] = f"url(#arrow-start-{name})"
        if dashed:
            attributes["stroke-dasharray"] = "7 6"
        return ET.SubElement(self.root, "path", attributes)

    def card(self, x, y, width, height, title, lines, *, color=TEAL, title_size=22):
        self.rect(x, y, width, height)
        self.rect(x + 18, y + 22, 3, 24, fill=color, stroke="none", radius=1)
        self.text(x + 34, y + 42, title, size=title_size, weight="700")
        self.text(x + 24, y + 78, lines, size=17, color=MUTED, leading=25)

    def notice(self, y, lines, *, color=AMBER, height=56):
        self.rect(40, y, 1200, height, fill="#172a32", stroke="#41535e", radius=10)
        self.text(58, y + 25, lines, size=16, color=color, leading=23)

    def serialize(self) -> str:
        ET.indent(self.root, space="  ")
        return ET.tostring(self.root, encoding="unicode") + "\n"


def nature() -> str:
    diagram = Diagram(
        "La nature du projet, en un coup d’œil",
        "Sentinel Bridge est un laboratoire SOC/PFE : un SIEM pour centraliser, "
        "des investigations multi-sources et du SOAR conditionnel. Analystes, opérateurs "
        "et développeurs partagent une API modulaire. Ce n’est pas un IPS inline ni un produit certifié.",
        700,
        "SENTINEL BRIDGE / 01 · NATURE",
        "Monorepo · API modulaire · deux interfaces React · services externes à connecter",
    )
    cards = (
        (
            40,
            "01 / SIEM",
            "Centraliser",
            ["Wazuh · Suricata · syslog", "Normalisation et règles", "Sévérité et contexte"],
            ["Des signaux comparables", "pour le travail de l’analyste"],
            TEAL,
        ),
        (
            452,
            "02 / INVESTIGATION XDR",
            "Expliquer",
            ["Cases et preuves", "Contexte multi-sources", "Assistance IA optionnelle"],
            ["Un dossier partagé", "pour comprendre l’incident"],
            BLUE,
        ),
        (
            864,
            "03 / ORCHESTRATION SOAR",
            "Agir sous contrôle",
            ["Playbooks et recommandations", "Approbation si requise", "Connecteurs Wazuh / SSH"],
            ["Des résultats à vérifier", "pas un blocage inline"],
            VIOLET,
        ),
    )
    for x, label, title, lines, result, color in cards:
        diagram.rect(x, 180, 376, 294)
        diagram.text(x + 24, 216, label, size=12, color=color, weight="700", spacing="1")
        diagram.text(x + 24, 257, title, size=26, weight="700")
        diagram.text(x + 24, 297, lines, size=18, color=MUTED, leading=29)
        diagram.path(f"M{x + 24} 380H{x + 352}", color=BORDER, width=1)
        diagram.text(x + 24, 408, "APPORT", size=11, color=color, weight="700", spacing="1.5")
        diagram.text(x + 24, 438, result, size=18, leading=25)
    diagram.rect(40, 510, 1200, 108)
    for x, label, body in (
        (64, "ANALYSTE", ["Trier, investiguer", "et suivre les résultats"]),
        (468, "OPÉRATEUR AUTORISÉ", ["Configurer les sources", "et administrer les accès"]),
        (872, "DÉVELOPPEUR", ["Tester les parcours", "et étendre les connecteurs"]),
    ):
        diagram.text(x, 541, label, size=12, color=TEAL, weight="700", spacing="1")
        diagram.text(x, 572, body, size=18, leading=25)
    diagram.notice(644, "Pas d’IPS inline. Pas de certification. Connecteurs et déploiement à préparer.", height=40)
    return diagram.serialize()


def architecture() -> str:
    diagram = Diagram(
        "Carte logique des composants",
        "Les interfaces SOC et admin et les webhooks Wazuh/Suricata utilisent le processus FastAPI. "
        "Le backend contient les contrôles d’accès, le pipeline et le bus local avec les modules métier. "
        "PostgreSQL conserve les données. Redis transporte les jobs Celery et les Streams syslog. "
        "Le récepteur syslog est séparé. Les playbooks directs utilisent des threads du processus appelant. "
        "Les services de TI, IA, notification et réponse sont optionnels et exigent leur configuration.",
        1090,
        "SENTINEL BRIDGE / 02 · ARCHITECTURE",
        "Schéma de composants, pas une topologie de production ni une garantie de livraison.",
    )
    diagram.text(
        40,
        163,
        "TRAIT CONTINU : FLUX REPRÉSENTÉ    ·    POINTILLÉS : SOURCES À ACTIVER / CONFIGURER",
        size=12,
        color=MUTED,
    )
    diagram.card(40, 192, 280, 112, "Interface SOC", ["React · Vite", "HTTP et WebSocket"], title_size=21)
    diagram.card(346, 192, 280, 112, "Console admin", ["React · Vite", "HTTP / accès opérateur"], title_size=21)
    diagram.card(754, 192, 222, 112, "Wazuh", ["Manager externe", "Webhook / API"], color=AMBER)
    diagram.card(1002, 192, 238, 112, "Suricata", ["Sonde externe", "EVE JSON / NDJSON"], color=AMBER)
    diagram.path("M180 304V330H333V366", arrow=True)
    diagram.path("M486 304V330H333")
    diagram.path("M865 304V330H995V366", color=AMBER, dashed=True, arrow=True)
    diagram.path("M1121 304V330H995", color=AMBER, dashed=True)
    diagram.rect(40, 366, 1200, 242, fill="#0b2530", stroke="#286b73")
    diagram.text(64, 397, "PROCESSUS API / FastAPI", size=14, color=TEAL, weight="700", spacing="1")
    diagram.card(
        64,
        423,
        336,
        154,
        "Interfaces + contrôles",
        ["Routes et credentials", "Rôles, scopes, contexte tenant", "Adaptation des payloads"],
        title_size=21,
    )
    diagram.card(
        464,
        423,
        340,
        154,
        "Pipeline + détection",
        ["Normaliser, enrichir si activé", "Dédupliquer, persister", "Évaluer les règles"],
        title_size=21,
    )
    diagram.card(
        864,
        423,
        352,
        154,
        "Bus + modules métier",
        ["Outbox, cases et investigations", "Déclencheurs sous conditions", "SOAR direct : threads locaux"],
        title_size=21,
    )
    diagram.path("M412 499H452", arrow=True)
    diagram.path("M816 499H852", arrow=True)
    diagram.path("M224 608V684", arrow=True)
    diagram.text(240, 650, "SQL", size=14, color=TEAL)
    diagram.path("M1040 608V638H501V684", color=BLUE, arrow=True)
    diagram.text(745, 629, "Dispatch des jobs configurés", size=14, color=BLUE)
    diagram.card(
        40,
        684,
        300,
        144,
        "PostgreSQL",
        ["TimescaleDB", "Alertes, cases, règles, outbox", "Accès API et workers"],
        title_size=22,
    )
    diagram.card(
        382, 684, 238, 144, "Redis", ["Broker et résultats", "Streams syslog", "Rate-limit / cache"], color=BLUE
    )
    diagram.card(
        662,
        684,
        300,
        144,
        "Celery + Beat",
        ["Jobs et planification", "Files celery / investigation", "Consommateurs à configurer"],
        color=BLUE,
    )
    diagram.card(
        1004,
        684,
        236,
        144,
        "Syslog séparé",
        ["TCP / UDP 1514", "Résolution IP → tenant", "Publication en Stream"],
        color=BLUE,
        title_size=20,
    )
    diagram.path("M631 754H651", color=BLUE, start_arrow=True, arrow=True)
    diagram.path("M1122 828V861H501V828", color=BLUE, arrow=True)
    diagram.text(970, 853, "Redis Stream", size=14, color=BLUE)
    diagram.text(
        40, 907, "CONNECTEURS OPTIONNELS / SELON LE MODULE, LES PERMISSIONS ET LA CONFIGURATION", size=12, color=AMBER
    )
    diagram.card(40, 925, 376, 96, "Threat Intelligence", ["AbuseIPDB · pipeline et jobs"], color=AMBER, title_size=21)
    diagram.card(452, 925, 376, 96, "Assistance IA", ["Ollama / HF Router · à configurer"], color=AMBER, title_size=21)
    diagram.card(
        864,
        925,
        376,
        96,
        "Actions et notifications",
        ["Wazuh / SSH · SMTP / Telegram / HTTP"],
        color=AMBER,
        title_size=20,
    )
    diagram.text(
        40,
        1060,
        "Attention : un bus local, une outbox SQL et un broker Redis sont trois mécanismes différents.",
        size=16,
        color=MUTED,
    )
    return diagram.serialize()


def lifecycle() -> str:
    diagram = Diagram(
        "Huit étapes pour lire le parcours SOC",
        "Parcours pédagogique : collecter, structurer, contextualiser, dédupliquer, corréler, "
        "investiguer, décider et capitaliser. Les doublons sortent avant la corrélation. "
        "Une correspondance peut déclencher des branches indépendantes d’investigation ou de SOAR. "
        "Toute alerte ne devient pas automatiquement une case, une action ou un rapport.",
        890,
        "SENTINEL BRIDGE / 03 · PARCOURS D’UN ÉVÉNEMENT",
        "Lire de gauche à droite, puis suivre le retour. Les branches détaillées sont dans le guide.",
    )
    positions = ((40, 180), (346, 180), (652, 180), (958, 180), (958, 494), (652, 494), (346, 494), (40, 494))
    steps = (
        ("ENTRÉE", "Collecter", ["Wazuh, Suricata, syslog", "ou injection de laboratoire"], ["Payload reçu"], TEAL),
        (
            "FORMAT",
            "Structurer",
            ["Tenant, temps, IP et type", "Adaptateurs de normalisation"],
            ["Événement canonique"],
            TEAL,
        ),
        ("CONTEXTE", "Sévérité et TI", ["Échelle 0–15", "TI uniquement si activée"], ["normalized_severity"], TEAL),
        (
            "BRUIT",
            "Dédupliquer",
            ["Empreinte et fenêtre", "Compteurs du pipeline"],
            ["accepted / deduped", "/ suppressed"],
            TEAL,
        ),
        (
            "DÉTECTION",
            "Corréler",
            ["Conditions et séquences", "Contexte MITRE si présent"],
            ["Match ou aucun match"],
            BLUE,
        ),
        (
            "ENQUÊTE",
            "Investiguer",
            ["Si déclenchée : case", "preuves, score et synthèse"],
            ["Investigation / Case"],
            BLUE,
        ),
        (
            "CONTRÔLE",
            "Décider / répondre",
            ["Approbation si requise", "Connecteurs autorisés"],
            ["Résultat ou attente"],
            AMBER,
        ),
        (
            "RESTITUTION",
            "Capitaliser",
            ["Clôture, rapports et exports", "Livraison selon configuration"],
            ["Timeline / rapport"],
            VIOLET,
        ),
    )
    for index, ((x, y), (label, title, lines, outputs, color)) in enumerate(zip(positions, steps, strict=True), 1):
        diagram.rect(x, y, 282, 240)
        diagram.text(x + 22, y + 35, f"0{index} / {label}", size=12, color=color, weight="700", spacing="1")
        diagram.text(x + 22, y + 79, title, size=23, weight="700")
        diagram.text(x + 22, y + 115, lines, size=16, color=MUTED, leading=25)
        diagram.path(f"M{x + 22} {y + 164}H{x + 260}", color=BORDER, width=1)
        diagram.text(x + 22, y + 184, "SORTIE / REPÈRE", size=11, color=color, weight="700", spacing="1")
        diagram.text(x + 22, y + 208, outputs, size=16, leading=19)
    for left in (322, 628, 934):
        diagram.path(f"M{left + 3} 300H{left + 20}", arrow=True)
    diagram.path("M1099 431V483", arrow=True)
    diagram.text(1116, 462, "si accepté", size=13, color=TEAL)
    for right in (958, 652, 346):
        diagram.path(f"M{right - 3} 614H{right - 20}", color=BLUE, dashed=True, arrow=True)
    diagram.path("M1099 734V768H487V734", color=AMBER, dashed=True, arrow=True)
    diagram.text(666, 757, "SOAR direct si éligible : sans attendre l’investigation", size=13, color=AMBER)
    diagram.notice(
        790,
        [
            "01–05 : chemin d’ingestion. Doublons et événements supprimés ne poursuivent pas ce chemin.",
            "06–08 : parcours conditionnels. Un match peut déclencher l’investigation, le SOAR ou les deux.",
        ],
        height=65,
    )
    return diagram.serialize()


def value() -> str:
    diagram = Diagram(
        "Du problème au bénéfice attendu",
        "Cinq liens qualitatifs entre un problème SOC, un mécanisme du code et son apport attendu. "
        "Ces bénéfices ne sont pas des résultats chiffrés : logs dispersés vers lecture cohérente, "
        "répétitions vers déduplication, contexte éparpillé vers dossier partagé, actions vers contrôle, "
        "évolutions en silos vers couches et tests.",
        850,
        "SENTINEL BRIDGE / 04 · VALEUR APPORTÉE",
        "Des objectifs explicables, sans pourcentage de gain, SLA ou ROI inventé.",
    )
    for x, title, color in (
        (40, "PROBLÈME OBSERVÉ", MUTED),
        (460, "MÉCANISME DU CODE", BLUE),
        (880, "APPORT ATTENDU", TEAL),
    ):
        diagram.text(x + 20, 181, title, size=12, color=color, weight="700", spacing="1.2")
    rows = (
        (["Sources de logs", "dispersées"], ["Normalisation", "et corrélation"], ["Lecture cohérente", "des signaux"]),
        (["Alertes", "répétitives"], ["Déduplication", "sur fenêtre"], ["Moins de répétitions", "à présenter"]),
        (["Contexte", "éparpillé"], ["Cases, preuves", "et timeline"], ["Investigation", "partageable"]),
        (
            ["Actions difficiles", "à expliquer"],
            ["Approbation", "et résultats tracés"],
            ["Décision et effets", "plus explicites"],
        ),
        (
            ["Évolutions", "en silos"],
            ["Couches, connecteurs", "et tests"],
            ["Base pédagogique", "plus facile à étendre"],
        ),
    )
    for index, row in enumerate(rows):
        y = 204 + index * 116
        for column, lines in enumerate(row):
            x = (40, 460, 880)[column]
            color = (MUTED, BLUE, TEAL)[column]
            diagram.rect(x, y, 360, 94, stroke="#28685f" if column == 2 else BORDER)
            diagram.rect(x + 18, y + 23, 3, 46, fill=color, radius=1, stroke="none")
            diagram.text(x + 38, y + 39, lines, size=20, weight="700" if column == 2 else "400", leading=29)
        diagram.path(f"M412 {y + 47}H448", color=BLUE, arrow=True)
        diagram.path(f"M832 {y + 47}H868", arrow=True)
    diagram.notice(
        800, "Ces apports dépendent des règles, des connecteurs, des droits et de l’exploitation effective.", height=40
    )
    return diagram.serialize()


BUILDERS = {
    "project-nature.svg": nature,
    "architecture-map.svg": architecture,
    "incident-lifecycle.svg": lifecycle,
    "value-map.svg": value,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check generated SVGs without modifying any file.")
    args = parser.parse_args()
    failed = False
    if not args.check:
        ASSETS.mkdir(parents=True, exist_ok=True)
    for filename, builder in BUILDERS.items():
        path = ASSETS / filename
        expected = builder()
        if args.check:
            matches = path.is_file() and path.read_text(encoding="utf-8") == expected
            print(f"{'OK' if matches else 'OUTDATED'} {path.relative_to(ASSETS.parent)}")
            failed |= not matches
        else:
            path.write_text(expected, encoding="utf-8")
            print(f"Wrote {path.relative_to(ASSETS.parent)}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
