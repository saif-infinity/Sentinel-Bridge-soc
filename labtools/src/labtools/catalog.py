"""Inventaire des outils du laboratoire et recherche plein texte."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_INVENTORY = Path(__file__).resolve().parent / "data" / "inventory.json"
REQUIRED_FIELDS = (
    "id", "name", "category", "purpose", "homepage", "language", "lab_safe", "tags",
)


class CatalogError(RuntimeError):
    """Inventaire absent, illisible ou invalide."""


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    category: str
    purpose: str
    homepage: str
    language: str
    lab_safe: bool
    tags: tuple[str, ...]
    caution: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Tool:
        missing = [field for field in REQUIRED_FIELDS if field not in raw]
        if missing:
            raise CatalogError(
                f"outil {raw.get('id', '?')!r} : champ(s) manquant(s) : "
                f"{', '.join(missing)}"
            )
        tags = raw.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise CatalogError(f"outil {raw['id']!r} : « tags » doit être une liste de chaînes")
        return cls(
            id=str(raw["id"]),
            name=str(raw["name"]),
            category=str(raw["category"]),
            purpose=str(raw["purpose"]),
            homepage=str(raw["homepage"]),
            language=str(raw["language"]),
            lab_safe=bool(raw["lab_safe"]),
            tags=tuple(tags),
            caution=str(raw.get("caution", "")),
        )

    @property
    def searchable(self) -> str:
        return " ".join(
            (self.id, self.name, self.category, self.purpose, self.language,
             *self.tags, self.caution)
        ).lower()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "purpose": self.purpose,
            "homepage": self.homepage,
            "language": self.language,
            "lab_safe": self.lab_safe,
            "tags": list(self.tags),
            "caution": self.caution,
        }


@dataclass(frozen=True)
class Catalog:
    tools: tuple[Tool, ...]

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for tool in self.tools:
            counts[tool.category] = counts.get(tool.category, 0) + 1
        return dict(sorted(counts.items()))

    def filter(
        self,
        *,
        category: str | None = None,
        query: str | None = None,
        lab_safe_only: bool = False,
    ) -> list[Tool]:
        selected = list(self.tools)
        if category:
            wanted = category.strip().lower()
            selected = [tool for tool in selected if tool.category.lower() == wanted]
        if query:
            terms = [term for term in query.lower().split() if term]
            selected = [
                tool for tool in selected
                if all(term in tool.searchable for term in terms)
            ]
        if lab_safe_only:
            selected = [tool for tool in selected if tool.lab_safe]
        return sorted(selected, key=lambda tool: (tool.category, tool.name.lower()))

    def find(self, tool_id: str) -> Tool | None:
        wanted = tool_id.strip().lower()
        for tool in self.tools:
            if tool.id.lower() == wanted:
                return tool
        return None


def load_catalog(path: str | Path | None = None) -> Catalog:
    """Charge l'inventaire JSON (par défaut celui embarqué dans le paquet)."""

    source = Path(path) if path else DEFAULT_INVENTORY
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogError(f"inventaire introuvable : {source}") from exc
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{source} : JSON invalide ({exc.msg})") from exc

    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise CatalogError(f"{source} : objet racine avec clé « tools » attendu")
    tools = tuple(Tool.from_dict(raw) for raw in data["tools"])
    if not tools:
        raise CatalogError(f"{source} : inventaire vide")
    identifiers = [tool.id for tool in tools]
    duplicates = {item for item in identifiers if identifiers.count(item) > 1}
    if duplicates:
        raise CatalogError(f"{source} : identifiants dupliqués : {', '.join(sorted(duplicates))}")
    return Catalog(tools=tools)


def format_table(tools: list[Tool]) -> str:
    """Tableau compact pour le terminal."""

    if not tools:
        return "Aucun outil ne correspond aux filtres."
    width_id = max(len(tool.id) for tool in tools)
    width_category = max(len(tool.category) for tool in tools)
    lines = [
        f"{'ID'.ljust(width_id)}  {'CATÉGORIE'.ljust(width_category)}  "
        f"{'LAB'.ljust(3)}  NOM / OBJECTIF"
    ]
    for tool in tools:
        flag = "oui" if tool.lab_safe else "non"
        purpose = tool.purpose
        if len(purpose) > 64:
            purpose = purpose[:61] + "…"
        lines.append(
            f"{tool.id.ljust(width_id)}  {tool.category.ljust(width_category)}  "
            f"{flag.ljust(3)}  {tool.name} — {purpose}"
        )
    return "\n".join(lines)


def format_details(tool: Tool) -> str:
    """Fiche détaillée d'un outil."""

    lines = [
        f"{tool.name} ({tool.id})",
        f"  Catégorie : {tool.category}",
        f"  Objectif  : {tool.purpose}",
        f"  Langage   : {tool.language}",
        f"  Dépôt     : {tool.homepage}",
        f"  Laboratoire : {'oui' if tool.lab_safe else 'non — voir avertissement'}",
    ]
    if tool.tags:
        lines.append(f"  Mots-clés : {', '.join(tool.tags)}")
    if tool.caution:
        lines.append(f"  Prudence  : {tool.caution}")
    return "\n".join(lines)
