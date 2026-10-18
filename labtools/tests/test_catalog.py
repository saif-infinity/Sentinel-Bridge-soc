"""Tests de l'inventaire d'outils."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from labtools.catalog import CatalogError, format_details, format_table, load_catalog

CATEGORIES = {"collecte", "reseau", "endpoint", "detection", "conteneurs", "charge", "soc"}


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


def test_inventory_loads(catalog):
    assert len(catalog.tools) >= 25
    assert all(tool.homepage.startswith("http") for tool in catalog.tools)
    assert all(tool.category in CATEGORIES for tool in catalog.tools)


def test_categories_counts(catalog):
    counts = catalog.categories()
    assert sum(counts.values()) == len(catalog.tools)
    assert set(counts) <= CATEGORIES


def test_filter_by_category(catalog):
    selected = catalog.filter(category="collecte")
    assert selected
    assert all(tool.category == "collecte" for tool in selected)


def test_filter_case_insensitive(catalog):
    assert catalog.filter(category="COLLECTE") == catalog.filter(category="collecte")


def test_search_single_and_multiple_terms(catalog):
    assert catalog.filter(query="python")
    windows = catalog.filter(query="windows evtx")
    assert windows
    assert all("windows" in tool.searchable and "evtx" in tool.searchable for tool in windows)


def test_search_no_result(catalog):
    assert catalog.filter(query="zzzz-introuvable") == []


def test_lab_safe_filter(catalog):
    selected = catalog.filter(lab_safe_only=True)
    assert selected
    assert all(tool.lab_safe for tool in selected)
    assert len(selected) < len(catalog.tools)


def test_find(catalog):
    tool = catalog.find("scapy")
    assert tool is not None
    assert tool.name == "Scapy"
    assert catalog.find("SCAPY") is not None
    assert catalog.find("inexistant") is None


def test_formats(catalog):
    table = format_table(catalog.filter(category="reseau"))
    assert "Scapy" in table or "scapy" in table.lower()
    details = format_details(catalog.find("nmap"))
    assert "Nmap" in details
    assert "Prudence" in details
    assert format_table([]) == "Aucun outil ne correspond aux filtres."


def _write(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _tool(**overrides):
    tool = {
        "id": "demo",
        "name": "Demo",
        "category": "collecte",
        "purpose": "test",
        "homepage": "https://example.com",
        "language": "Python",
        "lab_safe": True,
        "tags": ["x"],
    }
    tool.update(overrides)
    return tool


def test_custom_inventory(tmp_path):
    path = _write(tmp_path, {"tools": [_tool()]})
    catalog = load_catalog(path)
    assert len(catalog.tools) == 1
    assert catalog.find("demo").tags == ("x",)


def test_missing_field(tmp_path):
    broken = _tool()
    del broken["purpose"]
    with pytest.raises(CatalogError, match="manquant"):
        load_catalog(_write(tmp_path, {"tools": [broken]}))


def test_duplicate_ids(tmp_path):
    with pytest.raises(CatalogError, match="dupliqués"):
        load_catalog(_write(tmp_path, {"tools": [_tool(), _tool()]}))


def test_bad_root(tmp_path):
    with pytest.raises(CatalogError, match="tools"):
        load_catalog(_write(tmp_path, {"outils": []}))


def test_empty_inventory(tmp_path):
    with pytest.raises(CatalogError, match="vide"):
        load_catalog(_write(tmp_path, {"tools": []}))


def test_missing_file():
    with pytest.raises(CatalogError, match="introuvable"):
        load_catalog("/nonexistent/inventory.json")


def test_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("[", encoding="utf-8")
    with pytest.raises(CatalogError, match="JSON invalide"):
        load_catalog(path)


def test_bad_tags(tmp_path):
    with pytest.raises(CatalogError, match="tags"):
        load_catalog(_write(tmp_path, {"tools": [_tool(tags="x")]}))
