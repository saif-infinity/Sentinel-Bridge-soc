"""Dependency-free checks for the visual documentation.

Run from the repository root:
    python3 -m unittest discover -s docs/tests -v

Browser interaction and accessibility still require a browser-based review.
These tests do not import the backend, contact services or change SVG outputs.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SVG_NS = {"svg": "http://www.w3.org/2000/svg"}


class GuideParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class VisualGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (DOCS / "index.html").read_text(encoding="utf-8")
        cls.javascript = (DOCS / "assets/visual-guide.js").read_text(encoding="utf-8")
        parser = GuideParser()
        parser.feed(cls.html)
        cls.elements = parser.elements

    def test_unique_ids_and_accessibility_references(self):
        ids = [attrs["id"] for _, attrs in self.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate HTML IDs")
        for _, attrs in self.elements:
            for name in ("aria-labelledby", "aria-controls"):
                for ref in (attrs.get(name) or "").split():
                    with self.subTest(attribute=name, reference=ref):
                        self.assertIn(ref, ids)
        self.assertIn(("html", {"lang": "fr"}), self.elements)

    def test_local_assets_exist_and_need_no_remote_host(self):
        checked = 0
        for tag, attrs in self.elements:
            for name in ("src", "href"):
                target = attrs.get(name)
                if not target or target.startswith("#"):
                    continue
                url = urlsplit(target)
                if url.scheme or url.netloc:
                    self.assertEqual(tag, "a", "A runtime resource requires a remote host")
                    continue
                path = (DOCS / unquote(url.path)).resolve()
                with self.subTest(target=target):
                    self.assertTrue(path.is_relative_to(DOCS))
                    self.assertTrue(path.is_file(), f"Missing asset: {path}")
                checked += 1
        self.assertGreaterEqual(checked, 8)
        self.assertNotRegex(self.javascript, r"\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(")
        self.assertNotIn("innerHTML", self.javascript)

    def test_eight_steps_and_four_views_have_explicit_labels(self):
        steps = [attrs for _, attrs in self.elements if "data-step" in attrs]
        self.assertEqual([attrs["data-step"] for attrs in steps], [str(index) for index in range(8)])
        self.assertEqual(Counter(attrs.get("aria-selected") for attrs in steps), {"true": 1, "false": 7})
        self.assertTrue(all(attrs.get("role") == "tab" for attrs in steps))
        views = [attrs["data-view"] for _, attrs in self.elements if "data-view" in attrs]
        self.assertEqual(views, ["apercu", "architecture", "parcours", "avantages"])

    def test_component_hotspots_match_the_generated_diagram(self):
        svg = ET.parse(DOCS / "assets/architecture-map.svg").getroot()
        width, height = map(float, (svg.get("width"), svg.get("height")))
        rects = [
            tuple(float(rect.get(key, "0")) for key in ("x", "y", "width", "height"))
            for rect in svg.findall(".//svg:rect", SVG_NS)
        ]
        hotspots = [attrs for _, attrs in self.elements if "data-component" in attrs]
        self.assertEqual(len(hotspots), 14)
        self.assertEqual(len({attrs["data-component"] for attrs in hotspots}), 14)
        component_source = self.javascript.split("const components =", 1)[1].split("const steps =", 1)[0]
        for attrs in hotspots:
            component = attrs["data-component"]
            with self.subTest(component=component):
                self.assertRegex(component_source, rf"\b{re.escape(component)}:\s*\{{")
                self.assertTrue(attrs.get("aria-label"))
                coords = dict(re.findall(r"--([xywh]):\s*([\d.]+)%", attrs["style"]))
                self.assertEqual(set(coords), {"x", "y", "w", "h"})
                actual = tuple(
                    float(coords[key]) * dimension / 100
                    for key, dimension in zip(("x", "y", "w", "h"), (width, height, width, height), strict=True)
                )
                self.assertTrue(
                    any(all(abs(a - b) < 0.25 for a, b in zip(actual, rect, strict=True)) for rect in rects),
                    "Hotspot no longer matches a diagram rectangle; update its percentages after geometry changes",
                )

    def test_source_references_point_to_real_files(self):
        paths = set(re.findall(r'"((?:backend|frontend|admin-frontend)/[^"\n]+)"', self.javascript))
        self.assertGreaterEqual(len(paths), 20)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), f"Stale source reference: {path}")

    def test_svg_assets_are_self_contained_and_accessible(self):
        for path in (DOCS / "assets").glob("*.svg"):
            with self.subTest(svg=path.name):
                root = ET.parse(path).getroot()
                self.assertEqual(root.get("role"), "img")
                self.assertTrue(root.find("svg:title", SVG_NS).text)
                self.assertTrue(root.find("svg:desc", SVG_NS).text)
                ids = [node.get("id") for node in root.iter() if node.get("id")]
                self.assertEqual(len(ids), len(set(ids)))
                for ref in root.get("aria-labelledby", "").split():
                    self.assertIn(ref, ids)
                for node in root.iter():
                    self.assertNotIn(node.tag.split("}")[-1].lower(), {"script", "foreignobject", "image"})
                    for name, value in node.attrib.items():
                        self.assertFalse(name.lower().startswith("on"))
                        if name.endswith("href"):
                            self.assertTrue(value.startswith("#"))

    def test_svg_generation_check_does_not_change_outputs(self):
        files = sorted((DOCS / "assets").glob("*.svg"))
        before = {path.name: path.read_bytes() for path in files}
        result = subprocess.run(
            [sys.executable, str(DOCS / "diagrams/generate.py"), "--check"],
            cwd=DOCS,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, {path.name: path.read_bytes() for path in files})

    def test_static_fallback_is_available_without_javascript(self):
        self.assertGreaterEqual(sum(tag == "noscript" for tag, _ in self.elements), 2)
        views = [attrs for tag, attrs in self.elements if tag == "section" and attrs.get("class") == "view"]
        self.assertEqual(len(views), 4)
        self.assertTrue(all("hidden" not in attrs for attrs in views))
        self.assertIn('href="ARCHITECTURE.md#etapes"', self.html)


if __name__ == "__main__":
    unittest.main()
