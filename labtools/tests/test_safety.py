"""Tests de la politique de ciblage (garde-fous réseau)."""

from __future__ import annotations

import pytest

from labtools.safety import (
    MAX_PUBLIC_PORTS,
    SafetyError,
    classify_address,
    ensure_lab_target,
    ensure_url_allowed,
    resolve_target,
)


@pytest.mark.parametrize(
    ("address", "zone"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.0.0.5", "private"),
        ("172.16.4.9", "private"),
        ("192.168.1.10", "private"),
        ("169.254.1.1", "private"),
        ("192.0.2.10", "private"),  # documentation RFC 5737 : non routable
        ("8.8.8.8", "public"),
        ("2001:4860:4860::8888", "public"),
    ],
)
def test_classify_address(address, zone):
    assert classify_address(address) == zone


def test_localhost_is_lab():
    scope = resolve_target("localhost")
    assert scope.is_lab
    assert scope.addresses
    assert ensure_lab_target("localhost").is_lab


def test_private_target_allowed_without_flag():
    scope = ensure_lab_target("10.20.30.40", purpose="test")
    assert scope.zone == "private"


def test_public_target_refused_by_default():
    with pytest.raises(SafetyError, match="Cible publique refusée"):
        ensure_lab_target("8.8.8.8")


def test_public_target_allowed_with_flag():
    assert ensure_lab_target("8.8.8.8", allow_public=True).is_public


def test_env_flag_allows_public(monkeypatch):
    monkeypatch.setenv("LABTOOLS_ALLOW_PUBLIC", "1")
    assert ensure_lab_target("8.8.8.8").is_public


def test_public_many_ports_requires_extra_flag():
    with pytest.raises(SafetyError, match="allow-many-ports"):
        ensure_lab_target(
            "8.8.8.8", allow_public=True, port_count=MAX_PUBLIC_PORTS + 1
        )
    scope = ensure_lab_target(
        "8.8.8.8",
        allow_public=True,
        port_count=MAX_PUBLIC_PORTS + 1,
        allow_many_ports=True,
    )
    assert scope.is_public


def test_private_many_ports_is_fine():
    ensure_lab_target("10.0.0.1", port_count=5000)


def test_unresolved_target_refused_by_default():
    scope = resolve_target("nom-qui-nexiste-pas.invalid")
    assert scope.zone == "unresolved"
    with pytest.raises(SafetyError, match="Impossible de vérifier"):
        ensure_lab_target("nom-qui-nexiste-pas.invalid")


def test_unresolved_target_allowed_with_flag():
    scope = ensure_lab_target("nom-qui-nexiste-pas.invalid", allow_public=True)
    assert scope.zone == "unresolved"


def test_empty_target():
    with pytest.raises(SafetyError, match="cible vide"):
        ensure_lab_target("   ")


@pytest.mark.parametrize("url", ["ftp://localhost/x", "file:///etc/passwd", "localhost:8000"])
def test_bad_url_scheme(url):
    with pytest.raises(SafetyError, match="http"):
        ensure_url_allowed(url)


def test_credentials_in_url_refused():
    with pytest.raises(SafetyError, match="identifiants"):
        ensure_url_allowed("http://user:secret@localhost:8000/ingest")


def test_public_url_refused():
    with pytest.raises(SafetyError, match="Cible publique"):
        ensure_url_allowed("https://example.com/hook")


def test_private_url_allowed():
    scope = ensure_url_allowed("http://127.0.0.1:8000/api/pipeline/ingest")
    assert scope.is_lab


def test_addresses_text_truncates():
    scope = resolve_target("localhost")
    assert scope.addresses_text()
