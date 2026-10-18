"""Providers TI — AbuseIPDB (actif), VirusTotal et Kaspersky (optionnels, stub conforme API officielle)."""
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
KASPERSKY_URL = "https://opentip.kaspersky.com/api/v1/search/ip"  # placeholder URL conforme doc OpenTIP

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_UNKNOWN = "unknown"


def _verdict_from_score(score: int) -> str:
    if score >= 80:
        return VERDICT_MALICIOUS
    if score >= 40:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


# ── AbuseIPDB ────────────────────────────────────────────────────────

def fetch_abuseipdb(ip: str, api_key: str, timeout: int = 10) -> dict[str, Any]:
    """Appel réel AbuseIPDB — mockable dans tests."""
    with httpx.Client(timeout=timeout) as client:
        r = client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "verdict": _verdict_from_score(int(d.get("abuseConfidenceScore") or 0)),
            "risk_score": int(d.get("abuseConfidenceScore") or 0),
            "source_name": "AbuseIPDB",
            "raw_json": json.dumps(d, default=str),
            "provider": "abuseipdb",
        }


# ── VirusTotal ───────────────────────────────────────────────────────

def fetch_virustotal(ip: str, api_key: str, timeout: int = 10) -> dict[str, Any]:
    """
    VirusTotal IP report.
    API doc: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}  header x-apikey
    Réponse: data.attributes.last_analysis_stats {malicious, suspicious, harmless, undetected}
    Mapping: malicious>0 → malicious, suspicious>0 → suspicious, sinon clean.
    Quota: dépend clé (public 500/j, premium plus). Géré côté SystemConfig/quota check.
    """
    url = VIRUSTOTAL_URL.format(ip=ip)
    with httpx.Client(timeout=timeout) as client:
        r = client.get(url, headers={"x-apikey": api_key, "Accept": "application/json"})
        r.raise_for_status()
        j = r.json()
        attrs = j.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        reputation = int(attrs.get("reputation") or 0)
        if malicious > 0:
            verdict = VERDICT_MALICIOUS
            score = min(100, 40 + malicious * 10)
        elif suspicious > 0:
            verdict = VERDICT_SUSPICIOUS
            score = min(79, 20 + suspicious * 10)
        elif stats.get("harmless") is not None:
            verdict = VERDICT_CLEAN
            score = max(0, 100 - (reputation if reputation > 0 else 50))
            # clamp clean score low
            score = min(score, 10)
        else:
            verdict = VERDICT_UNKNOWN
            score = 0
        return {
            "verdict": verdict,
            "risk_score": score,
            "source_name": "VirusTotal",
            "raw_json": json.dumps({"stats": stats, "reputation": reputation}, default=str),
            "provider": "virustotal",
        }


# ── Kaspersky Threat Lookup ─────────────────────────────────────────

def fetch_kaspersky(ip: str, api_key: str, timeout: int = 10) -> dict[str, Any]:
    """
    Kaspersky Threat Intelligence Portal / OpenTIP.
    Doc: https://opentip.kaspersky.com/api/v1/search/ip?request={ip}
    Nécessite clé partenaire. Si non configuré, renvoie unknown (jamais lève).
    Réponse (exemple): {"Zone": "Red" | "Yellow" | "Green" | "Grey", "score": 0-100}
    Mapping: Red → malicious, Yellow → suspicious, Green → clean, Grey → unknown
    """
    if not api_key:
        return {
            "verdict": VERDICT_UNKNOWN,
            "risk_score": None,
            "source_name": "Kaspersky",
            "raw_json": None,
            "provider": "kaspersky",
        }
    with httpx.Client(timeout=timeout) as client:
        r = client.get(
            KASPERSKY_URL,
            params={"request": ip},
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json()
        zone = str(d.get("Zone") or d.get("zone") or "").lower()
        score = d.get("score")
        try:
            score = int(score) if score is not None else None
        except Exception:
            score = None
        mapping = {"red": VERDICT_MALICIOUS, "yellow": VERDICT_SUSPICIOUS, "green": VERDICT_CLEAN, "grey": VERDICT_UNKNOWN}
        verdict = mapping.get(zone, VERDICT_UNKNOWN)
        return {
            "verdict": verdict,
            "risk_score": score,
            "source_name": "Kaspersky",
            "raw_json": json.dumps(d, default=str),
            "provider": "kaspersky",
        }
