"""F1 — Forme normalisée de l'alerte + évaluation des conditions (événement unique)."""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Clés canoniques de l'alerte normalisée (contrat pipeline ↔ engine ↔ events)
NORMALIZED_KEYS = [
    "alert_id", "tenant_id", "timestamp", "source", "severity",
    "normalized_severity", "signature", "category", "description",
    "src_ip", "dest_ip", "agent_id", "proto", "raw",
    "mitre_attack_ids", "tactics",   # R2 — optionnels (None si absents)
]

# ── R2 MITRE ATT&CK ──────────────────────────────────────────────────
# Mapping technique → (nom, tactiques). Les sous-techniques (T1059.001)
# héritent de la technique parente (T1059).
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactics": ["privilege-escalation", "defense-evasion"]},
    "T1562": {"name": "Impair Defenses", "tactics": ["defense-evasion"]},
    "T1110": {"name": "Brute Force", "tactics": ["credential-access"]},
    "T1021": {"name": "Remote Services", "tactics": ["lateral-movement"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactics": ["exfiltration"]},
    "T1566": {"name": "Phishing", "tactics": ["initial-access"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
    "T1571": {"name": "Non-Standard Port", "tactics": ["command-and-control"]},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["command-and-control"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactics": ["defense-evasion"]},
    "T1003": {"name": "OS Credential Dumping", "tactics": ["credential-access"]},
    "T1036": {"name": "Masquerading", "tactics": ["defense-evasion"]},
    "T1498": {"name": "Network Denial of Service", "tactics": ["impact"]},
    "T1485": {"name": "Data Destruction", "tactics": ["impact"]},
    "T1053": {"name": "Scheduled Task/Job", "tactics": ["execution", "persistence", "privilege-escalation"]},
    "T1055": {"name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"]},
    "T1046": {"name": "Network Service Discovery", "tactics": ["discovery"]},
    "T1016": {"name": "System Network Configuration Discovery", "tactics": ["discovery"]},
    "T1018": {"name": "Remote System Discovery", "tactics": ["discovery"]},
    "T1082": {"name": "System Information Discovery", "tactics": ["discovery"]},
    "T1555": {"name": "Credentials from Password Stores", "tactics": ["credential-access"]},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactics": ["privilege-escalation"]},
    "T1219": {"name": "Remote Access Software", "tactics": ["command-and-control"]},
    "T1505": {"name": "Server Software Component", "tactics": ["persistence"]},
    "T1543": {"name": "Create or Modify System Process", "tactics": ["persistence", "privilege-escalation"]},
    "T1550": {"name": "Use Alternate Authentication Material", "tactics": ["defense-evasion", "lateral-movement"]},
    "T1573": {"name": "Encrypted Channel", "tactics": ["command-and-control"]},
    "T1047": {"name": "Windows Management Instrumentation", "tactics": ["execution"]},
    "T1090": {"name": "Proxy", "tactics": ["command-and-control"]},
    "T1133": {"name": "External Remote Services", "tactics": ["persistence", "initial-access"]},
    "T1567": {"name": "Exfiltration Over Web Service", "tactics": ["exfiltration"]},
    "T1204": {"name": "User Execution", "tactics": ["execution"]},
    "T1210": {"name": "Exploitation of Remote Services", "tactics": ["lateral-movement"]},
    "T1482": {"name": "Domain Trust Discovery", "tactics": ["discovery"]},
    "T1587": {"name": "Develop Capabilities", "tactics": ["resource-development"]},
    "T1588": {"name": "Obtain Capabilities", "tactics": ["resource-development"]},
    "T1583": {"name": "Acquire Infrastructure", "tactics": ["resource-development"]},
    "T1595": {"name": "Active Scanning", "tactics": ["reconnaissance"]},
    "T1598": {"name": "Phishing for Information", "tactics": ["reconnaissance"]},
    "T1589": {"name": "Gather Victim Identity Information", "tactics": ["reconnaissance"]},
    "T1592": {"name": "Gather Victim Host Information", "tactics": ["reconnaissance"]},
}


def mitre_parent(tech_id: str) -> str:
    """T1059.001 -> T1059 (sous-technique -> technique parente)."""
    return str(tech_id).split(".", 1)[0]


def mitre_technique_info(tech_id: str) -> Dict[str, Any]:
    """Infos (nom + tactiques) d'une technique, héritées de la technique parente."""
    base = MITRE_TECHNIQUES.get(mitre_parent(tech_id))
    if base:
        return {"id": tech_id, "name": base["name"], "tactics": list(base["tactics"])}
    return {"id": tech_id, "name": tech_id, "tactics": []}


def mitre_tactics_for(ids: Optional[List[str]]) -> List[str]:
    """Dérive la liste des tactiques depuis les IDs de techniques (dédupliquée)."""
    out: List[str] = []
    for tid in (ids or []):
        for t in mitre_technique_info(tid)["tactics"]:
            if t not in out:
                out.append(t)
    return out

# Mapping de sévérité par défaut (surchargé via SystemConfig section "pipeline", clé "severity_mapping")
DEFAULT_SEVERITY_MAPPING: Dict[str, Any] = {
    "suricata": {1: 15, 2: 10, 3: 5, 4: 2},   # Suricata : 1 = le plus critique
    "wazuh": "clamp",                          # niveau 0-15 conservé tel quel
    "manual": "clamp",
    "default": 5,
}

OPS = {"eq", "ne", "gt", "ge", "lt", "le", "in", "contains", "startswith", "regex", "exists"}


def normalize_severity(source: str, raw: Optional[int], mapping: Optional[dict] = None) -> int:
    """Normalise une sévérité source vers l'échelle uniforme 0-15."""
    m = mapping or DEFAULT_SEVERITY_MAPPING
    try:
        raw = int(raw)
    except (TypeError, ValueError):
        raw = None
    src = (source or "manual").lower()
    rule = m.get(src, m.get("default", 5))
    if isinstance(rule, dict):
        # Les clés peuvent être int (mapping par défaut) ou str (mapping JSON via SystemConfig)
        val = rule.get(raw)
        if val is None:
            val = rule.get(str(raw))
        if val is None:
            val = m.get("default", 5)
        return int(val)
    if raw is None:
        return int(m.get("default", 5))
    return max(0, min(15, raw))


def _get_field(alert: Dict[str, Any], path: str) -> Any:
    cur: Any = alert
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _to_num(v: Any):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def evaluate_condition(cond: Dict[str, Any], alert: Dict[str, Any]) -> bool:
    field = cond.get("field")
    op = str(cond.get("op", "eq")).lower()
    expected = cond.get("value")
    actual = _get_field(alert, field)

    if op == "exists":
        return actual is not None

    if op in ("eq", "ne"):
        match = str(actual) == str(expected) if actual is not None else False
        return match if op == "eq" else (actual is not None and not match)

    if op in ("gt", "ge", "lt", "le"):
        a, b = _to_num(actual), _to_num(expected)
        if a is None or b is None:
            return False
        return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}[op]

    if op == "in":
        return actual is not None and str(actual) in {str(x) for x in (expected or [])}

    if op == "contains":
        return actual is not None and str(expected) in str(actual)

    if op == "startswith":
        return actual is not None and str(actual).startswith(str(expected))

    if op == "regex":
        if actual is None:
            return False
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            return False

    return False


def evaluate_conditions(conditions: List[Dict[str, Any]], alert: Dict[str, Any]) -> List[int]:
    """Retourne la liste des index des conditions satisfaites."""
    matched: List[int] = []
    for i, cond in enumerate(conditions or []):
        try:
            if evaluate_condition(cond, alert):
                matched.append(i)
        except Exception:
            continue
    return matched


def build_normalized_alert(payload: Dict[str, Any], mapping: Optional[dict] = None) -> Dict[str, Any]:
    """Construit l'alerte normalisée canonique depuis un payload brut.

    Si payload contient déjà "normalized_severity", il est conservé
    (calculé par le pipeline) ; sinon il est recalculé ici.
    """
    raw_sev = payload.get("severity")
    source = str(payload.get("source") or "manual").lower()
    norm = payload.get("normalized_severity")
    if norm is None:
        norm = normalize_severity(source, raw_sev, mapping)
    return {
        "alert_id": payload.get("alert_id"),
        "tenant_id": payload.get("tenant_id", "default"),
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "source": source,
        "severity": int(raw_sev) if raw_sev is not None else None,
        "normalized_severity": int(norm),
        "signature": str(payload.get("signature") or payload.get("description") or "")[:255] or None,
        "category": str(payload.get("category") or "")[:100] or None,
        "description": str(payload.get("description") or "")[:500] or None,
        "src_ip": str(payload.get("src_ip") or "")[:45] or None,
        "dest_ip": str(payload.get("dest_ip") or "")[:45] or None,
        "agent_id": str(payload.get("agent_id") or "")[:10] or None,
        "proto": str(payload.get("proto") or "")[:20] or None,
        "raw": payload.get("raw") or payload,
        # R2 — propagation des champs MITRE de la règle matchée (optionnels)
        "mitre_attack_ids": payload.get("mitre_attack_ids") or None,
        "tactics": payload.get("tactics") or None,
    }
