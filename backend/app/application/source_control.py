"""Source toggle control — DB-first, env fallback.

`is_source_enabled(db, source)` reads the effective state from the
`sources` section of SystemConfig (set via PUT /api/settings).
If the DB value is absent (tenant never touched settings), falls back
to the env-derived Settings attributes.
"""
from sqlalchemy.orm import Session

from ..config import settings
from .system_config import get_config_value

SOURCE_MAP = {
    "host_agent": "HOST_AGENT_SOURCE",
    "wazuh": "WAZUH_SOURCE",
    "suricata": "SURICATA_SOURCE",
}

_BOOL_TRUE = {"true", "1", "yes", "on"}


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in _BOOL_TRUE


def is_source_enabled(db: Session, source: str, tenant_id: str = "default") -> bool:
    """Return whether a source is enabled (DB priority, env fallback)."""
    env_attr = SOURCE_MAP.get(source)
    env_default = getattr(settings, f"ENABLE_{env_attr}", False) if env_attr else False

    db_value = get_config_value(db, "sources", source, fallback="", tenant_id=tenant_id)
    if db_value:
        return _parse_bool(db_value)
    return env_default
