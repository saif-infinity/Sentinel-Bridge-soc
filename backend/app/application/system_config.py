from sqlalchemy.orm import Session
from ..models import SystemConfig
from ..config import settings

DEFAULT_CONFIGS = {
    "wazuh_api": {
        "label": "Wazuh API",
        "fields": {
            "url": {"label": "API URL", "default": settings.WAZUH_API_URL, "is_secret": False},
            "user": {"label": "Username", "default": settings.WAZUH_USER, "is_secret": False},
            "password": {"label": "Password", "default": "", "is_secret": True},
        },
    },
    "wazuh_indexer": {
        "label": "Wazuh Indexer (OpenSearch)",
        "fields": {
            "url": {"label": "Indexer URL", "default": settings.WAZUH_INDEXER_URL, "is_secret": False},
            "user": {"label": "Username", "default": settings.WAZUH_INDEXER_USER, "is_secret": False},
            "password": {"label": "Password", "default": "", "is_secret": True},
        },
    },
    "suricata_ssh": {
        "label": "Suricata SSH Connection",
        "fields": {
            "host": {"label": "Host IP", "default": settings.SURICATA_HOST, "is_secret": False},
            "port": {"label": "SSH Port", "default": str(settings.SURICATA_PORT), "is_secret": False},
            "user": {"label": "Username", "default": settings.SURICATA_USER, "is_secret": False},
            "password": {"label": "Password", "default": "", "is_secret": True},
        },
    },
    "wazuh_ssh": {
        "label": "Wazuh Manager SSH",
        "fields": {
            "docker_container": {"label": "Docker Container", "default": settings.WAZUH_DOCKER_CONTAINER, "is_secret": False},
            "ssh_port": {"label": "SSH Port", "default": str(settings.WAZUH_SSH_PORT), "is_secret": False},
            "ssh_user": {"label": "SSH User", "default": settings.WAZUH_SSH_USER, "is_secret": False},
            "ssh_password": {"label": "SSH Password", "default": "", "is_secret": True},
        },
    },
    "ollama": {
        "label": "Ollama LLM",
        "fields": {
            "url": {"label": "Ollama URL", "default": settings.OLLAMA_URL, "is_secret": False},
            "model": {"label": "Model Name", "default": settings.OLLAMA_MODEL, "is_secret": False},
        },
    },
    "redis": {
        "label": "Redis",
        "fields": {
            "url": {"label": "Redis URL", "default": settings.REDIS_URL, "is_secret": False},
            "password": {"label": "Password", "default": settings.REDIS_PASSWORD, "is_secret": True},
        },
    },
    "soar": {
        "label": "Mini-SOAR (Playbooks)",
        "fields": {
            "enabled": {"label": "Activer l'automatisation SOAR", "default": "true", "is_secret": False},
            "requires_approval": {"label": "Approbation requise par défaut", "default": "false", "is_secret": False},
            "max_runs_per_day": {"label": "Runs max par jour et par tenant", "default": "50", "is_secret": False},
            "max_steps_per_run": {"label": "Steps max par run", "default": "10", "is_secret": False},
            "default_timeout_seconds": {"label": "Timeout par défaut (s)", "default": "30", "is_secret": False},
        },
    },
    "threat_intel": {
        "label": "Threat Intelligence",
        "fields": {
            "enabled": {"label": "Activer l'enrichissement", "default": "false", "is_secret": False},
            "api_key": {"label": "Clé API AbuseIPDB", "default": "", "is_secret": True},
        },
    },
}


def _init_defaults(db: Session, tenant_id: str = "default"):
    existing = db.query(SystemConfig.section).filter(SystemConfig.tenant_id == tenant_id).distinct().all()
    existing_sections = {row[0] for row in existing}

    for section, config in DEFAULT_CONFIGS.items():
        if section not in existing_sections:
            for key, field in config["fields"].items():
                db.add(SystemConfig(
                    section=section,
                    key=key,
                    value=field["default"],
                    is_secret=field["is_secret"],
                    label=field["label"],
                    tenant_id=tenant_id,
                ))
    db.commit()


def get_all_settings(db: Session, tenant_id: str = "default") -> dict:
    rows = db.query(SystemConfig).filter(SystemConfig.tenant_id == tenant_id).all()
    result = {}
    for row in rows:
        if row.section not in result:
            result[row.section] = {"label": DEFAULT_CONFIGS.get(row.section, {}).get("label", row.section), "fields": {}}
        field_def = DEFAULT_CONFIGS.get(row.section, {}).get("fields", {}).get(row.key, {})
        result[row.section]["fields"][row.key] = {
            "value": "" if row.is_secret and not row.value else row.value,
            "is_secret": row.is_secret,
            "label": row.label or field_def.get("label", row.key),
            "has_value": bool(row.value),
        }
    return result


def update_settings(db: Session, section: str, data: dict, tenant_id: str = "default") -> bool:
    updated = False
    for key, value in data.items():
        row = db.query(SystemConfig).filter_by(section=section, key=key, tenant_id=tenant_id).first()
        if row:
            if row.is_secret and not value:
                continue
            row.value = value
            updated = True
        else:
            field_def = DEFAULT_CONFIGS.get(section, {}).get("fields", {}).get(key, {})
            db.add(SystemConfig(
                section=section,
                key=key,
                value=value,
                is_secret=field_def.get("is_secret", False),
                label=field_def.get("label", key),
                tenant_id=tenant_id,
            ))
            updated = True
    if updated:
        db.commit()
    return updated


def get_config_value(db: Session, section: str, key: str, fallback: str = "", tenant_id: str = "default") -> str:
    row = db.query(SystemConfig).filter_by(section=section, key=key, tenant_id=tenant_id).first()
    if row and row.value:
        return row.value
    field_def = DEFAULT_CONFIGS.get(section, {}).get("fields", {}).get(key, {})
    return field_def.get("default", fallback)


def get_config_dict(db: Session, tenant_id: str = "default") -> dict:
    rows = db.query(SystemConfig).filter(SystemConfig.tenant_id == tenant_id).all()
    config = {}
    for row in rows:
        if row.section not in config:
            config[row.section] = {}
        config[row.section][row.key] = row.value
    return config
