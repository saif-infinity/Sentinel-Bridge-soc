from sqlalchemy.orm import Session

from ..config import settings
from ..models import SystemConfig

DEFAULT_CONFIGS = {
    "sources": {
        "label": "Source Toggles",
        "fields": {
            "host_agent": {"label": "Activer la source host-agent", "default": str(settings.ENABLE_HOST_AGENT_SOURCE), "is_secret": False},
            "wazuh": {"label": "Activer la source Wazuh", "default": str(settings.ENABLE_WAZUH_SOURCE), "is_secret": False},
            "suricata": {"label": "Activer la source Suricata", "default": str(settings.ENABLE_SURICATA_SOURCE), "is_secret": False},
            "wazuh_method": {"label": "Méthode de connexion Wazuh (webhook/api_indexer)", "default": "", "is_secret": False},
            "suricata_method": {"label": "Méthode de connexion Suricata (webhook/ssh)", "default": "", "is_secret": False},
        },
    },
    "wazuh_webhook": {
        "label": "Token+Suffix webhook Wazuh",
        "fields": {
            "token": {"label": "Token webhook Wazuh", "default": "", "is_secret": True},
            "slug": {"label": "Suffix secret de l'URL webhook (généré)", "default": "", "is_secret": False},
        },
    },
    "suricata_webhook": {
        "label": "Token+Suffix webhook Suricata",
        "fields": {
            "token": {"label": "Token webhook Suricata", "default": "", "is_secret": True},
            "slug": {"label": "Suffix secret de l'URL webhook (généré)", "default": "", "is_secret": False},
        },
    },
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
    "investigation": {
        "label": "Automated Investigation",
        "fields": {
            "enabled": {"label": "Activer l'investigation automatique", "default": "true", "is_secret": False},
            "min_severity": {"label": "Sévérité minimale pour investigation", "default": "8", "is_secret": False},
            "dedup_window_hours": {"label": "Fenêtre de déduplication (heures)", "default": "24", "is_secret": False},
            "max_per_day": {"label": "Investigations max par jour et par tenant", "default": "20", "is_secret": False},
            "max_concurrent": {"label": "Investigations concurrentes max par tenant", "default": "3", "is_secret": False},
            "related_window_minutes": {"label": "Fenêtre d'alertes corrélées (minutes)", "default": "60", "is_secret": False},
            "llm_enabled": {"label": "Activer le résumé LLM", "default": "true", "is_secret": False},
            "llm_timeout_seconds": {"label": "Timeout LLM (secondes)", "default": "120", "is_secret": False},
            "critical_departments": {"label": "Départements critiques", "default": "it,admin,finance,management", "is_secret": False},
            "weights": {"label": "Poids personnalisés (JSON)", "default": "{}", "is_secret": False},
        },
    },
    "response": {
        "label": "Automated Response Agent",
        "fields": {
            "enabled": {"label": "Activer la réponse automatique", "default": "true", "is_secret": False},
            "auto_approve_actions": {"label": "Actions auto-approuvées", "default": "notify,monitor,escalate,run_playbook", "is_secret": False},
            "approval_timeout_hours": {"label": "Timeout approbation (heures)", "default": "24", "is_secret": False},
            "quarantine_dir": {"label": "Répertoire quarantine", "default": "/var/quarantine", "is_secret": False},
            "max_concurrent": {"label": "Réponses concurrentes max", "default": "3", "is_secret": False},
        },
    },
    "reporting": {
        "label": "Reporting",
        "fields": {
            "enabled": {"label": "Activer les rapports automatiques", "default": "true", "is_secret": False},
            "default_channel": {"label": "Canal de livraison par défaut", "default": "email", "is_secret": False},
            "default_recipient": {"label": "Destinataire par défaut", "default": "", "is_secret": False},
            "max_daily_reports": {"label": "Rapports quotidiens max", "default": "10", "is_secret": False},
            "retention_days": {"label": "Jours de rétention des rapports", "default": "90", "is_secret": False},
        },
    },
    "host_agent": {
        "label": "Agent hôte (Rust)",
        "fields": {
            "api_url": {"label": "URL du backend SOC", "default": "http://127.0.0.1:8001", "is_secret": False},
            "api_key": {"label": "Clé API", "default": "", "is_secret": True},
            "tenant_id": {"label": "Tenant ID", "default": "default", "is_secret": False},
            "agent_id": {"label": "ID de l'agent", "default": "host-01", "is_secret": False},
            "telemetry_interval_secs": {"label": "Intervalle télémétrie (s)", "default": "30", "is_secret": False},
            "orders_interval_secs": {"label": "Intervalle ordres (s)", "default": "10", "is_secret": False},
            "register_retry_backoff_secs": {"label": "Backoff ré-enregistrement (s)", "default": "5", "is_secret": False},
            "quarantine_dir": {"label": "Répertoire de quarantaine", "default": "/var/quarantine", "is_secret": False},
            "max_processes": {"label": "Processus max surveillés", "default": "500", "is_secret": False},
            "http_timeout_secs": {"label": "Timeout HTTP (s)", "default": "15", "is_secret": False},
        },
    },
    "ai_auto": {
        "label": "Auto-analyse IA (agent)",
        "fields": {
            "enabled": {"label": "Activer l'auto-analyse IA", "default": str(settings.AI_AUTO_DEFAULTS["enabled"]).lower(), "is_secret": False},
            "threshold": {"label": "Alertes déclenchant l'analyse (seuil)", "default": str(settings.AI_AUTO_DEFAULTS["threshold"]), "is_secret": False},
            "send_count": {"label": "Alertes max envoyées au LLM", "default": str(settings.AI_AUTO_DEFAULTS["send_count"]), "is_secret": False},
            "severity_min": {"label": "Sévérité minimale prise en compte", "default": str(settings.AI_AUTO_DEFAULTS["severity_min"]), "is_secret": False},
            "window_minutes": {"label": "Fenêtre de burst (minutes)", "default": str(settings.AI_AUTO_DEFAULTS["window_minutes"]), "is_secret": False},
            "model": {"label": "Modèle HF", "default": settings.AI_AUTO_DEFAULTS["model"], "is_secret": False},
            "url": {"label": "URL routeur HF", "default": settings.AI_AUTO_DEFAULTS["url"], "is_secret": False},
            "token": {"label": "Token HF (secret)", "default": "", "is_secret": True},
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
            "value": "" if row.is_secret else row.value,
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
