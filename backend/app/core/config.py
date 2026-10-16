from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Pas de mot de passe committé dans le DSN par défaut : un secret dans le code
    # est un secret qui fuit (il reste dans l'historique git pour toujours). Passez
    # par la variable d'environnement DATABASE_URL, ou par POSTGRES_USER /
    # POSTGRES_PASSWORD que docker-compose injecte déjà.
    DATABASE_URL: str = "postgresql+pg8000://postgres@localhost:5432/postgres"
    SCAN_INTERVAL_SECONDS: int = 10

    # ── Honeypot ────────────────────────────────────────────────────────────
    # Opt-in : le honeypot ouvre des ports en écoute sur 0.0.0.0. C'est une
    # surface d'attaque assumée, elle ne doit pas être active par défaut.
    ENABLE_HONEYPOT: bool = False
    # Liste vide => les 4 ports historiques (2323, 3389, 8443, 5555).
    HONEYPOT_PORTS: list[int] = Field(default_factory=list)
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ENVIRONMENT: str = "development"
    # Derrière un reverse proxy, `request.client.host` vaut l'IP du proxy : tous les
    # utilisateurs partageraient un seul seau de rate-limit. Activer ceci fait lire
    # X-Forwarded-For — à ne mettre à true QUE si un proxy de confiance est devant,
    # sinon l'en-tête est forgeable et la limite saute.
    TRUST_PROXY_HEADERS: bool = False
    # true en dev (create_all() au démarrage), à passer à false en production où
    # le schéma doit venir de `alembic upgrade head`.
    AUTO_CREATE_SCHEMA: bool = True
    API_KEY: SecretStr

    WAZUH_API_URL: str = "https://127.0.0.1:45000"
    WAZUH_USER: str = "wazuh-wui"
    WAZUH_PASS: SecretStr

    WAZUH_INDEXER_URL: str = "https://127.0.0.1:9200"
    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASS: SecretStr

    SURICATA_HOST: str = "192.168.1.100"
    SURICATA_PORT: int = 22
    SURICATA_USER: str = "suricata"
    SURICATA_PASS: SecretStr

    WAZUH_DOCKER_CONTAINER: str = "single-node-wazuh.manager-1"
    WAZUH_SSH_PORT: int = 2222
    WAZUH_SSH_USER: str = "root"
    WAZUH_SSH_PASS: SecretStr

    REDIS_URL: str = "redis://localhost:6379/0"

    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:1.5b"

    ADMIN_API_KEY: SecretStr
    ADMIN_JWT_SECRET: SecretStr

    REDIS_PASSWORD: str = ""
    POSTGRES_PASSWORD: str = ""

    ALLOWED_ORIGINS: list[str] = Field(default_factory=lambda: [
        "http://localhost:5173",
        "http://localhost:4173",
        "http://localhost:3000",
    ])

    STRIPE_SECRET_KEY: SecretStr = SecretStr("")
    STRIPE_WEBHOOK_SECRET: SecretStr = SecretStr("")
    SUPER_ADMIN_API_KEY: SecretStr = SecretStr("")
    SUPER_ADMIN_PASSWORD: SecretStr = SecretStr("")

    # ── Source toggles (default: host-agent enabled, Wazuh/Suricata off) ──
    ENABLE_HOST_AGENT_SOURCE: bool = True
    ENABLE_WAZUH_SOURCE: bool = False
    ENABLE_SURICATA_SOURCE: bool = False

    THREAT_INTEL_ENABLED: bool = True
    THREAT_INTEL_PROVIDER: str = "abuseipdb"
    THREAT_INTEL_API_KEY: SecretStr = SecretStr("")
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 3600
    THREAT_INTEL_TIMEOUT_SECONDS: int = 10

    # Inscription : l'analyste attend l'approbation admin avant d'entrer.
    # False → register crée le compte immédiatement (ancien comportement).
    REGISTRATION_REQUIRES_APPROVAL: bool = True

    # Rate-limit login (/auth/token) : max tentatives par fenêtre, par IP.
    # Dev partage 127.0.0.1 entre tous les users → seuil plus permissif.
    AUTH_LOGIN_RATE_LIMIT_MAX: int = 10
    AUTH_LOGIN_RATE_LIMIT_WINDOW: int = 60

    # R3 — Notifications : clé Fernet pour chiffrer les configs de canaux.
    # Vide => fallback déterministe dérivé de JWT_SECRET_KEY (dev/tests).
    NOTIFICATION_ENCRYPTION_KEY: str = ""

    # ── HF Router LLM config ──
    HF_ROUTER_URL: str = "https://router.huggingface.co/v1"
    HF_MODEL: str = "meta-llama/Llama-3.1-70B-Instruct:featherless-ai"
    HF_TOKEN: str = ""

    # ── AI Auto-Analyse defaults (ai_auto section) ──
    AI_AUTO_DEFAULTS: dict = Field(default_factory=lambda: {
        "enabled": False,
        "threshold": 8,
        "send_count": 10,
        "severity_min": 8,
        "window_minutes": 60,
        "model": "meta-llama/Llama-3.1-70B-Instruct:featherless-ai",
        "url": "https://router.huggingface.co/v1",
    })

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
