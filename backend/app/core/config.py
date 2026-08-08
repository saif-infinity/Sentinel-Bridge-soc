from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+pg8000://postgres:saif@localhost:5432/postgres"
    SCAN_INTERVAL_SECONDS: int = 10
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ENVIRONMENT: str = "development"
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

    THREAT_INTEL_ENABLED: bool = False
    THREAT_INTEL_PROVIDER: str = "abuseipdb"
    THREAT_INTEL_API_KEY: SecretStr = SecretStr("")
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 3600
    THREAT_INTEL_TIMEOUT_SECONDS: int = 10

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
