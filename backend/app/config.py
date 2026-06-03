from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+pg8000://postgres:saif@localhost:5432/postgres"
    SCAN_INTERVAL_SECONDS: int = 10
    API_KEY: str = "sDr6ANE9JVhPTBxjLJpKq5SHLXHNSt3_LAfz4c6yj3U"
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    WAZUH_API_URL: str = "https://127.0.0.1:45000"
    WAZUH_USER: str = "wazuh-wui"
    WAZUH_PASS: str = "MyS3cr37P450r.*-"

    WAZUH_INDEXER_URL: str = "https://127.0.0.1:9200"
    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASS: str = "SecretPassword"

    SURICATA_HOST: str = "192.168.133.136"
    SURICATA_PORT: int = 22
    SURICATA_USER: str = "suricata"
    SURICATA_PASS: str = "saif"

    WAZUH_DOCKER_CONTAINER: str = "single-node-wazuh.manager-1"
    WAZUH_SSH_PORT: int = 2222
    WAZUH_SSH_USER: str = "root"
    WAZUH_SSH_PASS: str = "wazuh"

    REDIS_URL: str = "redis://localhost:6379/0"

    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:1.5b"

settings = Settings()