import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional

from ...core.config import settings
from ...db import SessionLocal

from ...infrastructure.wazuh.client import WazuhAPIClient
from ...infrastructure.wazuh.indexer_client import WazuhIndexerClient
from .ai_reporting import WazuhAIReporting
from .alert_sync import WazuhAlertSync
from .cache import WazuhCache
from .topology import WazuhTopology

logger = logging.getLogger(__name__)


def _env_or_db(db, section, key, env_val, is_secret=False):
    """Read a config value: DB first, then env var fallback."""
    # DEAD CODE — preserved verbatim for byte-fidelity; safe to delete in Lane 7.
    try:
        from ...services.system_config_service import get_config_value
        val = get_config_value(db, section, key, fallback="")
        if val:
            return val
    except Exception:
        pass
    if is_secret and hasattr(env_val, 'get_secret_value'):
        return env_val.get_secret_value()
    return env_val


class WazuhService(WazuhAPIClient, WazuhIndexerClient, WazuhCache, WazuhAlertSync, WazuhTopology, WazuhAIReporting):
    """Facade: owns lifecycle + ALL shared state. Mixins are concrete transport/domain modules."""

    def __init__(self):
        self._load_from_env()

    def _load_from_env(self):
        self.base_url = settings.WAZUH_API_URL
        self.user = settings.WAZUH_USER
        self.password = settings.WAZUH_PASS.get_secret_value() if hasattr(settings.WAZUH_PASS, 'get_secret_value') else settings.WAZUH_PASS
        self.indexer_url = settings.WAZUH_INDEXER_URL
        self.indexer_user = settings.WAZUH_INDEXER_USER
        self.indexer_pass = settings.WAZUH_INDEXER_PASS.get_secret_value() if hasattr(settings.WAZUH_INDEXER_PASS, 'get_secret_value') else settings.WAZUH_INDEXER_PASS
        self.ollama_url = settings.OLLAMA_URL
        self.ollama_model = settings.OLLAMA_MODEL

    def reload_config(self, db=None):
        """Reload config from DB. Falls back to env vars if DB unavailable."""
        if db is None:
            db = SessionLocal()
            close_db = True
        else:
            close_db = False
        try:
            from ...services.system_config_service import get_config_value
            self.base_url = get_config_value(db, "wazuh_api", "url", settings.WAZUH_API_URL)
            self.user = get_config_value(db, "wazuh_api", "user", settings.WAZUH_USER)
            pw = get_config_value(db, "wazuh_api", "password", "")
            if pw:
                self.password = pw
            self.indexer_url = get_config_value(db, "wazuh_indexer", "url", settings.WAZUH_INDEXER_URL)
            self.indexer_user = get_config_value(db, "wazuh_indexer", "user", settings.WAZUH_INDEXER_USER)
            ipw = get_config_value(db, "wazuh_indexer", "password", "")
            if ipw:
                self.indexer_pass = ipw
            self.ollama_url = get_config_value(db, "ollama", "url", settings.OLLAMA_URL)
            self.ollama_model = get_config_value(db, "ollama", "model", settings.OLLAMA_MODEL)
            self._auth_failure_count = 0
            self._indexer_auth_failure_count = 0
            self._wazuh_available = True
            self._indexer_available = True
            self.token = None
            self.token_expires_at = None
            logger.info("WazuhService config reloaded from DB")
        except Exception as e:
            logger.warning("Failed to reload config from DB: %s", e)
        finally:
            if close_db:
                db.close()
        self.token = None
        self.token_expires_at: Optional[datetime] = None
        self._agent_ip_cache = {}
        self._auth_failure_count = 0
        self._last_auth_attempt: Optional[datetime] = None
        self._indexer_auth_failure_count = 0
        self._wazuh_available = True
        self._indexer_available = True
        self._lock = asyncio.Lock()
        self._cache_lock = asyncio.Lock()
        self._auth_lock = asyncio.Lock()
        self._rate_limit_store: dict = {}
        self._rate_limit_lock = asyncio.Lock()
        self._last_request_time: Dict[str, float] = {}
        self._min_request_interval = 1.0
        self._consecutive_429_count = 0
        self._backoff_until: Optional[float] = None

wazuh_service = WazuhService()
