import base64
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from .ssl_context import ssl_ctx

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    """Wazuh indexer (OpenSearch) read queries."""

    async def _get_indexer_auth(self) -> str | None:
        if self._indexer_auth_failure_count > 0 and self._last_auth_attempt:
            elapsed = (datetime.now(UTC) - self._last_auth_attempt).total_seconds()
            backoff = min(2 ** self._indexer_auth_failure_count, 300)
            if elapsed < backoff:
                return None

        auth_str = f"{self.indexer_user}:{self.indexer_pass}"
        return base64.b64encode(auth_str.encode()).decode()

    async def get_active_response_history(self) -> list[dict[str, Any]]:
        """Fetch history of automated defense actions (Active Responses) from the Indexer."""
        auth_b64 = await self._get_indexer_auth()
        if not auth_b64:
            return []

        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                # Query alerts where rule group is 'active_response' (try multiple possible group names)
                query = {
                    "size": 50,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"rule.groups": "active_response"}},
                                {"term": {"rule.groups": "active-response"}},
                                {"term": {"rule.groups": "wazuh_active_response"}},
                                {"term": {"rule.groups": "active_response_firewall"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                }
                response = await self._rate_limited_request(
                    client, "POST",
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/json"},
                    json=query,
                    timeout=5.0
                )

                if response.status_code == 200:
                    self._indexer_auth_failure_count = 0
                    hits = response.json().get('hits', {}).get('hits', [])
                    results = []
                    for hit in hits:
                        source = hit['_source']
                        results.append({
                            "timestamp": source.get('timestamp'),
                            "agent_name": source.get('agent', {}).get('name'),
                            "agent_id": source.get('agent', {}).get('id'),
                            "action": source.get('rule', {}).get('description') or "Active Response",
                            "full_log": source.get('full_log') or "",
                            "level": source.get('rule', {}).get('level')
                        })
                    return results
                elif response.status_code == 401:
                    self._indexer_auth_failure_count += 1
                    if self._indexer_auth_failure_count == 1:
                        logger.warning("Wazuh Indexer authentication failed for active responses")
                    self._indexer_available = False
                else:
                    logger.warning("Wazuh Indexer active response query error (HTTP %d)", response.status_code)
        except httpx.ConnectError:
            self._indexer_auth_failure_count += 1
            if self._indexer_auth_failure_count == 1:
                logger.warning("Cannot connect to Wazuh Indexer for active responses")
            self._indexer_available = False
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return []
            if self._indexer_auth_failure_count <= 2:
                logger.warning("Wazuh Active Response Query Error: %s", e)
        except Exception as e:
            if self._indexer_auth_failure_count <= 2:
                logger.warning("Wazuh Active Response Query Error: %s", e)
        return []

