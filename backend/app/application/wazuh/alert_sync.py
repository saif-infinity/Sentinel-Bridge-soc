import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from ...infrastructure.wazuh.ssl_context import ssl_ctx

logger = logging.getLogger(__name__)


class WazuhAlertSync:
    """Indexer alert ingestion → Alerts/Device/Asset tables (dedup + identity enrichment)."""

    async def sync_alerts(self, db_session_factory, tenant_id: str = "default"):
        auth_b64 = await self._get_indexer_auth()
        if not auth_b64:
            return
        
        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                query = {
                    "size": 15,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["timestamp", "rule", "agent", "full_log"]
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
                    if not self._indexer_available:
                        logger.info("Wazuh Indexer connection restored")
                        self._indexer_available = True
                    
                    hits = response.json().get('hits', {}).get('hits', [])
                    from ...models import Alert, Device, Asset
                    import dateutil.parser
                    
                    db = db_session_factory()
                    try:
                        for hit in hits:
                            source = hit['_source']
                            ts_str = source.get('timestamp')
                            ts = dateutil.parser.isoparse(ts_str) if ts_str else datetime.now(timezone.utc)
                            desc = source.get('rule', {}).get('description', 'Wazuh Security Event')
                            sev = source.get('rule', {}).get('level', 3)
                            
                            agent_data = source.get('agent', {})
                            agent_id = agent_data.get('id', '000')
                            agent_name = agent_data.get('name', 'Unknown')
                            
                            async with self._cache_lock:
                                if agent_id not in self._agent_ip_cache:
                                    identity = await self.get_agent_real_identity(agent_id, fallback_name=agent_name)
                                    self._agent_ip_cache[agent_id] = identity
                                else:
                                    identity = self._agent_ip_cache[agent_id]
                            real_ip = identity['ip']
                            real_mac = identity['mac']
                            os_user = identity['user']

                            # Make sure Asset and Device exist so employee mapping and inventory work
                            if real_ip != '0.0.0.0':
                                # Update Device
                                device = db.query(Device).filter(Device.ip == real_ip).first()
                                if not device:
                                    device = Device(ip=real_ip, mac=real_mac, is_online=True, is_wazuh_agent=True, tenant_id=tenant_id)
                                    db.add(device)
                                else:
                                    device.is_wazuh_agent = True
                                
                                # Update Asset
                                asset = db.query(Asset).filter(Asset.ip == real_ip).first()
                                if not asset:
                                    asset = Asset(ip=real_ip, employee_name=os_user, department="Auto-Detected", tenant_id=tenant_id)
                                    db.add(asset)
                                else:
                                    asset.employee_name = os_user
                                db.flush()

                            exists = db.query(Alert).filter(Alert.description == desc, Alert.timestamp == ts).first()
                            if not exists:
                                # Force src_ip to be the real_ip from PC, not the alert
                                new_alert = Alert(timestamp=ts, description=desc, severity=sev, src_ip=real_ip, agent_id=agent_id, tenant_id=tenant_id)
                                db.add(new_alert)
                        db.commit()
                    finally:
                        db.close()
                elif response.status_code == 401:
                    self._indexer_auth_failure_count += 1
                    if self._indexer_auth_failure_count == 1:
                        logger.warning("Wazuh Indexer authentication failed: Invalid credentials. Check WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS in .env")
                    self._indexer_available = False
                else:
                    logger.warning("Wazuh Indexer query error (HTTP %d)", response.status_code)
        except httpx.ConnectError:
            self._indexer_auth_failure_count += 1
            if self._indexer_auth_failure_count == 1:
                logger.warning("Cannot connect to Wazuh Indexer at %s. Is OpenSearch running?", self.indexer_url)
            self._indexer_available = False
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return
            if self._indexer_auth_failure_count <= 2:
                logger.warning("Wazuh Sync Error: %s", e)
        except Exception as e:
            if self._indexer_auth_failure_count <= 2:
                logger.warning("Wazuh Sync Error: %s", e)

