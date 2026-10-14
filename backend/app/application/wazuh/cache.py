import logging

from ...db import SessionLocal

logger = logging.getLogger(__name__)


class WazuhCache:
    """Agent identity cache (real IP/MAC/user) + Device/Asset enrichment sync."""

    async def refresh_agent_cache(self, tenant_id: str = "default"):
        """
        Pre-fetch real network IPs and primary users for all agents.
        """
        agents = await self.get_agents()

        if not agents:
            if not self._wazuh_available and not self._agent_ip_cache:
                logger.info("Wazuh unavailable, using cached/mock data for topology")
            return

        logger.info("Refreshing agent real identity cache...")
        new_cache = {}

        for agent in agents:
            agent_id = agent['id']
            agent_name = agent.get('name', 'Unknown')
            identity = await self.get_agent_real_identity(agent_id, fallback_name=agent_name)

            if identity['ip'] in ['0.0.0.0', 'any', None]:
                api_ip = agent.get('ip', '')
                is_real_ip = (
                    api_ip and
                    api_ip not in ['any', '0.0.0.0', '127.0.0.1'] and
                    not api_ip.startswith('172.') and
                    not api_ip.startswith('169.254.')
                )
                if is_real_ip:
                    identity['ip'] = api_ip

            new_cache[agent_id] = identity

        async with self._cache_lock:
            self._agent_ip_cache = new_cache
        logger.info("Cache updated: %d agents mapped.", len(self._agent_ip_cache))

        # Sync to Devices and Assets table
        db = SessionLocal()
        try:
            from ...models import Asset, Device
            for agent_id, data in self._agent_ip_cache.items():
                ip = data['ip']
                mac = data['mac']
                user = data['user']
                if ip != '0.0.0.0' and mac != '00:00:00:00:00:00':
                    # Check for existing device by IP OR MAC (MAC has unique constraint)
                    dev = db.query(Device).filter(
                        (Device.ip == ip) | (Device.mac == mac)
                    ).first()
                    if not dev:
                        dev = Device(ip=ip, mac=mac, is_online=True, is_wazuh_agent=True, tenant_id=tenant_id)
                        db.add(dev)
                    else:
                        # Update both IP and MAC in case either changed
                        dev.ip, dev.mac, dev.is_wazuh_agent = ip, mac, True

                    # Update Asset (Employee Mapping)
                    asset = db.query(Asset).filter(Asset.ip == ip).first()
                    if not asset:
                        asset = Asset(ip=ip, employee_name=user, department="Auto-Detected", tenant_id=tenant_id)
                        db.add(asset)
                    else:
                        # Always update user to keep it fresh
                        asset.employee_name = user
            db.commit()
        except Exception as e:
            logger.error("Enrichment sync error: %s", e)
            db.rollback()
        finally:
            db.close()

