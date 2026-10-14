import asyncio
import base64
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .ssl_context import ssl_ctx

logger = logging.getLogger(__name__)


class WazuhAPIClient:
    """Wazuh REST API transport + agent syscollector queries."""

    async def _rate_limited_request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
        """Make a rate-limited request with exponential backoff on 429."""
        async with self._rate_limit_lock:
            now = datetime.now(UTC).timestamp()

            if self._backoff_until and now < self._backoff_until:
                wait_time = self._backoff_until - now
                logger.debug("Rate limit backoff: waiting %.1fs", wait_time)
                await asyncio.sleep(wait_time)
                now = datetime.now(UTC).timestamp()

            last_time = self._last_request_time.get(url, 0)
            elapsed = now - last_time
            if elapsed < self._min_request_interval:
                wait_time = self._min_request_interval - elapsed
                logger.debug("Rate limiting: waiting %.1fs", wait_time)
                await asyncio.sleep(wait_time)

            self._last_request_time[url] = datetime.now(UTC).timestamp()

        response = await client.request(method, url, **kwargs)

        if response.status_code == 429:
            self._consecutive_429_count += 1
            backoff = min(2 ** self._consecutive_429_count, 60)
            self._backoff_until = datetime.now(UTC).timestamp() + backoff
            self._min_request_interval = min(self._min_request_interval * 1.5, 10.0)
            logger.warning("Wazuh API rate limited (429). Backing off for %ds, interval=%.1fs", backoff, self._min_request_interval)
            raise httpx.HTTPStatusError("Rate limited", request=response.request, response=response)
        else:
            self._consecutive_429_count = max(0, self._consecutive_429_count - 1)
            self._min_request_interval = max(self._min_request_interval * 0.9, 1.0)
            self._backoff_until = None

        return response

    async def _get_token(self) -> str | None:
        async with self._auth_lock:
            now = datetime.now(UTC)

            if self.token and self.token_expires_at and now < self.token_expires_at:
                return self.token

            if self._last_auth_attempt:
                elapsed = (now - self._last_auth_attempt).total_seconds()
                backoff = min(2 ** self._auth_failure_count, 300)
                if elapsed < backoff:
                    return None

            self._last_auth_attempt = now
            auth_str = f"{self.user}:{self.password}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()

            try:
                async with httpx.AsyncClient(verify=ssl_ctx) as client:
                    response = await client.get(
                        f"{self.base_url}/security/user/authenticate",
                        headers={"Authorization": f"Basic {auth_b64}"},
                        timeout=5.0
                    )
                    response.raise_for_status()
                    data = response.json()
                    self.token = data['data']['token']
                    self.token_expires_at = now + timedelta(minutes=15)
                    self._auth_failure_count = 0
                    if not self._wazuh_available:
                        logger.info("Wazuh connection restored")
                        self._wazuh_available = True
                    return self.token
            except httpx.HTTPStatusError as e:
                self._auth_failure_count += 1
                if e.response.status_code == 401:
                    if self._auth_failure_count == 1:
                        logger.warning("Wazuh authentication failed: Invalid credentials. Check WAZUH_USER and WAZUH_PASS in .env")
                    self._wazuh_available = False
                else:
                    logger.warning("Wazuh auth error (HTTP %d): %s", e.response.status_code, e)
                return None
            except httpx.ConnectError:
                self._auth_failure_count += 1
                if self._auth_failure_count == 1:
                    logger.warning("Cannot connect to Wazuh API at %s. Is Wazuh running?", self.base_url)
                self._wazuh_available = False
                return None
            except Exception as e:
                self._auth_failure_count += 1
                if self._auth_failure_count <= 2:
                    logger.warning("Wazuh auth error: %s", e)
                return None

    async def get_agents(self) -> list[dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                response = await self._rate_limited_request(
                    client, "GET",
                    f"{self.base_url}/agents",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 401:
                    self._auth_failure_count += 1
                    self._wazuh_available = False
                    return []
                response.raise_for_status()
                return response.json()['data']['affected_items']
        except httpx.ConnectError:
            self._wazuh_available = False
            return []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return []
            logger.warning("Error fetching agents: %s", e)
            return []
        except Exception as e:
            logger.warning("Error fetching agents: %s", e)
            return []

    async def get_agent_netinfo(self, agent_id: str) -> dict[str, Any]:
        token = await self._get_token()
        if not token:
            return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}

        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                response = await self._rate_limited_request(
                    client, "GET",
                    f"{self.base_url}/syscollector/{agent_id}/netaddr",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 401:
                    self._auth_failure_count += 1
                    self._wazuh_available = False
                    return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}
                if response.status_code == 200:
                    # Get MAC addresses to match with IPs
                    response_mac = await self._rate_limited_request(
                        client, "GET",
                        f"{self.base_url}/syscollector/{agent_id}/netiface",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5.0
                    )
                    mac_map = {}
                    if response_mac.status_code == 200:
                        mac_items = response_mac.json().get('data', {}).get('affected_items', [])
                        for m in mac_items:
                            if m.get('name') and m.get('mac'):
                                mac_map[m['name'].lower()] = m['mac']

                    items = response.json().get('data', {}).get('affected_items', [])
                    if items:
                        possible_ips = []
                        for item in items:
                            ip = item.get('address') or item.get('ipv4', {}).get('address')
                            iface_orig = item.get('iface', '')
                            iface = iface_orig.lower()
                            proto = item.get('proto', '').lower()

                            if not ip or ":" in ip or proto == 'ipv6' or ip == "127.0.0.1" or ip.startswith("169.254."):
                                continue

                            is_virtual = any(x in iface for x in ['wsl', 'vethernet', 'docker', 'virtual', 'vmware', 'pseudo', 'loopback', 'tunnel'])
                            priority = 10
                            if any(hw in iface for hw in ['eth', 'en', 'wi-fi', 'wlan', 'wl']):
                                priority = 100
                            if is_virtual or ip.startswith("172."):
                                priority = 1

                            mac = mac_map.get(iface, "00:00:00:00:00:00")
                            possible_ips.append((ip, priority, iface, mac))

                        if possible_ips:
                            possible_ips.sort(key=lambda x: x[1], reverse=True)
                            best = possible_ips[0]
                            return {"ip": best[0], "mac": best[3], "iface": best[2]}
                return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}
        except httpx.ConnectError:
            self._wazuh_available = False
            return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}
            logger.warning("Error fetching agent netinfo: %s", e)
            return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}
        except Exception as e:
            logger.warning("Error fetching agent netinfo: %s", e)
            return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}

    async def get_agent_users(self, agent_id: str) -> str:
        """Fetch the primary logged-in user from the agent OS."""
        token = await self._get_token()
        if not token:
            return "Unknown"
        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                response = await self._rate_limited_request(
                    client, "GET",
                    f"{self.base_url}/syscollector/{agent_id}/users?limit=10",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 401:
                    self._auth_failure_count += 1
                    self._wazuh_available = False
                    return "Unknown"
                if response.status_code == 200:
                    users = response.json().get('data', {}).get('affected_items', [])
                    # Filter out system users to find the real person
                    for u in users:
                        name = u.get('name', '').lower()
                        if name and name not in ['system', 'local service', 'network service', 'root', 'nobody', 'daemon']:
                            return u.get('name', 'Unknown')
                    if users:
                        return users[0].get('name', 'Unknown')
        except httpx.ConnectError:
            self._wazuh_available = False
            return "Unknown"
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return "Unknown"
            logger.warning("Error fetching agent users: %s", e)
        except Exception as e:
            logger.warning("Error fetching agent users: %s", e)
        return "Unknown"

    async def get_agent_real_identity(self, agent_id: str, fallback_name: str = "Unknown") -> dict[str, str]:
        """Fetch the true physical IP, MAC, and OS User from Syscollector directly."""
        if agent_id == "000":
            return {"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "user": "System (Manager)"}

        net_info = await self.get_agent_netinfo(agent_id)
        os_user = await self.get_agent_users(agent_id)

        # Smart Fallback: If Syscollector hasn't scanned users yet, use the PC Name (Agent Name)
        if os_user == "Unknown" and fallback_name != "Unknown":
            os_user = fallback_name

        real_ip = net_info.get('ip', '0.0.0.0')
        real_mac = net_info.get('mac', '00:00:00:00:00:00')

        return {"ip": real_ip, "mac": real_mac, "user": os_user}

    async def get_agent_hardware(self, agent_id: str) -> dict[str, Any]:
        token = await self._get_token()
        if not token:
            return {"cpu_name": "Intel Core i7-10700K (Mock)", "ram_total": 16777216, "ram_free": 8388608, "os_name": "Ubuntu Linux", "os_version": "22.04 LTS", "board_serial": "MB-X99-PRO"}

        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                response = await self._rate_limited_request(
                    client, "GET",
                    f"{self.base_url}/syscollector/{agent_id}/hardware",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 401:
                    self._auth_failure_count += 1
                    self._wazuh_available = False
                    return {"cpu_name": "Unknown Processor (Data Unavailable)", "ram_total": 0, "ram_free": 0, "os_name": "Unknown", "board_serial": "N/A"}
                if response.status_code == 200:
                    items = response.json().get('data', {}).get('affected_items', [])
                    if items: return items[0]
        except httpx.ConnectError:
            self._wazuh_available = False
            return {"cpu_name": "Unknown Processor (Data Unavailable)", "ram_total": 0, "ram_free": 0, "os_name": "Unknown", "board_serial": "N/A"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"cpu_name": "Unknown Processor (Data Unavailable)", "ram_total": 0, "ram_free": 0, "os_name": "Unknown", "board_serial": "N/A"}
            logger.warning("Error getting agent hardware: %s", e)
        except Exception as e:
            logger.warning("Error getting agent hardware: %s", e)
        return {"cpu_name": "Unknown Processor (Data Unavailable)", "ram_total": 0, "ram_free": 0, "os_name": "Unknown", "board_serial": "N/A"}

    async def get_agent_packages(self, agent_id: str, limit: int = 5) -> list[dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

        try:
            async with httpx.AsyncClient(verify=ssl_ctx) as client:
                response = await self._rate_limited_request(
                    client, "GET",
                    f"{self.base_url}/syscollector/{agent_id}/packages?limit={limit}&sort=-install_time",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 401:
                    self._auth_failure_count += 1
                    self._wazuh_available = False
                    return []
                if response.status_code == 200:
                    return response.json().get('data', {}).get('affected_items', [])
        except httpx.ConnectError:
            self._wazuh_available = False
            return []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return []
            logger.error(f"Error getting agent packages: {e}")
        except Exception as e:
            logger.error(f"Error getting agent packages: {e}")
        return []

