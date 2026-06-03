import httpx
import base64
import urllib3
import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict, Any
from ..config import settings
from ..db import SessionLocal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WazuhService:
    def __init__(self):
        self.base_url = settings.WAZUH_API_URL
        self.user = settings.WAZUH_USER
        self.password = settings.WAZUH_PASS
        self.indexer_url = settings.WAZUH_INDEXER_URL
        self.indexer_user = settings.WAZUH_INDEXER_USER
        self.indexer_pass = settings.WAZUH_INDEXER_PASS
        self.ollama_url = settings.OLLAMA_URL
        self.ollama_model = settings.OLLAMA_MODEL
        self.token = None
        self._agent_ip_cache = {}

    async def _get_token(self):
        auth_str = f"{self.user}:{self.password}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/security/user/authenticate",
                    headers={"Authorization": f"Basic {auth_b64}"},
                    timeout=5.0
                )
                response.raise_for_status()
                self.token = response.json()['data']['token']
                return self.token
        except Exception as e:
            logger.error("Wazuh Auth Error: %s", e)
            return None

    async def get_agents(self) -> List[Dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{self.base_url}/agents",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            response.raise_for_status()
            return response.json()['data']['affected_items']

    async def get_agent_netinfo(self, agent_id: str) -> Dict[str, Any]:
        token = await self._get_token()
        if not token:
            return {"ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "iface": "unknown"}

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{self.base_url}/syscollector/{agent_id}/netaddr",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            if response.status_code == 200:
                # Get MAC addresses to match with IPs
                response_mac = await client.get(
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

    async def get_agent_users(self, agent_id: str) -> str:
        """Fetch the primary logged-in user from the agent OS."""
        token = await self._get_token()
        if not token: return "Unknown"
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/syscollector/{agent_id}/users?limit=10",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                if response.status_code == 200:
                    users = response.json().get('data', {}).get('affected_items', [])
                    # Filter out system users to find the real person
                    for u in users:
                        name = u.get('name', '').lower()
                        if name and name not in ['system', 'local service', 'network service', 'root', 'nobody', 'daemon']:
                            return u.get('name', 'Unknown')
                    if users: return users[0].get('name', 'Unknown')
         except Exception as e:
             logger.error(f"Error fetching agent users: {e}")
        return "Unknown"

    async def get_agent_real_identity(self, agent_id: str, fallback_name: str = "Unknown") -> Dict[str, str]:
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

    async def refresh_agent_cache(self):
        """
        Pre-fetch real network IPs and primary users for all agents.
        """
        logger.info("Refreshing agent real identity cache...")
        agents = await self.get_agents()
        new_cache = {}
        
        for agent in agents:
            agent_id = agent['id']
            agent_name = agent.get('name', 'Unknown')
            identity = await self.get_agent_real_identity(agent_id, fallback_name=agent_name)
            
            # Fallback to agent.ip only if Syscollector completely fails
            # But NEVER use WSL/Docker/virtual IPs (172.x.x.x, 169.254.x.x)
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

        self._agent_ip_cache = new_cache
        logger.info("Cache updated: %d agents mapped.", len(self._agent_ip_cache))

        # Sync to Devices and Assets table
        db = SessionLocal()
        try:
            from ..models import Device, Asset
            for agent_id, data in self._agent_ip_cache.items():
                ip = data['ip']
                mac = data['mac']
                user = data['user']
                if ip != '0.0.0.0':
                    # Update Device
                    dev = db.query(Device).filter(Device.ip == ip).first()
                    if not dev:
                        dev = Device(ip=ip, mac=mac, is_online=True, is_wazuh_agent=True)
                        db.add(dev)
                    else:
                        dev.mac, dev.is_wazuh_agent = mac, True
                    
                    # Update Asset (Employee Mapping)
                    asset = db.query(Asset).filter(Asset.ip == ip).first()
                    if not asset:
                        asset = Asset(ip=ip, employee_name=user, department="Auto-Detected")
                        db.add(asset)
                    else:
                        # Always update user to keep it fresh
                        asset.employee_name = user
            db.commit()
        except Exception as e:
            logger.error("Enrichment sync error: %s", e)
        finally:
            db.close()

    async def get_agent_hardware(self, agent_id: str) -> Dict[str, Any]:
        token = await self._get_token()
        if not token:
            return {"cpu_name": "Intel Core i7-10700K (Mock)", "ram_total": 16777216, "ram_free": 8388608, "os_name": "Ubuntu Linux", "os_version": "22.04 LTS", "board_serial": "MB-X99-PRO"}

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/syscollector/{agent_id}/hardware",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5.0
                )
                 if response.status_code == 200:
                     items = response.json().get('data', {}).get('affected_items', [])
                     if items: return items[0]
         except Exception as e:
             logger.error(f"Error getting agent hardware: {e}")
        return {"cpu_name": "Unknown Processor (Data Unavailable)", "ram_total": 0, "ram_free": 0, "os_name": "Unknown", "board_serial": "N/A"}

    async def get_agent_packages(self, agent_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

         try:
             async with httpx.AsyncClient(verify=False) as client:
                 response = await client.get(
                     f"{self.base_url}/syscollector/{agent_id}/packages?limit={limit}&sort=-install_time",
                     headers={"Authorization": f"Bearer {token}"},
                     timeout=5.0
                 )
                 if response.status_code == 200:
                     return response.json().get('data', {}).get('affected_items', [])
         except Exception as e:
             logger.error(f"Error getting agent packages: {e}")
         return []

    async def sync_alerts(self, db_session_factory):
        auth_str = f"{self.indexer_user}:{self.indexer_pass}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                query = {
                    "size": 15,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["timestamp", "rule", "agent", "full_log"]
                }
                response = await client.post(
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/json"},
                    json=query,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    hits = response.json().get('hits', {}).get('hits', [])
                    from ..models import Alert, Device, Asset
                    import dateutil.parser
                    
                    db = db_session_factory()
                    try:
                        for hit in hits:
                            source = hit['_source']
                            ts_str = source.get('timestamp')
                            ts = dateutil.parser.isoparse(ts_str) if ts_str else datetime.utcnow()
                            desc = source.get('rule', {}).get('description', 'Wazuh Security Event')
                            sev = source.get('rule', {}).get('level', 3)
                            
                            agent_data = source.get('agent', {})
                            agent_id = agent_data.get('id', '000')
                            agent_name = agent_data.get('name', 'Unknown')
                            
                            # CRITICAL FIX: Ignore alert's agent_data['ip']. Use Syscollector cache!
                            if agent_id not in self._agent_ip_cache:
                                # On-the-fly fetch if cache missed
                                identity = await self.get_agent_real_identity(agent_id, fallback_name=agent_name)
                                self._agent_ip_cache[agent_id] = identity
                            
                            identity = self._agent_ip_cache[agent_id]
                            real_ip = identity['ip']
                            real_mac = identity['mac']
                            os_user = identity['user']

                            # Make sure Asset and Device exist so employee mapping and inventory work
                            if real_ip != '0.0.0.0':
                                # Update Device
                                device = db.query(Device).filter(Device.ip == real_ip).first()
                                if not device:
                                    device = Device(ip=real_ip, mac=real_mac, is_online=True, is_wazuh_agent=True)
                                    db.add(device)
                                else:
                                    device.is_wazuh_agent = True
                                
                                # Update Asset
                                asset = db.query(Asset).filter(Asset.ip == real_ip).first()
                                if not asset:
                                    asset = Asset(ip=real_ip, employee_name=os_user, department="Auto-Detected")
                                    db.add(asset)
                                else:
                                    asset.employee_name = os_user
                                db.flush()

                            exists = db.query(Alert).filter(Alert.description == desc, Alert.timestamp == ts).first()
                            if not exists:
                                # Force src_ip to be the real_ip from PC, not the alert
                                new_alert = Alert(timestamp=ts, description=desc, severity=sev, src_ip=real_ip, agent_id=agent_id)
                                db.add(new_alert)
                        db.commit()
                    finally:
                        db.close()
        except Exception as e:
            logger.error("Wazuh Sync Error: %s", e)

    async def get_active_response_history(self) -> List[Dict[str, Any]]:
        """Fetch history of automated defense actions (Active Responses) from the Indexer."""
        auth_str = f"{self.indexer_user}:{self.indexer_pass}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                # Query alerts where rule group is 'active_response'
                query = {
                    "size": 50,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"rule.groups": "active_response"}}
                            ]
                        }
                    }
                }
                response = await client.post(
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/json"},
                    json=query,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    hits = response.json().get('hits', {}).get('hits', [])
                    results = []
                    for hit in hits:
                        source = hit['_source']
                        results.append({
                            "timestamp": source.get('timestamp'),
                            "agent_name": source.get('agent', {}).get('name'),
                            "agent_id": source.get('agent', {}).get('id'),
                            "action": source.get('rule', {}).get('description'),
                            "full_log": source.get('full_log'),
                            "level": source.get('rule', {}).get('level')
                        })
                    return results
        except Exception as e:
            logger.error("Wazuh Active Response Query Error: %s", e)
        return []

    async def get_active_alerts(self) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            from ..models import Alert
            alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
            return [
                {
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat(),
                    "description": a.description,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "agent_id": a.agent_id,
                }
                for a in alerts
            ]
        except Exception as e:
            logger.error("Failed to fetch active alerts: %s", e)
            return []
        finally:
            db.close()

    async def get_topology(self) -> Dict[str, Any]:
        agents = await self.get_agents()
        nodes = []
        edges = []
        subnets = {}

        # Add Wazuh Manager node
        nodes.append({
            "id": "manager",
            "type": "custom",
            "data": {"label": "Wazuh Manager", "status": "normal", "ip": "127.0.0.1", "type": "manager", "os": "Linux"},
            "position": {"x": 0, "y": 0}
        })

        for agent in agents:
            agent_id = agent['id']
            agent_name = agent.get('name', f'Agent-{agent_id}')
            agent_status = agent.get('status', 'disconnected')
            if agent_id == "000":
                continue

            # ── Step 1: Try the real IP from Syscollector cache (most accurate) ──
            real_ip = None
            if agent_id in self._agent_ip_cache:
                cached_ip = self._agent_ip_cache[agent_id].get('ip', '0.0.0.0')
                if cached_ip not in ['0.0.0.0', '127.0.0.1', 'any', None]:
                    real_ip = cached_ip

            # ── Step 2: Fallback - live Syscollector query ──
            if not real_ip:
                net_info = await self.get_agent_netinfo(agent_id)
                candidate = net_info.get('ip', '0.0.0.0')
                if candidate not in ['0.0.0.0', '127.0.0.1', 'any', None]:
                    real_ip = candidate

            # ── Step 3: Last resort - Wazuh API registered IP (may be 'any') ──
            if not real_ip:
                api_ip = agent.get('ip', '0.0.0.0')
                if api_ip not in ['any', '0.0.0.0', '127.0.0.1', None]:
                    real_ip = api_ip

            # ── Step 4: If still no IP or it's a virtual/WSL IP, mark as unavailable ──
            if not real_ip:
                real_ip = "0.0.0.0"

            # Filter out WSL/Docker/virtual adapters (172.x.x.x ranges)
            is_virtual = (
                real_ip.startswith("172.") or
                real_ip.startswith("169.254.") or
                real_ip == "0.0.0.0"
            )

            # Compute subnet for grouping (use /24 for real IPs, Unknown for virtual)
            if not is_virtual:
                try:
                    parts = real_ip.split(".")
                    subnet_id = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                except Exception:
                    subnet_id = "Unknown"
            else:
                subnet_id = "Virtual / Unknown"

            if subnet_id not in subnets:
                subnets[subnet_id] = []

            # Attach real_ip to the agent dict for node creation
            agent["_real_ip"] = real_ip
            agent["_is_virtual"] = is_virtual
            subnets[subnet_id].append(agent)

        # ── Build node/edge layout ──
        y_offset = 100
        x_offset = -400

        for subnet_id, subnet_agents in subnets.items():
            group_id = f"group-{subnet_id}"
            group_height = max(220, len(subnet_agents) * 110 + 60)
            nodes.append({
                "id": group_id,
                "type": "group",
                "data": {"label": f"Subnet: {subnet_id}"},
                "position": {"x": x_offset, "y": y_offset},
                "style": {"width": 340, "height": group_height}
            })

            inner_y = 50
            for agent in subnet_agents:
                agent_node_id = f"agent-{agent['id']}"
                real_ip = agent.get("_real_ip", "0.0.0.0")
                is_virtual = agent.get("_is_virtual", False)
                os_info = agent.get('os', {})
                os_name = os_info.get('name', '') if isinstance(os_info, dict) else str(os_info)

                nodes.append({
                    "id": agent_node_id,
                    "parentNode": group_id,
                    "extent": "parent",
                    "type": "custom",
                    "data": {
                        "label": agent['name'],
                        "status": "active" if agent.get('status') == 'active' else "disconnected",
                        "ip": real_ip,
                        "is_virtual": is_virtual,
                        "type": "agent",
                        "os": os_name,
                        "agent_id": agent['id']
                    },
                    "position": {"x": 30, "y": inner_y}
                })
                edges.append({
                    "id": f"edge-{agent_node_id}-manager",
                    "source": agent_node_id,
                    "target": "manager",
                    "animated": agent.get('status') == 'active',
                    "style": {"stroke": "#3b82f6" if agent.get('status') == 'active' else "#374151"}
                })
                inner_y += 110

            x_offset += 400
            if x_offset > 800:
                x_offset = -400
                y_offset += group_height + 80

        return {"nodes": nodes, "edges": edges}


    async def get_agent_logs(self, agent_id: str, limit: int = 40) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            from ..models import Alert
            alerts = db.query(Alert).filter(Alert.agent_id == agent_id).order_by(Alert.timestamp.desc()).limit(limit).all()
            return [
                {
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat(),
                    "description": a.description,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                }
                for a in alerts
            ]
        except Exception as e:
            logger.error("Failed to fetch agent logs: %s", e)
            return []
        finally:
            db.close()

    async def _save_report(self, report_type: str, content: str, agent_id: str | None = None):
        db = SessionLocal()
        try:
            from ..models import IaReport
            report = IaReport(report_type=report_type, content=content, agent_id=agent_id)
            db.add(report)
            db.commit()
            logger.info("AI report saved: type=%s agent=%s", report_type, agent_id or "global")
        except Exception as e:
            logger.error("Failed to save AI report: %s", e)
        finally:
            db.close()

    async def _wrap_stream(self, report_type: str, agent_id: str | None, inner):
        tokens = []
        async for token in inner:
            tokens.append(token)
            yield token
        if tokens:
            full = "".join(tokens)
            asyncio.create_task(self._save_report(report_type, full, agent_id))

    async def stream_ai_report(self, agent_id: str):
        import httpx as _httpx
        db = SessionLocal()
        try:
            from ..models import Alert
            alerts = db.query(Alert).filter(Alert.agent_id == agent_id).order_by(Alert.timestamp.desc()).limit(20).all()
            if not alerts:
                timeline = "No recent security events recorded for this agent."
            else:
                lines = [f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Level {a.severity}: {a.description} (src: {a.src_ip})" for a in alerts]
                timeline = "\n".join(lines)
        except Exception as e:
            timeline = f"Could not retrieve alerts: {e}"
        finally:
            db.close()

        prompt = f"""You are a Senior SOC Analyst. Analyze this security timeline for Wazuh Agent {agent_id}.

Timeline (most recent first):
{timeline}

Provide a concise behavioral analysis in Markdown:
## Threat Assessment
## Behavioral Patterns
## Recommended Actions

Be direct, use bullet points, under 300 words."""

        async def _generate():
            try:
                async with _httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        f"{self.ollama_url}/api/generate",
                        json={"model": self.ollama_model, "prompt": prompt, "stream": True},
                        timeout=300.0,
                    ) as response:
                        if response.status_code != 200:
                            yield f"[Ollama Error: HTTP {response.status_code}]"
                            return
                        async for line in response.aiter_lines():
                            if line:
                                try:
                                    data = json.loads(line)
                                    token = data.get("response", "")
                                    if token:
                                        yield token
                                    if data.get("done", False):
                                        break
                                except Exception:
                                    pass
            except _httpx.ConnectError:
                yield "\n\n**[Erreur: Ollama non démarré. Lancez `ollama serve`]**"
            except Exception as e:
                yield f"\n\n**[Erreur: {str(e)}]**"

        async for token in self._wrap_stream("behavioral", agent_id, _generate()):
            yield token

    async def stream_global_report(self):
        import httpx as _httpx
        db = SessionLocal()
        try:
            from ..models import Alert, Device
            alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(30).all()
            devices = db.query(Device).all()
            total_devices = len(devices)
            online_devices = sum(1 for d in devices if d.is_online)
            wazuh_agents = sum(1 for d in devices if d.is_wazuh_agent)

            if not alerts:
                alert_summary = "No security alerts recorded in the database."
            else:
                by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for a in alerts:
                    s = int(a.severity or 0)
                    if s >= 12: by_sev["critical"] += 1
                    elif s >= 8: by_sev["high"] += 1
                    elif s >= 4: by_sev["medium"] += 1
                    else: by_sev["low"] += 1
                recent_lines = [f"- [{a.timestamp.strftime('%H:%M')}] L{a.severity}: {a.description} ({a.src_ip})" for a in alerts[:5]]
                alert_summary = f"Critical:{by_sev['critical']} High:{by_sev['high']} Medium:{by_sev['medium']} Low:{by_sev['low']}\n" + "\n".join(recent_lines)
        except Exception as e:
            alert_summary = f"Data error: {e}"
            total_devices, online_devices, wazuh_agents = 0, 0, 0
        finally:
            db.close()

        prompt = f"""You are a CISO writing an Executive Security Audit Report.

Network Status:
- Total monitored devices: {total_devices} | Online: {online_devices} | Wazuh agents: {wazuh_agents}

Alert Distribution (last 30):
{alert_summary}

Generate a professional Markdown report:
# Executive Network Security Audit
## 1. Security Posture Overview
## 2. Key Threat Indicators
## 3. Network Health Summary
## 4. Immediate Action Items
## 5. Strategic Recommendations

Professional CISO language, max 400 words."""

        async def _generate():
            try:
                async with _httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        f"{self.ollama_url}/api/generate",
                        json={"model": self.ollama_model, "prompt": prompt, "stream": True},
                        timeout=300.0,
                    ) as response:
                        if response.status_code != 200:
                            yield f"[Ollama Error: HTTP {response.status_code}]"
                            return
                        async for line in response.aiter_lines():
                            if line:
                                try:
                                    data = json.loads(line)
                                    token = data.get("response", "")
                                    if token:
                                        yield token
                                    if data.get("done", False):
                                        break
                                except Exception:
                                    pass
            except _httpx.ConnectError:
                yield "\n\n**[Erreur: Ollama non démarré. Lancez `ollama serve`]**"
            except Exception as e:
                yield f"\n\n**[Erreur: {str(e)}]**"

        async for token in self._wrap_stream("global", None, _generate()):
            yield token


wazuh_service = WazuhService()
