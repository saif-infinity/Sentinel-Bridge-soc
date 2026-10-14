import logging
from typing import Any

from ...db import SessionLocal

logger = logging.getLogger(__name__)


class WazuhTopology:
    """Wazuh read queries: active alerts, agent logs, topology graph."""

    async def get_active_alerts(self, tenant_id: str = "default") -> list[dict[str, Any]]:
        db = SessionLocal()
        try:
            from ...models import Alert
            alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).order_by(Alert.timestamp.desc()).limit(50).all()
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

    async def get_topology(self) -> dict[str, Any]:
        agents = await self.get_agents()
        nodes = []
        edges = []
        subnets = {}

        # Add Wazuh Manager node
        nodes.append({
            "id": "manager",
            "type": "custom",
            # Le statut du manager reflète la réalité de la connexion, pas "normal" en dur.
            "data": {
                "label": "Wazuh Manager",
                "status": "normal" if self._wazuh_available else "unavailable",
                "ip": "127.0.0.1",
                "type": "manager",
                "os": "Linux",
            },
            "position": {"x": 0, "y": 0}
        })

        # Plus de « mock topology for UI » : trois hôtes inventés
        # (Workstation-01/Server-01/Laptop-01, IPs 192.168.1.x) étaient renvoyés
        # dès que Wazuh était injoignable. Un analyste voyait donc un parc fictif
        # présenté comme réel — exactement ce qu'un outil de défense ne doit jamais
        # faire. On renvoie désormais l'état vide + un drapeau explicite que le
        # frontend affiche comme « source indisponible ».
        source_unavailable = bool(not agents and not self._wazuh_available)

        for agent in agents:
            agent_id = agent['id']
            agent_name = agent.get('name', f'Agent-{agent_id}')
            agent_status = agent.get('status', 'disconnected')
            if agent_id == "000":
                continue

            async with self._cache_lock:
                cached_ip = self._agent_ip_cache.get(agent_id, {}).get('ip', '0.0.0.0') if agent_id in self._agent_ip_cache else None
            real_ip = None
            if cached_ip and cached_ip not in ['0.0.0.0', '127.0.0.1', 'any', None]:
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

    async def get_agent_logs(self, agent_id: str, tenant_id: str = "default", limit: int = 40) -> list[dict[str, Any]]:
        db = SessionLocal()
        try:
            from ...models import Alert
            alerts = db.query(Alert).filter(Alert.agent_id == agent_id).filter(Alert.tenant_id == tenant_id).order_by(Alert.timestamp.desc()).limit(limit).all()
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

