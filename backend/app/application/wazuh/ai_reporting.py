import asyncio
import json
import logging
import re

from ...db import SessionLocal

logger = logging.getLogger(__name__)


class WazuhAIReporting:
    """Ollama SSE streaming reports (agent behavioral + global CISO audit)."""

    async def _save_report(self, report_type: str, content: str, agent_id: str | None = None, tenant_id: str = "default"):
        db = SessionLocal()
        try:
            from ...models import IaReport
            report = IaReport(report_type=report_type, content=content, agent_id=agent_id, tenant_id=tenant_id)
            db.add(report)
            db.commit()
            logger.info("AI report saved: type=%s agent=%s", report_type, agent_id or "global")
        except Exception as e:
            logger.error("Failed to save AI report: %s", e)
        finally:
            db.close()

    async def _wrap_stream(self, report_type: str, agent_id: str | None, inner, tenant_id: str = "default"):
        tokens = []
        async for token in inner:
            tokens.append(token)
            yield token
        if tokens:
            full = "".join(tokens)
            asyncio.create_task(self._save_report(report_type, full, agent_id, tenant_id=tenant_id))

    def _sanitize(self, text: str) -> str:
        text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
        text = re.sub(r'<img[^>]*>', '', text)
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
        return text.strip()[:500]

    async def stream_ai_report(self, agent_id: str, tenant_id: str = "default"):
        import httpx as _httpx
        db = SessionLocal()
        try:
            from ...models import Alert
            alerts = db.query(Alert).filter(Alert.agent_id == agent_id).filter(Alert.tenant_id == tenant_id).order_by(Alert.timestamp.desc()).limit(10).all()
            if not alerts:
                timeline = "No recent security events recorded for this agent."
            else:
                lines = [f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Level {a.severity}: {self._sanitize(a.description)} (src: {a.src_ip})" for a in alerts]
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

Be direct, use bullet points, under 200 words."""

        async def _generate():
            try:
                async with _httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        f"{self.ollama_url}/api/generate",
                        json={
                            "model": self.ollama_model,
                            "prompt": prompt,
                            "stream": True,
                            "options": {"num_predict": 512, "temperature": 0.7}
                        },
                        timeout=120.0,
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

        async for token in self._wrap_stream("behavioral", agent_id, _generate(), tenant_id=tenant_id):
            yield token

    async def stream_global_report(self, tenant_id: str = "default"):
        import httpx as _httpx
        db = SessionLocal()
        try:
            from ...models import Device, SuricataAlert
            # Fetch 10 most recent CRITICAL Suricata alerts (severity >= 7)
            suricata_alerts = db.query(SuricataAlert).filter(SuricataAlert.severity >= 7).filter(SuricataAlert.tenant_id == tenant_id).order_by(SuricataAlert.timestamp.desc()).limit(5).all()
            devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
            total_devices = len(devices)
            online_devices = sum(1 for d in devices if d.is_online)
            wazuh_agents = sum(1 for d in devices if d.is_wazuh_agent)

            if not suricata_alerts:
                alert_summary = "Aucune alerte Suricata critique (severity >= 7) trouvée."
            else:
                by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for a in suricata_alerts:
                    s = int(a.severity or 0)
                    if s >= 7: by_sev["critical"] += 1
                    elif s >= 5: by_sev["high"] += 1
                    elif s >= 3: by_sev["medium"] += 1
                    else: by_sev["low"] += 1
                recent_lines = [f"- [{a.timestamp.strftime('%H:%M')}] S{a.severity}: {self._sanitize(a.alert_msg)} ({a.src_ip}->{a.dest_ip} {a.proto})" for a in suricata_alerts[:5]]
                alert_summary = f"Critical:{by_sev['critical']} High:{by_sev['high']} Medium:{by_sev['medium']} Low:{by_sev['low']}\n" + "\n".join(recent_lines)
        except Exception as e:
            alert_summary = f"Data error: {e}"
            total_devices, online_devices, wazuh_agents = 0, 0, 0
        finally:
            db.close()

        prompt = f"""You are a CISO writing an Executive Security Audit Report based on Suricata IDS network threats.

Network Status:
- Total devices: {total_devices} | Online: {online_devices} | Wazuh: {wazuh_agents}

Top Suricata Alerts (severity >= 7):
{alert_summary}

Generate a Markdown report:
# Network Security Audit
## 1. Threat Posture
## 2. Key Indicators
## 3. Action Items

Professional CISO language, max 300 words."""

        async def _generate():
            try:
                async with _httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        f"{self.ollama_url}/api/generate",
                        json={
                            "model": self.ollama_model,
                            "prompt": prompt,
                            "stream": True,
                            "options": {"num_predict": 512, "temperature": 0.7}
                        },
                        timeout=120.0,
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

        async for token in self._wrap_stream("global", None, _generate(), tenant_id=tenant_id):
            yield token

