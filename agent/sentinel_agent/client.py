"""HTTP client — LAN, TLS vérifié, retry, seq/ack fiable."""
import json
import time
import logging
import platform
import os

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error

logger = logging.getLogger(__name__)


class SentinelClient:
    def __init__(self, cfg: dict):
        self.server_url = cfg["server_url"].rstrip("/")
        self.agent_id = cfg["agent_id"]
        self.token = cfg.get("token", "")
        self.tenant_id = cfg.get("tenant_id", "default")
        self.verify_tls = cfg.get("verify_tls", True)
        self.timeout = int(cfg.get("http_timeout_secs", 15))
        # Coerce verify_tls: string "false"/"true"
        if isinstance(self.verify_tls, str):
            self.verify_tls = self.verify_tls.lower() not in ("false", "0", "no", "off")
        # Warn if HTTP in lab (expected) — mais documenter clairement
        if self.server_url.startswith("http://"):
            logger.warning("Mode HTTP (lab local) — non chiffré, réservé au Wi-Fi de confiance")

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "X-Tenant-ID": self.tenant_id,
            "User-Agent": f"sentinel-agent/{self.agent_id}",
        }
        if self.token:
            # Préfère X-Agent-Token, fallback Bearer
            h["X-Agent-Token"] = self.token
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.server_url}{path}"
        headers = self._headers()
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None

        if HAS_REQUESTS:
            try:
                resp = requests.request(
                    method, url, headers=headers, data=data,
                    timeout=self.timeout, verify=self.verify_tls
                )
                if resp.status_code >= 400:
                    logger.warning("HTTP %s %s → %s: %s", method, path, resp.status_code, resp.text[:300])
                    resp.raise_for_status()
                try:
                    return resp.json()
                except Exception:
                    return {"raw": resp.text}
            except requests.exceptions.SSLError as e:
                logger.error("TLS verification échouée pour %s: %s. Si vous utilisez HTTP lab, mettez verify_tls=false ou server_url en http://", url, e)
                raise
            except requests.exceptions.ConnectionError as e:
                logger.warning("Connexion échouée vers %s (%s) — file locale conserve, retry", url, e)
                raise
        else:
            # urllib fallback (sans requests)
            import urllib.request as req
            r = req.Request(url, data=data, headers=headers, method=method)
            # verify_tls=False not trivial with urllib — fallback ignore
            try:
                with req.urlopen(r, timeout=self.timeout) as resp:
                    body_bytes = resp.read()
                    return json.loads(body_bytes.decode()) if body_bytes else {}
            except urllib.error.HTTPError as e:
                logger.warning("HTTP %s %s → %s", method, path, e.code)
                raise
            except Exception as e:
                logger.warning("Connexion échouée: %s", e)
                raise

    def register(self, extra: dict | None = None) -> dict:
        payload = {
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "version": "1.0.0",
            "capabilities": {
                "collectors": ["system_logs", "auth_logs", "processes", "network"],
            },
        }
        if extra:
            payload.update(extra)
        return self._request("POST", "/api/agent/register", payload)

    def heartbeat(self, collectors_status: dict | None = None) -> dict:
        payload = {
            "agent_id": self.agent_id,
            "hostname": platform.node(),
            "version": "1.0.0",
            "collectors": collectors_status or {},
        }
        return self._request("POST", "/api/agent/heartbeat", payload)

    def telemetry(self, seq: int, batch: dict) -> dict:
        """Envoie un batch telemetry — batch contient les catégories."""
        payload = {
            "agent_id": self.agent_id,
            "seq": seq,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "version": "1.0.0",
            **batch,
        }
        return self._request("POST", "/api/agent/telemetry", payload)

    def get_orders(self) -> list[dict]:
        try:
            resp = self._request("GET", f"/api/agent/orders?agent_id={self.agent_id}")
            return resp.get("orders", [])
        except Exception:
            return []

    def submit_order_result(self, order_id: str, status: str, output: str | None = None, error: str | None = None) -> dict:
        body = {"status": status}
        if output is not None:
            body["output"] = output
        if error is not None:
            body["error"] = error
        return self._request("POST", f"/api/agent/orders/{order_id}/result", body)

    def check_connectivity(self) -> dict:
        """Vérifications de connectivité (à afficher à l'install)."""
        results = {}
        # 1. DNS / ping-like via HTTP
        try:
            # Try server root
            resp = self._request("GET", "/")
            results["server_reachable"] = True
            results["server_root"] = str(resp)[:100]
        except Exception as e:
            results["server_reachable"] = False
            results["error"] = str(e)
        # 2. TLS info
        results["server_url"] = self.server_url
        results["verify_tls"] = self.verify_tls
        results["agent_id"] = self.agent_id
        return results
