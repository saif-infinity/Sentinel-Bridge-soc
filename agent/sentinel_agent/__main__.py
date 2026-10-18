"""Agent main loop — heartbeat + telemetry batch + orders."""
import argparse
import json
import logging
import pathlib
import platform
import signal
import sys
import time
from datetime import datetime, timezone

from .config import load_config
from .client import SentinelClient
from .queue import BoundedQueue
from .collectors.processes import collect_processes
from .collectors.network import collect_network, collect_auth_events
from .collectors.system_logs import collect_system_logs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("sentinel_agent")

# Global for signal handling
_running = True


def _signal_handler(signum, frame):
    global _running
    logger.info("Signal %s reçu — arrêt propre...", signum)
    _running = False


def _check_mode(cfg: dict) -> bool:
    """Mode --check : vérifie connectivité et affiche diagnostic sans boucle."""
    from .client import SentinelClient
    print("=== Sentinel Agent — Vérification connectivité ===")
    print(f"Serveur: {cfg['server_url']}")
    print(f"Agent ID: {cfg['agent_id']}")
    print(f"Tenant: {cfg.get('tenant_id')}")
    print(f"Verify TLS: {cfg.get('verify_tls')}")
    print(f"Config file: {cfg.get('_config_path')}")
    if cfg.get("_warn_localhost"):
        print("⚠️  server_url contient localhost/127.0.0.1 — depuis un PC distant, utilisez l'IP LAN du serveur (ex: http://192.168.1.50:8001)")

    client = SentinelClient(cfg)
    # 1. Check TCP reachability
    checks = client.check_connectivity()
    print(json.dumps(checks, indent=2, ensure_ascii=False))
    # 2. Try register
    try:
        resp = client.register()
        print("\n✓ Register OK:", json.dumps(resp, indent=2, ensure_ascii=False)[:500])
    except Exception as e:
        print(f"\n✗ Register échoué: {e}")
        print("Vérifiez: pare-feu Windows (port 8001), adresse LAN, Wi-Fi isolation (AP isolation désactivée)")
        return False
    # 3. Heartbeat
    try:
        hb = client.heartbeat()
        print("\n✓ Heartbeat OK:", json.dumps(hb, indent=2, ensure_ascii=False)[:400])
    except Exception as e:
        print(f"\n✗ Heartbeat échoué: {e}")
    print("\nPare-feu nécessaires:")
    print("  Serveur (PC SOC): ouvrir TCP 8001 INBOUND depuis le subnet Wi-Fi")
    print("  Agents: autoriser OUTBOUND vers serveur:8001")
    print("  Si Wi-Fi invité / isolation client: désactiver 'AP isolation' sur la box, ou passer sur réseau principal")
    return checks.get("server_reachable", False)


def build_telemetry_batch(cfg: dict) -> dict:
    """Construit un batch selon collecte configurable."""
    batch: dict = {}
    now = datetime.now(timezone.utc).isoformat()

    if cfg.get("enable_system_logs", True):
        try:
            batch["system_logs"] = collect_system_logs(max_lines=30)
        except Exception as e:
            logger.warning("collect_system_logs échoué: %s", e)
            batch["system_logs"] = []

    if cfg.get("enable_auth_logs", True):
        try:
            batch["auth_logs"] = collect_auth_events()
            # aussi auth_events alias
            if batch["auth_logs"]:
                batch["auth_events"] = batch["auth_logs"]
        except Exception as e:
            logger.warning("collect_auth échoué: %s", e)

    if cfg.get("enable_processes", True):
        try:
            max_proc = int(cfg.get("max_processes", 500))
            batch["processes"] = collect_processes(max_count=max_proc)
        except Exception as e:
            logger.warning("collect_processes échoué: %s", e)

    if cfg.get("enable_network", True):
        try:
            batch["network_connections"] = collect_network(max_count=200)
        except Exception as e:
            logger.warning("collect_network échoué: %s", e)

    # Pseudo security_events pour pipeline: transformer certains logs en events
    sec_events = []
    for log in batch.get("system_logs", [])[:10]:
        if log.get("severity") in ("high", "warning") and "failed" in log.get("detail", "").lower():
            sec_events.append({
                "ts": log.get("ts", now),
                "source": log.get("source", "system"),
                "severity": log.get("severity", "medium"),
                "detail": log.get("detail", ""),
                "event_type": "suspicious_activity",
            })
    if sec_events:
        batch["security_events"] = sec_events

    return batch


def run_agent(cfg: dict):
    global _running
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _signal_handler)

    client = SentinelClient(cfg)
    # File locale bornée — pour .exe: à côté de l'exe, sinon home
    # Détection exe: si _config_path est dans un dossier d'exe, data_dir = ce dossier/data
    import sys as _sys
    if getattr(_sys, "frozen", False):
        # PyInstaller one-file: exe dir = où est SentinelAgent.exe
        try:
            exe_dir = pathlib.Path(_sys.executable).parent
            default_data_dir = exe_dir / "data"
        except Exception:
            default_data_dir = pathlib.Path(".") / "data"
    else:
        default_data_dir = pathlib.Path.home() / ".sentinel-agent" if platform.system() != "Windows" else pathlib.Path(".") / "data"
    data_dir = pathlib.Path(cfg.get("data_dir", default_data_dir))
    if cfg.get("_config_path"):
        # Use config dir for queue
        cfg_path = pathlib.Path(cfg["_config_path"])
        data_dir = cfg_path.parent / "data" if cfg_path.parent != pathlib.Path(".") else data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    queue_path = data_dir / "queue.jsonl"
    queue = BoundedQueue(
        str(queue_path),
        max_events=int(cfg.get("queue_max_events", 5000)),
        max_bytes=int(cfg.get("queue_max_bytes", 20 * 1024 * 1024)),
    )

    seq = int(cfg.get("last_seq", 0))
    # Try to recover last seq from agent state file
    state_path = data_dir / "state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            seq = int(state.get("seq", seq))
        except Exception:
            pass

    logger.info("Sentinel Agent démarré — %s → %s (tenant=%s) seq=%s", cfg["agent_id"], cfg["server_url"], cfg["tenant_id"], seq)
    logger.info("Queue: %s (%d events, %d bytes) — interval telemetry=%ss heartbeat=%ss", queue_path, queue.size(), queue.bytes_used(), cfg["telemetry_interval_secs"], cfg["heartbeat_interval_secs"])

    # Register initial
    try:
        reg = client.register()
        logger.info("Register OK — config serveur: %s", {k: v for k, v in (reg.get("config") or {}).items() if "key" not in k.lower()})
        # Merge server config (collecte configurable)
        srv_cfg = reg.get("config", {})
        for k in ("enable_system_logs", "enable_auth_logs", "enable_processes", "enable_network", "batch_size"):
            if k in srv_cfg and srv_cfg[k] != "":
                # server value as string
                val = srv_cfg[k]
                if isinstance(val, str) and val.lower() in ("true", "false"):
                    cfg[k] = val.lower() == "true"
                else:
                    try:
                        cfg[k] = int(val)
                    except Exception:
                        cfg[k] = val
    except Exception as e:
        logger.warning("Register échoué au démarrage (file locale garde les données): %s", e)

    last_heartbeat = 0
    last_telemetry = 0

    while _running:
        now = time.time()
        try:
            # Heartbeat
            hb_interval = int(cfg.get("heartbeat_interval_secs", 30))
            if now - last_heartbeat >= hb_interval:
                try:
                    collectors_status = {
                        "system_logs": cfg.get("enable_system_logs", True),
                        "auth_logs": cfg.get("enable_auth_logs", True),
                        "processes": cfg.get("enable_processes", True),
                        "network": cfg.get("enable_network", True),
                        "queue_size": queue.size(),
                    }
                    hb = client.heartbeat(collectors_status)
                    logger.debug("Heartbeat OK — pending_orders=%s", hb.get("pending_orders"))
                    last_heartbeat = now
                    # Check orders after heartbeat
                    if hb.get("pending_orders", 0) > 0:
                        _poll_orders(client)
                except Exception as e:
                    logger.warning("Heartbeat échoué: %s", e)
                    last_heartbeat = now  # avoid tight loop

            # Telemetry
            tel_interval = int(cfg.get("telemetry_interval_secs", 30))
            if now - last_telemetry >= tel_interval:
                batch = build_telemetry_batch(cfg)
                # Add to queue (bounded, dedup)
                total_events = sum(len(v) for v in batch.values() if isinstance(v, list))
                if total_events == 0:
                    logger.debug("Aucun événement collecté ce cycle")
                else:
                    # Flatten for queue: each event as separate? For now batch as one queue entry per category
                    # Simpler: queue one item per batch containing seq
                    seq += 1
                    queue_item = {"seq": seq, "batch": batch, "ts": datetime.now(timezone.utc).isoformat()}
                    queue.append(queue_item)
                    logger.info("Collecte: %d events → queue seq=%d (queue size %d)", total_events, seq, queue.size())

                # Try to flush queue
                batch_size = int(cfg.get("batch_size", 50))
                to_send = queue.load_batch(batch_size)
                if to_send:
                    # Merge batches into one telemetry payload
                    merged: dict = {}
                    send_seq = seq
                    for item in to_send:
                        b = item.get("batch", {})
                        for k, v in b.items():
                            if k not in merged:
                                merged[k] = []
                            if isinstance(v, list):
                                merged[k].extend(v)
                    # Deduplicate already handled in queue; now send
                    try:
                        resp = client.telemetry(send_seq, merged)
                        ack = resp.get("ack_seq")
                        received = resp.get("received", 0)
                        logger.info("Telemetry seq=%d → serveur ack_seq=%s received=%s", send_seq, ack, received)
                        # Ack fiable: purge queue if ack >= send_seq
                        if ack is not None and int(ack) >= send_seq:
                            queue.ack(len(to_send))
                            # Persist seq
                            try:
                                state_path.write_text(json.dumps({"seq": send_seq, "last_ack": ack}), encoding="utf-8")
                            except Exception:
                                pass
                        elif received is not None and received > 0:
                            # At least received, ack batch
                            queue.ack(len(to_send))
                    except Exception as e:
                        logger.warning("Envoi telemetry échoué (conservé en file): %s", e)
                        # Backoff: wait before retry
                        time.sleep(min(5, tel_interval))

                last_telemetry = now

            # Orders polling (separate interval)
            orders_interval = int(cfg.get("orders_interval_secs", 10))
            if now - last_telemetry >= orders_interval:
                _poll_orders(client)

        except Exception as e:
            logger.exception("Boucle agent erreur: %s", e)

        # Sleep with interruptible check
        for _ in range(10):
            if not _running:
                break
            time.sleep(0.5)

    logger.info("Arrêt agent — seq final %d, queue %d events", seq, queue.size())
    try:
        state_path.write_text(json.dumps({"seq": seq}), encoding="utf-8")
    except Exception:
        pass


def _poll_orders(client: SentinelClient):
    try:
        orders = client.get_orders()
        if not orders:
            return
        logger.info("%d ordre(s) en attente", len(orders))
        for order in orders:
            _execute_order(client, order)
    except Exception as e:
        logger.warning("Poll orders échoué: %s", e)


def _execute_order(client: SentinelClient, order: dict):
    order_id = order.get("id")
    action = order.get("action_type")
    target = order.get("target")
    params = order.get("params", {})
    logger.info("Exécution ordre %s: %s target=%s", order_id, action, target)

    # Whitelist stricte — aucune exécution arbitraire
    allowed = {"block_ip", "unblock_ip", "kill_process", "quarantine_file", "terminate_session", "restart_service"}
    if action not in allowed:
        client.submit_order_result(order_id, "error", error=f"action non autorisée: {action}")
        return

    output = ""
    error = None
    try:
        if action == "block_ip":
            output = f"[DRY-RUN] block_ip {target} — à implémenter via pare-feu local (netsh/iptables). Non exécuté sans confirmation."
            # En lab, on log mais ne bloque pas réellement sans module firewall
        elif action == "unblock_ip":
            output = f"[DRY-RUN] unblock_ip {target}"
        elif action == "kill_process":
            output = f"[DRY-RUN] kill_process {target} — vérifier PID/nom manuellement."
            # Real impl would use psutil
            try:
                import psutil
                # Only kill if target is numeric PID and we confirm
                if target and target.isdigit():
                    p = psutil.Process(int(target))
                    output = f"Process {target} ({p.name()}) — arrêt non effectué automatiquement (nécessite approbation)."
                else:
                    output = f"kill_process {target} — en attente validation analyste"
            except Exception as ex:
                output = f"kill_process lookup échoué: {ex}"
        elif action == "quarantine_file":
            output = f"[DRY-RUN] quarantine_file {target} — déplacer vers quarantine_dir non exécuté sans confirmation"
        elif action == "terminate_session":
            output = f"[DRY-RUN] terminate_session {target}"
        elif action == "restart_service":
            output = f"[DRY-RUN] restart_service {target}"
        client.submit_order_result(order_id, "done", output=output)
        logger.info("Ordre %s terminé: %s", order_id, output[:200])
    except Exception as e:
        error = str(e)
        try:
            client.submit_order_result(order_id, "error", error=error)
        except Exception:
            pass
        logger.error("Ordre %s erreur: %s", order_id, error)


def main():
    parser = argparse.ArgumentParser(description="Sentinel Bridge Agent (lab local)")
    parser.add_argument("--config", "-c", help="Chemin config.json")
    parser.add_argument("--check", action="store_true", help="Vérifie connectivité et quitte")
    parser.add_argument("--once", action="store_true", help="Un seul cycle telemetry puis quitte")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.check:
        ok = _check_mode(cfg)
        sys.exit(0 if ok else 2)
    if args.once:
        # Single shot
        batch = build_telemetry_batch(cfg)
        print(json.dumps({"agent_id": cfg["agent_id"], "batch": batch}, indent=2, ensure_ascii=False)[:5000])
        return
    run_agent(cfg)


if __name__ == "__main__":
    main()
