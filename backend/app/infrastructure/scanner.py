import asyncio
import ctypes
import logging
import os
import socket
from datetime import UTC, datetime

import psutil
from scapy.all import ARP, Ether, conf, srp
from sqlalchemy.orm import Session

from ..models import ConnectionLog, Device

logger = logging.getLogger(__name__)

if os.name == 'nt':
    conf.use_pcap = True

def get_active_interfaces():
    """Identifie les noms d'interfaces et leurs sous-réseaux associés, en évitant les interfaces virtuelles."""
    interfaces_to_scan = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for name, addr_list in addrs.items():
            # Vérifie si l'interface est active
            if name in stats and stats[name].isup:
                # Filtre les interfaces virtuelles courantes
                if any(virtual in name.lower() for virtual in ['vbox', 'virtual', 'docker', 'wsl', 'vmware', 'vpn', 'pseudo']):
                    continue

                for addr in addr_list:
                    # Filtrage IPv4 pour éviter les adresses fe80::
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        ip = addr.address
                        subnet = ".".join(ip.split('.')[:-1]) + ".0/24"
                        interfaces_to_scan.append({
                            "iface_name": name,
                            "subnet": subnet
                        })
    except Exception as e:
        logger.error(f"Error getting active interfaces: {e}")
    return interfaces_to_scan

_root_warned = False

def scan_network():
    """Effectue un scan ARP sur chaque carte réseau physique détectée."""
    global _root_warned

    is_admin = False
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
    else:
        is_admin = os.getuid() == 0

    if not is_admin:
        if not _root_warned:
            logger.warning("Not running as root — ARP scan disabled. Run with sudo for network discovery.")
            _root_warned = True
        return []

    all_devices = []
    target_interfaces = get_active_interfaces()

    if not target_interfaces:
        if not _root_warned:
            logger.warning("No active physical interfaces found to scan.")
            _root_warned = True

    for target in target_interfaces:
        arp_request = ARP(pdst=target['subnet'])
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        try:
            ans, _ = srp(packet, iface=target['iface_name'], timeout=3, verbose=False)

            for sent, received in ans:
                all_devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "is_online": True
                })
        except Exception as e:
            logger.error("Scan error on interface %s: %s", target['iface_name'], e)

    return all_devices

async def background_scanner(db_factory, broadcaster, interval: int):
    """Boucle de scan en arrière-plan avec mise à jour de la base de données."""
    while True:
        db: Session = db_factory()
        try:
            now = datetime.now(UTC)
            # Correction : seen est une liste de dict, pas de tuples
            seen = scan_network()
            online_ids = set()

            for item in seen:
                ip = item["ip"]
                mac = item["mac"]

                # 1. Gestion des conflits d'IP (Unique constraint)
                # Si l'IP est déjà attribuée à un AUTRE MAC, on libère l'IP du vieux record
                stale_device = db.query(Device).filter(Device.ip == ip, Device.mac != mac).first()
                if stale_device:
                    stale_device.ip = None
                    stale_device.is_online = False
                    db.flush()

                # 2. Recherche ou Création par MAC (Identifiant matériel stable)
                dev = db.query(Device).filter(Device.mac == mac).first()

                if not dev:
                    dev = Device(ip=ip, mac=mac, is_online=True)
                    db.add(dev)
                    db.flush()
                    db.add(ConnectionLog(device_id=dev.id, status=True, start_time=now))
                    await broadcaster({"device_id": dev.id, "status": True, "time": now.isoformat()})
                else:
                    online_ids.add(dev.id)
                    dev.ip = ip # Mise à jour propre
                    if not dev.is_online:
                        dev.is_online = True
                        db.add(ConnectionLog(device_id=dev.id, status=True, start_time=now))
                        await broadcaster({"device_id": dev.id, "status": True, "time": now.isoformat()})

            # Gestion des appareils qui sont passés hors ligne
            online_in_db = db.query(Device).filter(Device.is_online.is_(True)).all()
            for dev in online_in_db:
                if dev.id not in online_ids:
                    dev.is_online = False
                    # Fermeture du log de connexion précédent
                    last_log = (
                        db.query(ConnectionLog)
                        .filter(ConnectionLog.device_id == dev.id, ConnectionLog.end_time.is_(None))
                        .order_by(ConnectionLog.start_time.desc())
                        .first()
                    )
                    if last_log:
                        last_log.end_time = now

                    # Ajout d'un log de déconnexion
                    db.add(ConnectionLog(device_id=dev.id, status=False, start_time=now, end_time=now))
                    await broadcaster({"device_id": dev.id, "status": False, "time": now.isoformat()})

            db.commit() # Sauvegarde globale de la session
        except Exception as e:
            logger.error("Scan error: %s", e)
            db.rollback()
        finally:
            db.close()

        await asyncio.sleep(interval)
