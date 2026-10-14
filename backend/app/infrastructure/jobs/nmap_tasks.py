import logging

import nmap

from ...core.celery import celery_app

logger = logging.getLogger(__name__)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600, # Les scans Nmap peuvent être longs
    task_soft_time_limit=3500,
)

@celery_app.task(name="tasks.deep_nmap_scan")
def deep_nmap_scan_task(target, scan_args):
    logger.info("Démarrage scan Nmap approfondi sur %s avec args: %s", target, scan_args)

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=scan_args)

        results = []
        for host in nm.all_hosts():
            host_info = nm[host]
            addresses = host_info.get('addresses', {})
            mac = (addresses.get('mac') or host_info.get('mac') or 'UNKNOWN').upper()

            ports = []
            for proto in host_info.all_protocols():
                for port in host_info[proto].keys():
                    service = host_info[proto][port]['name']
                    product = host_info[proto][port].get('product', '')
                    ports.append(f"{port}/{proto}: {service} {product}")

            results.append({
                "ip": host,
                "mac": mac,
                "ports": ports,
                "os": (
                    host_info.get('osmatch', [{}])[0].get('name', 'Unknown')
                    if host_info.get('osmatch') else 'Unknown'
                )
            })

        logger.info("Scan approfondi terminé. %d hôtes trouvés.", len(results))
        return {"status": "success", "results": results}

    except Exception as e:
        logger.error("Échec du scan Nmap : %s", e)
        return {"status": "error", "message": str(e)}
