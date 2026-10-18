#!/bin/bash
# Uninstall sentinel-agent systemd service
set -e
SERVICE_NAME="sentinel-agent"
if [[ $EUID -ne 0 ]]; then echo "sudo requis"; exit 1; fi
systemctl stop "$SERVICE_NAME" || true
systemctl disable "$SERVICE_NAME" || true
rm -f /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload
echo "Service $SERVICE_NAME supprimé. Données conservées dans /home/sentinel-agent et queue.jsonl — supprimez manuellement si besoin."
