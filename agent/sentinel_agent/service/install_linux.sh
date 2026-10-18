#!/bin/bash
# Install Sentinel Agent as systemd service (Linux)
# Usage: sudo ./install_linux.sh
set -e
AGENT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG="$AGENT_DIR/config.json"
SERVICE_NAME="sentinel-agent"
USER="${SUDO_USER:-$USER}"

if [[ $EUID -ne 0 ]]; then
  echo "Relancez avec sudo: sudo $0"
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "ERREUR: $CONFIG introuvable. Copiez config.example.json -> config.json et éditez server_url/agent_id/token"
  exit 1
fi

echo "[1/4] Installation dépendances Python..."
python3 -m pip install --upgrade pip
pip install -r "$AGENT_DIR/requirements.txt" || pip3 install -r "$AGENT_DIR/requirements.txt"

echo "[2/4] Création utilisateur/service..."
id sentinel-agent >/dev/null 2>&1 || useradd -r -s /bin/false sentinel-agent || true

echo "[3/4] Installation systemd..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Sentinel Bridge Agent (lab local)
After=network.target
Wants=network.target

[Service]
Type=simple
User=sentinel-agent
Group=sentinel-agent
WorkingDirectory=$AGENT_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$(which python3) -m sentinel_agent --config $CONFIG
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "[4/4] Vérification..."
systemctl status "$SERVICE_NAME" --no-pager -l || true
echo ""
echo "Logs: journalctl -u $SERVICE_NAME -f"
echo "Config: $CONFIG"
echo "Désinstaller: sudo $AGENT_DIR/sentinel_agent/service/uninstall_linux.sh"
