#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Install nginx ==="
sudo apt-get update -qq
sudo apt-get install -y nginx

echo "=== Create directories ==="
sudo mkdir -p /opt/pad/static /opt/pad/data
sudo chown -R pad:pad /opt/pad
chmod 700 /opt/pad/data

echo "=== Python venv ==="
python3 -m venv /opt/pad/venv
/opt/pad/venv/bin/pip install --quiet websockets

echo "=== Copy app files ==="
cp "$REPO_DIR/server.py" /opt/pad/server.py
cp "$REPO_DIR/static/"* /opt/pad/static/

echo "=== Nginx config ==="
sudo cp "$REPO_DIR/pad-ratelimit.conf" /etc/nginx/conf.d/pad-ratelimit.conf
sudo cp "$REPO_DIR/pad-nginx.conf" /etc/nginx/sites-available/pad
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/pad /etc/nginx/sites-enabled/pad
sudo nginx -t

echo "=== Systemd service ==="
sudo cp "$REPO_DIR/pad.service" /etc/systemd/system/pad.service
sudo systemctl daemon-reload

echo "=== Firewall ==="
sudo ufw allow 80/tcp comment 'HTTP' 2>/dev/null || true
sudo ufw allow 443/tcp comment 'HTTPS' 2>/dev/null || true

echo "=== Start services ==="
sudo systemctl enable --now pad.service
sudo systemctl restart pad.service
sudo systemctl enable --now nginx
sudo systemctl reload nginx

sleep 1
echo "=== Status ==="
systemctl is-active pad.service
systemctl is-active nginx
echo "Done."
