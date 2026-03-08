#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Pull latest ==="
cd "$REPO_DIR"
git pull

echo "=== Update app files ==="
cp "$REPO_DIR/server.py" /opt/pad/server.py
cp "$REPO_DIR/static/"* /opt/pad/static/

echo "=== Update configs ==="
sudo cp "$REPO_DIR/pad-ratelimit.conf" /etc/nginx/conf.d/pad-ratelimit.conf
sudo cp "$REPO_DIR/pad-nginx.conf" /etc/nginx/sites-available/pad
sudo cp "$REPO_DIR/pad.service" /etc/systemd/system/pad.service
sudo systemctl daemon-reload

echo "=== Restart ==="
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart pad.service

sleep 1
systemctl is-active pad.service
systemctl is-active nginx
echo "Done."
