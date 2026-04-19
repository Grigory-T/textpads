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
sudo cp "$REPO_DIR/textpads-weekly-cleanup.service" /etc/systemd/system/textpads-weekly-cleanup.service
sudo cp "$REPO_DIR/textpads-weekly-cleanup.timer" /etc/systemd/system/textpads-weekly-cleanup.timer
sudo cp "$REPO_DIR/cleanup-pads.sh" /usr/local/bin/textpads-delete-all.sh
sudo chmod 755 /usr/local/bin/textpads-delete-all.sh
sudo systemctl daemon-reload

echo "=== Restart ==="
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart pad.service
sudo systemctl restart textpads-weekly-cleanup.timer || true

sleep 1
systemctl is-active pad.service
systemctl is-active nginx
echo "Done."
