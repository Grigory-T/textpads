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
sudo cp "$REPO_DIR/textpads-full-cleanup.service" /etc/systemd/system/textpads-full-cleanup.service
sudo cp "$REPO_DIR/textpads-full-cleanup.timer" /etc/systemd/system/textpads-full-cleanup.timer
sudo cp "$REPO_DIR/textpads-full-cleanup.sh" /usr/local/bin/textpads-full-cleanup.sh
sudo chmod 755 /usr/local/bin/textpads-full-cleanup.sh
sudo systemctl disable --now textpads-weekly-cleanup.timer 2>/dev/null || true
sudo rm -f /etc/systemd/system/textpads-weekly-cleanup.service /etc/systemd/system/textpads-weekly-cleanup.timer /usr/local/bin/textpads-delete-all.sh
sudo systemctl daemon-reload

echo "=== Restart ==="
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart pad.service
sudo systemctl enable --now textpads-full-cleanup.timer

sleep 1
systemctl is-active pad.service
systemctl is-active nginx
echo "Done."
