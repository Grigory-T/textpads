# Textpads

Collaborative plain-text editor with optional client-side encryption.

- Real-time sync via WebSocket
- AES-256-GCM encryption in the browser (server stores only ciphertext)
- Password-protected or open pads
- No accounts, no formatting — just text
- Mobile-friendly

## Stack

- **Backend:** Python 3 + `websockets`
- **Frontend:** Vanilla HTML/CSS/JS
- **Proxy:** Nginx with TLS

## Deploy

1. Edit `pad-nginx.conf` and `pad.service` — replace `example.com` with your domain
2. Run `bash deploy.sh`
3. Updates: `bash update.sh`
