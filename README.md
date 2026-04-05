# Textpads

Minimal collaborative plain-text editor with optional browser-side encryption.

- Real-time sync via WebSocket
- AES-256-GCM encryption in the browser for protected pads
- Separate static auth hash for server-side access checks
- Password-protected or open pads
- Always-dark interface
- Automatic pad expiry and scheduled full cleanup
- No accounts, no formatting — just text
- Mobile-friendly

## How To Use

1. Open the landing page.
2. Enter a pad name.
3. To create an open pad, leave the password empty.
4. To create a protected pad, enter a password before creating it.
5. To reopen an existing protected pad, use the same pad name and password.
6. Share the pad URL and password separately if you want other people to join.

Usage rules:

- Pad names use letters, numbers, and hyphens.
- Open pads store plaintext on the server.
- Protected pads encrypt pad content in the browser before upload.
- Protected pads still use a server-side auth hash to gate access.
- Pads are deleted automatically after 24 hours without access.
- All pads are deleted weekly at 03:00 GMT+3.

## Technical Overview

- **Frontend:** vanilla HTML/CSS/JS served by `nginx`
- **Backend:** single Python WebSocket server using `websockets`
- **Proxy:** `nginx` terminates TLS and proxies `/ws/` to `127.0.0.1:8765`
- **Storage:** one `*.txt` file per pad and one `*.meta.json` file per pad

Protected pad flow:

1. The browser keeps the raw password locally.
2. The browser derives an AES key for encrypting/decrypting pad content.
3. The browser derives a separate static auth hash for server-side authentication.
4. The server stores ciphertext plus pad metadata for protected pads.
5. The server never needs the raw password for authentication.

Data lifecycle:

- Recent pads are kept in memory while active.
- Pad files are stored under the configured data directory.
- Pads inactive for more than 24 hours are purged by the app.
- A separate cleanup script can remove all pads immediately.
- A weekly systemd timer performs a full wipe of all pad files.

## Stack

- **Backend:** Python 3 + `websockets`
- **Frontend:** Vanilla HTML/CSS/JS
- **Proxy:** Nginx with TLS

## Deploy

1. Edit `pad-nginx.conf` and `pad.service` — replace `example.com` with your domain
2. Run `bash deploy.sh`
3. Updates: `bash update.sh`

## Manual Cleanup

The repository includes a simple shell script for deleting all pads:

```bash
bash cleanup-pads.sh
```
