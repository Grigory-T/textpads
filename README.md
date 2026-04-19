# Textpads

Minimal collaborative plain-text editor with optional browser-side encryption.

- Real-time sync via WebSocket
- AES-256-GCM encryption in the browser for protected pads
- Separate static auth hash for server-side access checks
- Open or password-protected pads
- Always-dark interface
- Logical line numbers with stable no-wrap editor behavior
- Automatic pad expiry and scheduled full cleanup
- No accounts, no formatting, no history

## How To Use

1. Open the landing page.
2. Enter a pad name.
3. Leave password empty to create an open pad.
4. Enter a password to create a protected pad.
5. Reopen an existing protected pad with the same pad name and password.
6. Share the pad URL and password separately if other people should join.

Usage rules:

- Pad names use letters, numbers, and hyphens.
- Open pads store plaintext on the server.
- Protected pads encrypt content in the browser before upload.
- Protected pads still use a server-side auth hash to gate access.
- The editor uses logical line numbers only.
- Soft wrap is disabled for reliability; long lines scroll horizontally.
- Pads are deleted automatically after 7 days without successful access (configurable).
- All pads are deleted every 30 days by a systemd timer (configurable).

## Technical Overview

- **Frontend:** vanilla HTML/CSS/JS served by `nginx`
- **Backend:** single Python WebSocket server using `websockets`
- **Proxy:** `nginx` terminates TLS and proxies `/ws/` to `127.0.0.1:8765`
- **Storage:** one `*.txt` file per pad and one `*.meta.json` file per pad
- **Transport:** browser uses `https://` and `wss://`

Pad model:

- A pad is identified by its name.
- Open pads require only the pad name.
- Protected pads require the pad name and password.
- Anyone who knows the pad name and password can read and write that pad.

Protected pad flow:

1. The browser keeps the raw password locally.
2. The browser derives an AES key for encrypting and decrypting pad content.
3. The browser derives a separate static auth hash for server-side authentication.
4. The browser sends ciphertext plus auth hash to the server.
5. The server stores ciphertext plus pad metadata for protected pads.

Important security note:

- This is safer than sending the raw password to the server.
- It is not true end-to-end encryption.
- The static auth hash is still a reusable server-side credential.
- A malicious server can still serve modified JavaScript to capture future passwords.

## Sync Model

- Each client keeps a full local copy of the document.
- After `300 ms` of typing inactivity, the client sends the full document over WebSocket.
- Each update includes the client's current document version.
- If the version matches the server version, the server accepts the update, increments the version, stores the new full text, sends `ack` to the sender, and broadcasts the update to other clients.
- If the version is stale, the server rejects the update and returns `conflict` with the latest server text and version.

Implications:

- This is full-document sync, not patch-based sync.
- There is no merge, OT, or CRDT logic.
- Concurrent editing is effectively last-valid-write-wins.
- Simultaneous edits to the same area can still discard one side.

## Data Lifecycle

- Recent pads are kept in memory while active.
- Pad files are stored under the configured data directory.
- Pads inactive for more than the configured expiry are purged by the app.
- A separate cleanup script can remove all pads immediately.
- A systemd timer performs a full wipe of all pad files on a schedule.

## Retention Settings

These settings are intended to be easy to find and change:

- **Auto-expire (server-side):** edit `pad.service` and set `PAD_EXPIRY_DAYS` (or `PAD_EXPIRY_SECONDS`).
- **Expiry scan interval:** edit `pad.service` and set `PAD_EXPIRY_SCAN_MINUTES` (or `PAD_EXPIRY_SCAN_SECONDS`).
- **Full wipe schedule:** edit `textpads-weekly-cleanup.timer` (defaults to every 30 days).

After changing systemd unit files:

```bash
sudo systemctl daemon-reload
sudo systemctl restart pad.service
sudo systemctl restart textpads-weekly-cleanup.timer
```

## Stack

- **Backend:** Python 3 + `websockets`
- **Frontend:** vanilla HTML/CSS/JS
- **Proxy:** `nginx` with TLS

## Deploy

1. Edit `pad-nginx.conf` and `pad.service` for your real domain and service user.
2. Review `deploy.sh` and `update.sh` before using them in production.
3. Run `bash deploy.sh` for first install.
4. Run `bash update.sh` for updates.

Note:

- The service should run under a dedicated low-privilege user, not a general login account.
- Only ports `80` and `443` should be exposed for the app. The Python backend should stay bound to `127.0.0.1`.

## Manual Cleanup

The repository includes a simple shell script for deleting all pads:

```bash
bash cleanup-pads.sh
```
