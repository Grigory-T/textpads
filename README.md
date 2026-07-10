# Textpads

Minimal collaborative plain-text editor deployed at <https://keyconcept.site/>.

- Real-time sync via WebSocket
- AES-256-GCM encryption in the browser for protected pads
- Separate static auth hash for server-side access checks
- Open or password-protected pads
- Always-dark interface
- Logical line numbers with stable no-wrap editor behavior
- Automatic pad expiry and scheduled full cleanup
- One active editor with live read-only viewers
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
- After `300 ms` of typing inactivity, the client queues the full document over WebSocket.
- The first connected browser is the active editor. Other connected browsers are live read-only viewers.
- Only the editor can send updates, so competing full-document writes and merge conflicts cannot occur.
- Each browser keeps at most one save in flight and sends later editor changes after acknowledgement.
- The server stores each accepted document atomically, acknowledges it, and broadcasts it to viewers.
- If the editor disconnects, one connected viewer is promoted automatically.

Implications:

- This is full-document sync, not patch-based sync.
- There is no merge, OT, or CRDT logic.
- This deliberately avoids OT, CRDTs, client merges, and simultaneous writers.
- The toolbar shows whether the browser is the editor or a viewer and distinguishes `unsaved`, `saving`, `saved`, and disconnected states.

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
- **Full wipe schedule:** edit `textpads-full-cleanup.timer` (defaults to 30 days after activation, then every 30 days).

After changing systemd unit files:

```bash
sudo systemctl daemon-reload
sudo systemctl restart pad.service
sudo systemctl restart textpads-full-cleanup.timer
```

## Stack

- **Backend:** Python 3 + `websockets`
- **Frontend:** vanilla HTML/CSS/JS
- **Proxy:** `nginx` with TLS

## Deploy

This repository is the deployment source for `keyconcept.site`. Its nginx and
systemd files already contain that production domain.

1. Confirm DNS and the existing Let's Encrypt certificate for `keyconcept.site` and `www.keyconcept.site`.
2. Review the clean Git diff and run `bash deploy.sh` for first installation.
3. Run `bash update.sh` for later deployments.
4. Verify `pad.service`, nginx, HTTPS, WebSocket synchronization, and the cleanup timer.

Note:

- The service should run under a dedicated low-privilege user, not a general login account.
- Only ports `80` and `443` should be exposed for the app. The Python backend should stay bound to `127.0.0.1`.
- `deploy.sh` and `update.sh` replace the live nginx and systemd configuration with the tracked production files.
- The active cleanup unit is `textpads-full-cleanup.timer`. Both scripts remove the retired `textpads-weekly-cleanup.*` units and `textpads-delete-all.sh`.

## Production Layout

- Application checkout: a clean clone of this repository
- Runtime directory: `/opt/pad`
- Persistent data: `/opt/pad/data`
- Backend unit: `/etc/systemd/system/pad.service`
- Cleanup units: `/etc/systemd/system/textpads-full-cleanup.{service,timer}`
- Cleanup command: `/usr/local/bin/textpads-full-cleanup.sh`
- nginx site: `/etc/nginx/sites-available/pad`
- TLS lineage: `/etc/letsencrypt/live/keyconcept.site/`

`/opt/pad` is a copied runtime tree, not a Git checkout. GitHub `master` is the
source of truth; both machine checkouts should be clean and at that revision.

## Security Scope

- nginx terminates TLS, redirects HTTP and `www`, applies request limits, and sends restrictive browser security headers.
- The backend accepts only the configured browser origin and is not publicly exposed.
- Pad names are validated, message size and connection counts are bounded, and failed authentication is rate-limited.
- The systemd service uses a dedicated user and filesystem/kernel hardening.
- Protected-pad content is encrypted in the browser with AES-256-GCM and a PBKDF2-derived key.
- This provides reasonable protection for non-sensitive temporary notes, not protection from a malicious server or modified frontend JavaScript.

## Manual Cleanup

The repository includes a simple shell script for deleting all pads:

```bash
bash textpads-full-cleanup.sh
```
