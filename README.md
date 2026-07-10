# Textpads

Minimal collaborative plain-text editor deployed at <https://keyconcept.site/>.

- Fast synchronization through short HTTP requests
- AES-256-GCM encryption in the browser for protected pads
- Separate static auth hash for server-side access checks
- Open or password-protected pads
- Always-dark interface
- Logical line numbers with stable no-wrap editor behavior
- Automatic pad expiry and scheduled full cleanup
- Every open browser can edit
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
- **Backend:** Python standard-library HTTP server
- **Proxy:** `nginx` terminates TLS and proxies `/api/` to `127.0.0.1:8765`
- **Storage:** one `*.txt` file per pad and one `*.meta.json` file per pad
- **Transport:** same-origin HTTPS requests

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
- After `250 ms` of typing inactivity, a browser saves the full document with a short HTTP `PUT`.
- Browsers check the stored revision every `500 ms`; unchanged checks return no document body.
- Every browser can edit. There are no persistent connections, reconnect states, locks, editor roles, or client counts.
- Each browser keeps at most one save request in flight and sends later changes after acknowledgement.
- The server serializes writes per pad and stores accepted text atomically.
- A save based on a stale revision is not applied. The browser keeps its local text and reports that another browser changed the pad.

Implications:

- This is full-document sync, not patch-based sync.
- There is no merge, OT, CRDT, persistent session, or distributed lock logic.
- Normal sequential editing propagates in about half a second. Truly simultaneous writes are detected instead of silently overwriting stored text.
- The toolbar distinguishes `unsaved`, `saving`, `saved`, stale revision, and offline retry states.

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

- **Backend:** Python 3 standard library
- **Frontend:** vanilla HTML/CSS/JS
- **Proxy:** `nginx` with TLS

## Deploy

This repository is the deployment source for `keyconcept.site`. Its nginx and
systemd files already contain that production domain.

1. Confirm DNS and the existing Let's Encrypt certificate for `keyconcept.site` and `www.keyconcept.site`.
2. Review the clean Git diff and run `bash deploy.sh` for first installation.
3. Run `bash update.sh` for later deployments.
4. Verify `pad.service`, nginx, HTTPS, two-browser save/poll synchronization, and the cleanup timer.

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
- Pad names and request sizes are bounded, writes require the expected revision and same origin, and failed authentication is rate-limited.
- The systemd service uses a dedicated user and filesystem/kernel hardening.
- Protected-pad content is encrypted in the browser with AES-256-GCM and a PBKDF2-derived key.
- This provides reasonable protection for non-sensitive temporary notes, not protection from a malicious server or modified frontend JavaScript.

## Manual Cleanup

The repository includes a simple shell script for deleting all pads:

```bash
bash textpads-full-cleanup.sh
```
