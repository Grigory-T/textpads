#!/usr/bin/env python3
"""Small HTTP API for persistent collaborative text pads."""

import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


DATA_DIR = Path(os.environ.get("PAD_DATA_DIR", "/opt/pad/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
STATIC_DIR = Path(os.environ.get("PAD_STATIC_DIR", Path(__file__).parent / "static"))

MAX_BODY_SIZE = 3_000_000
MAX_TEXT_SIZE = 2_800_000
AUTH_FAILURE_WINDOW = 300
MAX_AUTH_FAILURES_IP = 10
DEFAULT_EXPIRY_SECONDS = 7 * 24 * 60 * 60
PAD_EXPIRY_SECONDS = DEFAULT_EXPIRY_SECONDS
ALLOWED_ORIGINS = set()

pad_locks = defaultdict(threading.Lock)
auth_lock = threading.Lock()
auth_failures = defaultdict(list)


def int_env(name, default):
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default


def is_valid_pad_name(name):
    return (
        bool(name)
        and 3 <= len(name) <= 64
        and all(char.isalnum() or char == "-" for char in name)
        and not name.startswith("-")
        and not name.endswith("-")
    )


def is_valid_hex(value, size):
    return (
        isinstance(value, str)
        and len(value) == size * 2
        and all(char in "0123456789abcdef" for char in value)
    )


def meta_path(name):
    return DATA_DIR / f"{name}.meta.json"


def text_path(name):
    return DATA_DIR / f"{name}.txt"


def atomic_write(path, content):
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def load_meta(name):
    try:
        raw = json.loads(meta_path(name).read_text(encoding="utf-8"))
        encrypted = bool(raw.get("encrypted", False))
        auth_salt = raw.get("auth_salt", raw.get("salt", ""))
        auth_hash = raw.get("auth_hash", raw.get("pw_hash", ""))
        enc_salt = raw.get("enc_salt", raw.get("salt", ""))
        if encrypted and not (
            is_valid_hex(auth_salt, 16)
            and is_valid_hex(auth_hash, 32)
            and is_valid_hex(enc_salt, 16)
        ):
            return None
        return {
            "encrypted": encrypted,
            "auth_salt": auth_salt if encrypted else "",
            "auth_hash": auth_hash if encrypted else "",
            "enc_salt": enc_salt if encrypted else "",
            "version": max(0, int(raw.get("version", 0))),
            "last_access": float(raw.get("last_access", time.time())),
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def save_meta(name, meta):
    atomic_write(meta_path(name), json.dumps(meta, separators=(",", ":")))


def load_text(name):
    try:
        return text_path(name).read_text(encoding="utf-8")
    except OSError:
        return ""


def delete_pad(name):
    meta_path(name).unlink(missing_ok=True)
    text_path(name).unlink(missing_ok=True)


def expired(meta, now=None):
    return (now or time.time()) - meta["last_access"] >= PAD_EXPIRY_SECONDS


def purge_expired():
    now = time.time()
    for path in DATA_DIR.glob("*.meta.json"):
        name = path.name[:-10]
        with pad_locks[name]:
            meta = load_meta(name)
            if meta is None or expired(meta, now):
                delete_pad(name)


def auth_is_limited(ip):
    now = time.time()
    with auth_lock:
        auth_failures[ip] = [
            stamp for stamp in auth_failures[ip] if now - stamp < AUTH_FAILURE_WINDOW
        ]
        return len(auth_failures[ip]) >= MAX_AUTH_FAILURES_IP


def record_auth_failure(ip):
    with auth_lock:
        auth_failures[ip].append(time.time())


class PadHandler(BaseHTTPRequestHandler):
    server_version = "Textpads/1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def send_static(self, path, content_type, head_only=False):
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def serve_page(self, head_only=False):
        path = urlparse(self.path).path
        if path == "/":
            self.send_static(STATIC_DIR / "index.html", "text/html; charset=utf-8", head_only)
        elif path == "/robots.txt":
            self.send_static(STATIC_DIR / "robots.txt", "text/plain; charset=utf-8", head_only)
        elif path == "/static/style.css":
            self.send_static(STATIC_DIR / "style.css", "text/css; charset=utf-8", head_only)
        elif path == "/favicon.ico":
            self.send_error(404)
        else:
            self.send_static(STATIC_DIR / "pad.html", "text/html; charset=utf-8", head_only)

    def do_HEAD(self):
        if urlparse(self.path).path.startswith("/api/"):
            self.send_json(405, {"error": "method not allowed"})
            return
        self.serve_page(head_only=True)

    def client_ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def pad_request(self):
        parsed = urlparse(self.path)
        prefix = "/api/pads/"
        if not parsed.path.startswith(prefix):
            return None, None, None
        remainder = unquote(parsed.path[len(prefix) :])
        if remainder.endswith("/meta"):
            name = remainder[:-5]
            action = "meta"
        else:
            name = remainder
            action = "document"
        if not is_valid_pad_name(name):
            return None, None, None
        return name, action, parse_qs(parsed.query)

    def authenticated(self, meta):
        if not meta["encrypted"]:
            return True
        provided = self.headers.get("X-Pad-Auth", "")
        return is_valid_hex(provided, 32) and hmac.compare_digest(
            provided, meta["auth_hash"]
        )

    def do_GET(self):
        name, action, query = self.pad_request()
        if name is None:
            self.serve_page()
            return

        with pad_locks[name]:
            meta = load_meta(name)
            if meta is not None and expired(meta):
                delete_pad(name)
                meta = None

            if action == "meta":
                payload = {"exists": meta is not None, "encrypted": False}
                if meta is not None:
                    payload["encrypted"] = meta["encrypted"]
                    if meta["encrypted"]:
                        payload["auth_salt"] = meta["auth_salt"]
                        payload["enc_salt"] = meta["enc_salt"]
                self.send_json(200, payload)
                return

            if meta is None:
                self.send_json(404, {"error": "pad not found"})
                return
            ip = self.client_ip()
            if auth_is_limited(ip) or not self.authenticated(meta):
                record_auth_failure(ip)
                self.send_json(403, {"error": "authentication failed"})
                return

            try:
                since = int(query.get("since", ["-1"])[0])
            except ValueError:
                since = -1
            if since == meta["version"]:
                self.send_json(204)
                return

            now = time.time()
            if now - meta["last_access"] >= 60:
                meta["last_access"] = now
                save_meta(name, meta)
            self.send_json(
                200, {"text": load_text(name), "version": meta["version"]}
            )

    def do_PUT(self):
        name, action, _query = self.pad_request()
        if name is None or action != "document":
            self.send_json(404, {"error": "not found"})
            return
        origin = self.headers.get("Origin", "")
        if ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
            self.send_json(403, {"error": "origin denied"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_SIZE:
            self.send_json(413, {"error": "invalid body size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid JSON"})
            return

        text = payload.get("text", "")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_SIZE:
            self.send_json(413, {"error": "text too large"})
            return

        with pad_locks[name]:
            meta = load_meta(name)
            if meta is not None and expired(meta):
                delete_pad(name)
                meta = None

            if meta is None:
                if not payload.get("create"):
                    self.send_json(404, {"error": "pad not found"})
                    return
                encrypted = bool(payload.get("encrypted", False))
                auth_salt = payload.get("auth_salt", "")
                auth_hash = payload.get("auth_hash", "")
                enc_salt = payload.get("enc_salt", "")
                if encrypted and not (
                    is_valid_hex(auth_salt, 16)
                    and is_valid_hex(auth_hash, 32)
                    and is_valid_hex(enc_salt, 16)
                ):
                    self.send_json(400, {"error": "invalid encryption metadata"})
                    return
                meta = {
                    "encrypted": encrypted,
                    "auth_salt": auth_salt if encrypted else "",
                    "auth_hash": auth_hash if encrypted else "",
                    "enc_salt": enc_salt if encrypted else "",
                    "version": 0,
                    "last_access": time.time(),
                }
            else:
                ip = self.client_ip()
                if auth_is_limited(ip) or not self.authenticated(meta):
                    record_auth_failure(ip)
                    self.send_json(403, {"error": "authentication failed"})
                    return

            try:
                base_version = int(payload.get("version", -1))
            except (TypeError, ValueError):
                base_version = -1
            if base_version != meta["version"]:
                self.send_json(
                    409,
                    {
                        "text": load_text(name),
                        "version": meta["version"],
                    },
                )
                return

            meta["version"] += 1
            meta["last_access"] = time.time()
            atomic_write(text_path(name), text)
            save_meta(name, meta)
            self.send_json(200, {"version": meta["version"]})


def cleanup_loop():
    while True:
        time.sleep(15 * 60)
        purge_expired()


def main():
    global PAD_EXPIRY_SECONDS, ALLOWED_ORIGINS
    days = int_env("PAD_EXPIRY_DAYS", 7)
    seconds = int_env("PAD_EXPIRY_SECONDS", 0)
    PAD_EXPIRY_SECONDS = seconds if seconds > 0 else days * 24 * 60 * 60
    ALLOWED_ORIGINS = {
        value.strip()
        for value in os.environ.get("PAD_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    }
    purge_expired()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    host = os.environ.get("PAD_HOST", "127.0.0.1")
    port = int_env("PAD_PORT", 8765)
    server = ThreadingHTTPServer((host, port), PadHandler)
    server.daemon_threads = True
    print(f"Textpads HTTP API listening on {host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
