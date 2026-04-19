#!/usr/bin/env python3
"""Minimal collaborative text pad - WebSocket server with password protection."""

import asyncio
import hmac
import json
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path

import websockets

DATA_DIR = Path(os.environ.get("PAD_DATA_DIR", "/opt/pad/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

# In-memory state: pad_name -> auth+content metadata and connected clients.
pads = {}

MAX_TEXT_SIZE = 2_000_000
MAX_PADS_IN_MEMORY = 200
AUTH_TIMEOUT = 10
DEFAULT_PAD_EXPIRY_DAYS = 7
DEFAULT_PAD_EXPIRY_SECONDS = DEFAULT_PAD_EXPIRY_DAYS * 24 * 60 * 60
PAD_EXPIRY_SECONDS = DEFAULT_PAD_EXPIRY_SECONDS

DEFAULT_EXPIRY_SCAN_SECONDS = 15 * 60
EXPIRY_SCAN_INTERVAL = DEFAULT_EXPIRY_SCAN_SECONDS
# Rate limiting
auth_failures_by_ip = defaultdict(list)  # ip -> [timestamps]
auth_failures_by_pad = defaultdict(list)  # pad_name -> [timestamps]
MAX_AUTH_FAILURES_IP = 10  # per IP per window
MAX_AUTH_FAILURES_PAD = 20  # per pad per window
AUTH_FAILURE_WINDOW = 300  # 5 minutes

# Connection limits
MAX_CONNECTIONS_PER_IP = 10
MAX_TOTAL_CONNECTIONS = 500
ip_connections = defaultdict(int)  # ip -> count
total_connections = 0

# Per-connection message rate limiting
MAX_MESSAGES_PER_SECOND = 5

ALLOWED_ORIGINS = None  # set from env


def _get_int_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_days_or_seconds(days_env, seconds_env, default_seconds):
    seconds = _get_int_env(seconds_env, 0)
    if seconds > 0:
        return seconds
    days = _get_int_env(days_env, 0)
    if days > 0:
        return days * 24 * 60 * 60
    return default_seconds


def _get_minutes_or_seconds(minutes_env, seconds_env, default_seconds):
    seconds = _get_int_env(seconds_env, 0)
    if seconds > 0:
        return seconds
    minutes = _get_int_env(minutes_env, 0)
    if minutes > 0:
        return minutes * 60
    return default_seconds


def is_valid_pad_name(name):
    return (
        bool(name)
        and 3 <= len(name) <= 64
        and all(c.isalnum() or c == "-" for c in name)
        and not name.startswith("-")
        and not name.endswith("-")
    )


def load_pad_meta(name):
    path = DATA_DIR / f"{name}.meta.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_pad_meta(name, meta):
    if not is_valid_pad_name(name):
        return
    path = DATA_DIR / f"{name}.meta.json"
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(json.dumps(meta), encoding="utf-8")
        tmp_path.rename(path)
    except Exception as e:
        print(f"Error saving meta {name}: {e}")
        tmp_path.unlink(missing_ok=True)


def delete_pad_files(name):
    for suffix in (".meta.json", ".txt"):
        try:
            (DATA_DIR / f"{name}{suffix}").unlink(missing_ok=True)
        except Exception as e:
            print(f"Error deleting {name}{suffix}: {e}")


def load_pad_content(name):
    path = DATA_DIR / f"{name}.txt"
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


def save_pad_content(name, text):
    if not is_valid_pad_name(name):
        return
    path = DATA_DIR / f"{name}.txt"
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(text, encoding="utf-8")
        tmp_path.rename(path)
    except Exception as e:
        print(f"Error saving pad {name}: {e}")
        tmp_path.unlink(missing_ok=True)


def cleanup_memory():
    if len(pads) <= MAX_PADS_IN_MEMORY:
        return
    now = time.time()
    inactive = [
        name
        for name, pad in pads.items()
        if not pad["clients"] and now - pad["last_modified"] > 300
    ]
    for name in inactive:
        del pads[name]


def check_auth_rate_limit(ip, pad_name):
    """Returns True if rate-limited (by IP or by pad)."""
    now = time.time()
    # Per-IP check
    auth_failures_by_ip[ip] = [
        t for t in auth_failures_by_ip[ip] if now - t < AUTH_FAILURE_WINDOW
    ]
    if len(auth_failures_by_ip[ip]) >= MAX_AUTH_FAILURES_IP:
        return True
    # Per-pad check
    auth_failures_by_pad[pad_name] = [
        t for t in auth_failures_by_pad[pad_name] if now - t < AUTH_FAILURE_WINDOW
    ]
    if len(auth_failures_by_pad[pad_name]) >= MAX_AUTH_FAILURES_PAD:
        return True
    return False


def record_auth_failure(ip, pad_name):
    now = time.time()
    auth_failures_by_ip[ip].append(now)
    auth_failures_by_pad[pad_name].append(now)


def get_client_ip(websocket):
    """Get client IP, preferring X-Real-IP from nginx."""
    if hasattr(websocket, "request") and websocket.request:
        headers = websocket.request.headers
        real_ip = headers.get("X-Real-IP")
        if real_ip:
            return real_ip
    try:
        return websocket.remote_address[0]
    except (AttributeError, TypeError, IndexError):
        return "unknown"


def check_origin(websocket):
    """Validate WebSocket Origin header."""
    if not ALLOWED_ORIGINS:
        return True
    if hasattr(websocket, "request") and websocket.request:
        origin = websocket.request.headers.get("Origin", "")
        return origin in ALLOWED_ORIGINS
    return True


def is_valid_hex(value, length_bytes):
    return (
        isinstance(value, str)
        and len(value) == length_bytes * 2
        and all(c in "0123456789abcdef" for c in value)
    )


def normalize_meta(meta):
    encrypted = bool(meta.get("encrypted", False))
    auth_salt = meta.get("auth_salt", meta.get("salt", ""))
    auth_hash = meta.get("auth_hash", meta.get("pw_hash", ""))
    enc_salt = meta.get("enc_salt", meta.get("salt", ""))
    last_access = meta.get("last_access", time.time())

    if encrypted:
        if not (
            is_valid_hex(auth_salt, 16)
            and is_valid_hex(enc_salt, 16)
            and is_valid_hex(auth_hash, 32)
        ):
            return None
    else:
        auth_salt = ""
        auth_hash = ""
        enc_salt = ""

    return {
        "auth_salt": auth_salt,
        "auth_hash": auth_hash,
        "enc_salt": enc_salt,
        "encrypted": encrypted,
        "last_access": float(last_access),
    }


def is_pad_expired(meta, now=None):
    if now is None:
        now = time.time()
    return now - float(meta.get("last_access", now)) >= PAD_EXPIRY_SECONDS


def touch_pad(name, pad, now=None):
    if now is None:
        now = time.time()
    pad["last_access"] = now
    save_pad_meta(
        name,
        {
            "auth_salt": pad["auth_salt"],
            "auth_hash": pad["auth_hash"],
            "enc_salt": pad["enc_salt"],
            "encrypted": pad["encrypted"],
            "last_access": now,
        },
    )


def purge_expired_pads(now=None):
    if now is None:
        now = time.time()

    for meta_path in DATA_DIR.glob("*.meta.json"):
        name = meta_path.name[:-10]
        meta = load_pad_meta(name)
        if meta is None:
            continue
        meta = normalize_meta(meta)
        if meta is None:
            delete_pad_files(name)
            pads.pop(name, None)
            continue
        if is_pad_expired(meta, now=now):
            delete_pad_files(name)
            pads.pop(name, None)


async def expiry_cleanup_loop():
    while True:
        await asyncio.sleep(EXPIRY_SCAN_INTERVAL)
        purge_expired_pads()


async def broadcast(pad, message, exclude=None):
    targets = [c for c in pad["clients"] if c != exclude]
    if targets:
        await asyncio.gather(
            *[c.send(message) for c in targets], return_exceptions=True
        )


async def broadcast_client_count(pad):
    msg = json.dumps({"type": "clients", "count": len(pad["clients"])})
    await broadcast(pad, msg)


async def handler(websocket):
    global total_connections

    # Validate origin
    if not check_origin(websocket):
        await websocket.close(1008, "Origin not allowed")
        return

    ws_path = (
        websocket.request.path if hasattr(websocket, "request") else websocket.path
    )
    parts = ws_path.strip("/").split("/")

    if len(parts) != 2 or parts[0] != "ws":
        await websocket.close(1008, "Invalid path")
        return

    pad_name = parts[1]
    if not is_valid_pad_name(pad_name):
        await websocket.close(1008, "Invalid pad name")
        return

    client_ip = get_client_ip(websocket)

    # Connection limits
    if total_connections >= MAX_TOTAL_CONNECTIONS:
        await websocket.close(1013, "Server full")
        return
    if ip_connections[client_ip] >= MAX_CONNECTIONS_PER_IP:
        await websocket.close(1008, "Too many connections")
        return

    # Count connection immediately (covers auth phase too)
    total_connections += 1
    ip_connections[client_ip] += 1
    pad = None

    try:
        # Check auth rate limit
        if check_auth_rate_limit(client_ip, pad_name):
            await websocket.send(json.dumps({"type": "auth_fail"}))
            await websocket.close(1008, "Rate limited")
            return

        # --- Authentication phase ---
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=AUTH_TIMEOUT)
            start_msg = json.loads(raw)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            record_auth_failure(client_ip, pad_name)
            await websocket.close(1008, "Auth timeout")
            return

        if start_msg.get("type") != "start":
            record_auth_failure(client_ip, pad_name)
            await websocket.close(1008, "Start required")
            return

        wants_create = bool(start_msg.get("create", False))

        # Load or initialize pad
        if pad_name not in pads:
            cleanup_memory()
            meta = load_pad_meta(pad_name)

            if meta is not None:
                meta = normalize_meta(meta)
                if meta is None:
                    await websocket.close(1011, "Invalid pad metadata")
                    return
                if is_pad_expired(meta):
                    delete_pad_files(pad_name)
                    meta = None

                if meta is not None:
                    pads[pad_name] = {
                        "text": load_pad_content(pad_name),
                        "clients": set(),
                        "last_modified": time.time(),
                        "version": 0,
                        "auth_salt": meta["auth_salt"],
                        "auth_hash": meta["auth_hash"],
                        "enc_salt": meta["enc_salt"],
                        "encrypted": meta["encrypted"],
                        "last_access": meta["last_access"],
                    }

        pad_exists = pad_name in pads
        pad = pads.get(pad_name)

        if not pad_exists and not wants_create:
            record_auth_failure(client_ip, pad_name)
            await asyncio.sleep(1)
            await websocket.send(json.dumps({"type": "auth_fail"}))
            await websocket.close(1008, "Auth failed")
            return

        if pad_exists and not pad["encrypted"]:
            await websocket.send(
                json.dumps({"type": "auth_ok", "encrypted": False, "enc_salt": ""})
            )
        else:
            challenge = {
                "type": "auth_challenge",
                "exists": pad_exists,
                "encrypted": pad["encrypted"] if pad_exists else False,
            }
            if pad_exists and pad["encrypted"]:
                challenge["auth_salt"] = pad["auth_salt"]
                challenge["enc_salt"] = pad["enc_salt"]
            await websocket.send(json.dumps(challenge))

            try:
                raw = await asyncio.wait_for(websocket.recv(), timeout=AUTH_TIMEOUT)
                auth_msg = json.loads(raw)
            except (asyncio.TimeoutError, json.JSONDecodeError):
                record_auth_failure(client_ip, pad_name)
                await websocket.close(1008, "Auth timeout")
                return

            if auth_msg.get("type") != "auth":
                record_auth_failure(client_ip, pad_name)
                await websocket.close(1008, "Auth required")
                return

            if pad_exists:
                if pad["encrypted"]:
                    provided_hash = auth_msg.get("auth_hash", "")
                    if not (
                        is_valid_hex(provided_hash, 32)
                        and hmac.compare_digest(provided_hash, pad["auth_hash"])
                    ):
                        record_auth_failure(client_ip, pad_name)
                        await asyncio.sleep(1)
                        await websocket.send(json.dumps({"type": "auth_fail"}))
                        await websocket.close(1008, "Auth failed")
                        return

                await websocket.send(
                    json.dumps(
                        {
                            "type": "auth_ok",
                            "encrypted": pad["encrypted"],
                            "enc_salt": pad["enc_salt"],
                        }
                    )
                )
            else:
                encrypted = bool(auth_msg.get("encrypted", False))
                auth_salt = auth_msg.get("auth_salt", "")
                auth_hash = auth_msg.get("auth_hash", "")
                enc_salt = auth_msg.get("enc_salt", "")

                if encrypted and not (
                    is_valid_hex(auth_salt, 16)
                    and is_valid_hex(enc_salt, 16)
                    and is_valid_hex(auth_hash, 32)
                ):
                    record_auth_failure(client_ip, pad_name)
                    await websocket.close(1008, "Invalid auth setup")
                    return

                meta = {
                    "auth_salt": auth_salt if encrypted else "",
                    "auth_hash": auth_hash if encrypted else "",
                    "enc_salt": enc_salt if encrypted else "",
                    "encrypted": encrypted,
                }
                save_pad_meta(pad_name, meta)

                pads[pad_name] = {
                    "text": "",
                    "clients": set(),
                    "last_modified": time.time(),
                    "version": 0,
                    "auth_salt": meta["auth_salt"],
                    "auth_hash": meta["auth_hash"],
                    "enc_salt": meta["enc_salt"],
                    "encrypted": encrypted,
                    "last_access": time.time(),
                }
                pad = pads[pad_name]
                touch_pad(pad_name, pad)

                await websocket.send(
                    json.dumps(
                        {
                            "type": "auth_ok",
                            "encrypted": encrypted,
                            "enc_salt": pad["enc_salt"],
                        }
                    )
                )

        # --- Normal operation ---
        pad = pads[pad_name]
        touch_pad(pad_name, pad)
        pad["clients"].add(websocket)
        message_count_window = 0
        window_start = time.time()

        await websocket.send(
            json.dumps(
                {
                    "type": "init",
                    "text": pad["text"],
                    "version": pad["version"],
                    "clients": len(pad["clients"]),
                }
            )
        )

        await broadcast_client_count(pad)

        async for message in websocket:
            now = time.time()
            if now - window_start > 1.0:
                message_count_window = 0
                window_start = now
            message_count_window += 1
            if message_count_window > MAX_MESSAGES_PER_SECOND:
                continue

            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                continue

            if data.get("type") == "update":
                text = data.get("text", "")
                base_version = data.get("version")

                if len(text) > MAX_TEXT_SIZE:
                    await websocket.send(
                        json.dumps(
                            {"type": "error", "message": "Text too large"}
                        )
                    )
                    continue

                if not isinstance(base_version, int):
                    await websocket.send(
                        json.dumps({"type": "error", "message": "Missing version"})
                    )
                    continue

                if base_version != pad["version"]:
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "conflict",
                                "text": pad["text"],
                                "version": pad["version"],
                            }
                        )
                    )
                    continue

                pad["text"] = text
                pad["version"] += 1
                pad["last_modified"] = time.time()
                touch_pad(pad_name, pad)
                save_pad_content(pad_name, text)

                await websocket.send(
                    json.dumps({"type": "ack", "version": pad["version"]})
                )

                msg = json.dumps(
                    {"type": "update", "text": text, "version": pad["version"]}
                )
                await broadcast(pad, msg, exclude=websocket)

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        total_connections -= 1
        ip_connections[client_ip] -= 1
        if ip_connections[client_ip] <= 0:
            del ip_connections[client_ip]
        if pad is not None:
            pad["clients"].discard(websocket)
            if pad["clients"]:
                await broadcast_client_count(pad)


async def main():
    global ALLOWED_ORIGINS
    global PAD_EXPIRY_SECONDS
    global EXPIRY_SCAN_INTERVAL
    host = os.environ.get("PAD_HOST", "127.0.0.1")
    port = int(os.environ.get("PAD_PORT", "8765"))
    origins_env = os.environ.get("PAD_ALLOWED_ORIGINS", "")
    if origins_env:
        ALLOWED_ORIGINS = set(origins_env.split(","))

    PAD_EXPIRY_SECONDS = _get_days_or_seconds(
        "PAD_EXPIRY_DAYS", "PAD_EXPIRY_SECONDS", DEFAULT_PAD_EXPIRY_SECONDS
    )
    EXPIRY_SCAN_INTERVAL = _get_minutes_or_seconds(
        "PAD_EXPIRY_SCAN_MINUTES",
        "PAD_EXPIRY_SCAN_SECONDS",
        DEFAULT_EXPIRY_SCAN_SECONDS,
    )

    purge_expired_pads()

    async with websockets.serve(
        handler,
        host,
        port,
        max_size=2_000_000,
        ping_interval=30,
        ping_timeout=10,
    ):
        asyncio.create_task(expiry_cleanup_loop())
        print(f"Pad server running on ws://{host}:{port}")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
