"""netWatch shared constants, config I/O, and password hashing.

Split out so scanner.py/notify.py/web.py/netwatch.py can all depend on this
without any of them importing each other and creating a cycle.
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
IS_WIN = os.name == "nt"


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"No config found. Copy config.example.json to {CONFIG_PATH} and edit it.")
    return json.loads(CONFIG_PATH.read_text())


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000)
    return f"{salt}${h.hex()}"


def check_password(pw, stored):
    try:
        salt, h = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000)
        return hmac.compare_digest(got.hex(), h)
    except Exception:
        return False
