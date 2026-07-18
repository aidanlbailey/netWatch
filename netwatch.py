"""netWatch — LAN device join/leave tracker.

Single file: scanner thread + Flask dashboard + Discord/email notifier.
CLI: python netwatch.py [run | set-password | test-notify]
"""
import ctypes
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from pathlib import Path

__version__ = "1.0.0"

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
IS_WIN = os.name == "nt"

log = logging.getLogger("netwatch")

# ---------------------------------------------------------------- config

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

# ---------------------------------------------------------------- discovery

def detect_network(cfg):
    """Return (local_ip, ip_network). UDP-connect trick; no packet is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    if cfg.get("subnet"):
        net = ipaddress.ip_network(cfg["subnet"], strict=False)
    else:
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    if ipaddress.ip_address(local_ip) not in net:
        # default route is elsewhere (e.g. a VPN); find our address on the target subnet
        try:
            local_ip = next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                            if ipaddress.ip_address(ip) in net)
        except (StopIteration, OSError):
            pass
    return local_ip, net


def normalize_mac(mac):
    return mac.lower().replace("-", ":")


def parse_arp(text, require=()):
    """Extract (ip, mac) pairs from neighbor-table output, one entry per line.

    `require`: neighbor states a line must contain one of — stale cache entries
    linger for minutes after a device leaves, so unfiltered output would keep
    departed devices "online" forever.
    """
    pairs = []
    for line in text.splitlines():
        if require and not any(r in line for r in require):
            continue
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_m = re.search(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b", line)
        if ip_m and mac_m:
            pairs.append((ip_m.group(1), normalize_mac(mac_m.group(1))))
    return pairs


def own_mac():
    node = uuid.getnode()
    return ":".join(f"{(node >> s) & 0xFF:02x}" for s in range(40, -1, -8))


def read_arp_cache():
    """Linux: (ip, mac) pairs the kernel is actively verifying or has verified.

    STALE is excluded — it's what departed devices decay to. DELAY/PROBE are
    in-flight verification triggered by our pings; a departed device falls
    through to FAILED within a couple of sweeps.
    """
    try:
        out = subprocess.run(["ip", "-4", "neigh"], capture_output=True, text=True).stdout
        return parse_arp(out, require=("REACHABLE", "DELAY", "PROBE"))
    except OSError:  # no iproute2; /proc has no state, accept its stale-entry lag
        return parse_arp(Path("/proc/net/arp").read_text())


def _win_arp(ip):
    """Send a real ARP request via iphlpapi.SendARP. Returns MAC or None.

    Unlike reading the ARP cache, this asks the device directly, right now —
    no stale entries, no dependency on the device answering ICMP, no admin.
    """
    mac = (ctypes.c_ubyte * 6)()
    n = ctypes.c_ulong(6)
    dest = int.from_bytes(socket.inet_aton(ip), "little")
    if ctypes.windll.Iphlpapi.SendARP(dest, 0, mac, ctypes.byref(n)) == 0 and n.value == 6:
        return ":".join(f"{b:02x}" for b in mac)
    return None


def sweep(net, local_ip):
    """Probe every host in the subnet. Returns {mac: ip} for devices present now."""
    seen = {}
    hosts = [str(ip) for ip in net.hosts()]
    if IS_WIN:
        # ponytail: one thread per host; SendARP blocks ~3s on absent hosts, so a
        # /24 sweep is ~3-4s wall time. Chunk the pool if this ever grows past /23.
        with ThreadPoolExecutor(max_workers=len(hosts)) as ex:
            for ip, mac in zip(hosts, ex.map(_win_arp, hosts)):
                if mac and not int(mac[:2], 16) & 1:
                    seen[mac] = ip
    else:
        # ping forces the kernel to (re)verify each neighbor; replies are irrelevant
        procs = [subprocess.Popen(["ping", "-c", "1", "-W", "1", ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for ip in hosts]
        for p in procs:
            p.wait()
        for ip, mac in read_arp_cache():
            if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
                continue
            if ipaddress.ip_address(ip) in net:
                seen[mac] = ip
    if local_ip not in seen.values():  # this machine may not appear in its own neighbor table
        seen[own_mac()] = local_ip
    return seen

# ---------------------------------------------------------------- persistence + state

DB_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  mac        TEXT PRIMARY KEY,
  ip         TEXT,
  nickname   TEXT,
  vendor     TEXT,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  online     INTEGER NOT NULL DEFAULT 0,
  notify     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  mac  TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('join','leave')),
  ts   INTEGER NOT NULL
);
"""


def open_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:  # migrate DBs created before the notify column existed
        conn.execute("ALTER TABLE devices ADD COLUMN notify INTEGER NOT NULL DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    return conn


class Tracker:
    """Online/offline state machine. Devices keyed by MAC; DB is the source of truth."""

    def __init__(self, conn, offline_after_misses):
        self.conn = conn
        self.offline_after = offline_after_misses
        self.misses = {}  # mac -> consecutive sweeps unseen while online

    def process(self, seen, now):
        """Apply one sweep result. Returns [(kind, device_dict), ...] to notify."""
        events = []
        with DB_LOCK:
            known = {r["mac"]: dict(r) for r in self.conn.execute("SELECT * FROM devices")}
            for mac, ip in seen.items():
                self.misses.pop(mac, None)
                row = known.get(mac)
                if row is None:
                    self.conn.execute(
                        "INSERT INTO devices (mac, ip, first_seen, last_seen, online) VALUES (?,?,?,?,1)",
                        (mac, ip, now, now))
                    events.append(("join", {"mac": mac, "ip": ip, "nickname": None,
                                            "vendor": None, "new": True}))
                elif not row["online"]:
                    self.conn.execute(
                        "UPDATE devices SET ip=?, last_seen=?, online=1 WHERE mac=?", (ip, now, mac))
                    events.append(("join", row | {"ip": ip, "new": False}))
                else:
                    self.conn.execute(
                        "UPDATE devices SET ip=?, last_seen=? WHERE mac=?", (ip, now, mac))
            for mac, row in known.items():
                if row["online"] and mac not in seen:
                    n = self.misses.get(mac, 0) + 1
                    if n >= self.offline_after:
                        self.misses.pop(mac, None)
                        self.conn.execute("UPDATE devices SET online=0 WHERE mac=?", (mac,))
                        events.append(("leave", row))
                    else:
                        self.misses[mac] = n
            for kind, dev in events:
                self.conn.execute("INSERT INTO events (mac, kind, ts) VALUES (?,?,?)",
                                  (dev["mac"], kind, now))
            self.conn.commit()
        return events

# ---------------------------------------------------------------- vendor lookup

_vendor_attempted = set()


def lookup_vendors(conn):
    """Fill in vendor names via api.macvendors.com (free, ~1 req/s). Best-effort, no retries."""
    with DB_LOCK:
        macs = [r["mac"] for r in conn.execute("SELECT mac FROM devices WHERE vendor IS NULL")]
    for mac in [m for m in macs if m not in _vendor_attempted][:3]:  # a few per sweep, rate-limit friendly
        _vendor_attempted.add(mac)
        vendor = None
        try:
            with urllib.request.urlopen(f"https://api.macvendors.com/{mac}", timeout=3) as r:
                vendor = r.read().decode()[:100]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                vendor = ""  # unknown OUI (randomized MAC etc.) — don't ask again
        except Exception:
            pass  # network hiccup; retried after next restart
        if vendor is not None:
            with DB_LOCK:
                conn.execute("UPDATE devices SET vendor=? WHERE mac=?", (vendor, mac))
                conn.commit()
        time.sleep(1)

# ---------------------------------------------------------------- notifications

def device_name(dev):
    return dev.get("nickname") or dev.get("vendor") or dev["mac"]


def notify(cfg, kind, dev):
    """Send to each configured channel. Returns [(channel, error_or_None), ...]."""
    # ponytail: fire-and-forget per channel; add one retry if webhooks ever flake
    tag = "New device" if dev.get("new") else kind.capitalize()
    msg = f"{tag}: {device_name(dev)} ({dev.get('ip')}, {dev['mac']})"
    results = []

    d = cfg["discord"]
    if d["webhook_url"]:
        try:
            mention = f"<@{d['mention_user_id']}> " if d["mention_user_id"] else ""
            req = urllib.request.Request(
                d["webhook_url"],
                json.dumps({"content": mention + msg}).encode(),
                {"Content-Type": "application/json", "User-Agent": "netwatch"})
            urllib.request.urlopen(req, timeout=5).close()
            results.append(("Discord", None))
        except Exception as e:
            log.warning("discord notify failed: %s", e)
            results.append(("Discord", str(e)))

    s = cfg["smtp"]
    if s["host"]:
        try:
            em = EmailMessage()
            em["Subject"] = f"[netWatch] {tag}: {device_name(dev)}"
            em["From"] = s["from_addr"]
            em["To"] = s["to_addr"]
            em.set_content(msg)
            if s["port"] == 465:
                srv = smtplib.SMTP_SSL(s["host"], s["port"], timeout=10)
            else:
                srv = smtplib.SMTP(s["host"], s["port"], timeout=10)
                srv.starttls()
            with srv:
                if s["username"]:
                    srv.login(s["username"], s["password"])
                srv.send_message(em)
            results.append(("email", None))
        except Exception as e:
            log.warning("email notify failed: %s", e)
            results.append(("email", str(e)))
    return results

# ---------------------------------------------------------------- scanner thread

def scanner_loop(cfg, tracker, net, local_ip, baseline):
    """baseline=True means the DB started empty: suppress notifications for the
    first minute so every device already in the house isn't announced (slow
    devices can take a few sweeps to answer their first ping)."""
    log.info("scanning %s every %ss", net, cfg["scan_interval_sec"])
    baseline_until = time.time() + 60 if baseline else 0
    cfg_mtime = CONFIG_PATH.stat().st_mtime
    while True:
        start = time.time()
        try:
            try:  # hot-reload config.json edits (bind/port/password still need a restart)
                m = CONFIG_PATH.stat().st_mtime
                if m != cfg_mtime:
                    cfg_mtime = m
                    cfg.update(load_config())
                    tracker.offline_after = cfg["offline_after_misses"]
                    local_ip, net = detect_network(cfg)
                    log.info("config reloaded: %s every %ss, offline after %d misses",
                             net, cfg["scan_interval_sec"], cfg["offline_after_misses"])
            except (OSError, ValueError) as e:  # mid-save or invalid JSON; keep current config
                log.warning("config reload skipped: %s", e)
            seen = sweep(net, local_ip)
            events = tracker.process(seen, int(time.time()))
            quiet = time.time() < baseline_until
            for kind, dev in events:
                log.info("%s %s (%s)%s", kind.upper(), device_name(dev), dev.get("ip"),
                         " [baseline, not notified]" if quiet else "")
                if not quiet and dev.get("notify", 1):
                    notify(cfg, kind, dev)
            lookup_vendors(tracker.conn)
        except Exception:
            log.exception("sweep failed")
        time.sleep(max(0, cfg["scan_interval_sec"] - (time.time() - start)))

# ---------------------------------------------------------------- web

LOGIN_HTML = """<!doctype html><title>netWatch login</title>
<style>body{{font-family:system-ui,sans-serif;max-width:20rem;margin:4rem auto;padding:0 1rem}}
input,button{{font:inherit;padding:.4rem;display:block;margin:.5rem 0}}.err{{color:#b00}}</style>
<h1>netWatch</h1><p class="err">{err}</p>
<form method="post">
<label>Password <input type="password" name="password" autofocus></label>
<button>Log in</button></form>"""


def create_app(cfg, conn, tracker):
    from flask import Flask, request, session, redirect, send_file, jsonify

    app = Flask("netwatch")
    app.secret_key = cfg["secret_key"]
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=30 * 86400)
    fails = {}  # ip -> [count, locked_until]  # ponytail: in-memory, resets on restart

    def authed():
        return session.get("ok") is True

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/login")
    def login_form():
        return LOGIN_HTML.format(err="")

    @app.post("/login")
    def login():
        ip = request.remote_addr
        count, locked_until = fails.get(ip, [0, 0])
        if time.time() < locked_until:
            return LOGIN_HTML.format(err="too many attempts — try again later"), 429
        if check_password(request.form.get("password", ""), cfg["password_hash"]):
            fails.pop(ip, None)
            session.permanent = True
            session["ok"] = True
            return redirect("/")
        count += 1
        fails[ip] = [count, time.time() + 900 if count >= 5 else 0]
        log.warning("failed login from %s (%d)", ip, count)
        return LOGIN_HTML.format(err="wrong password"), 401

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    @app.get("/")
    def index():
        if not authed():
            return redirect("/login")
        return send_file(BASE / "dashboard.html")

    @app.post("/api/test-notify")
    def api_test_notify():
        if not authed():
            return jsonify(error="unauthorized"), 401
        if not request.is_json:
            return jsonify(error="json required"), 400
        results = notify(cfg, "join", {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.1",
                                       "nickname": "test device", "vendor": None})
        return jsonify(results=[{"channel": c, "error": e} for c, e in results])

    @app.get("/api/devices")
    def api_devices():
        if not authed():
            return jsonify(error="unauthorized"), 401
        with DB_LOCK:
            devices = [dict(r) for r in conn.execute(
                "SELECT * FROM devices ORDER BY online DESC, last_seen DESC")]
            events = [dict(r) for r in conn.execute(
                "SELECT e.kind, e.ts, e.mac, d.nickname, d.vendor FROM events e "
                "LEFT JOIN devices d USING(mac) ORDER BY e.id DESC LIMIT 50")]
        return jsonify(devices=devices, events=events, now=int(time.time()),
                       offline_after_misses=tracker.offline_after,
                       scan_interval_sec=cfg["scan_interval_sec"])

    @app.post("/api/nickname")
    def api_nickname():
        if not authed():
            return jsonify(error="unauthorized"), 401
        if not request.is_json:  # cheap CSRF guard: cross-site forms can't send JSON
            return jsonify(error="json required"), 400
        body = request.get_json()
        nickname = (body.get("nickname") or "").strip()[:64] or None
        with DB_LOCK:
            conn.execute("UPDATE devices SET nickname=? WHERE mac=?", (nickname, body.get("mac")))
            conn.commit()
        return jsonify(ok=True)

    @app.post("/api/settings")
    def api_settings():
        if not authed():
            return jsonify(error="unauthorized"), 401
        if not request.is_json:
            return jsonify(error="json required"), 400
        try:
            misses = max(1, min(120, int(request.get_json().get("offline_after_misses"))))
        except (TypeError, ValueError):
            return jsonify(error="offline_after_misses must be an integer"), 400
        tracker.offline_after = misses
        cfg["offline_after_misses"] = misses
        save_config(cfg)
        log.info("offline_after_misses set to %d via dashboard", misses)
        return jsonify(ok=True)

    @app.post("/api/notify")
    def api_notify():
        if not authed():
            return jsonify(error="unauthorized"), 401
        if not request.is_json:
            return jsonify(error="json required"), 400
        body = request.get_json()
        val = 1 if body.get("notify") else 0
        with DB_LOCK:
            if body.get("mac") == "*":
                conn.execute("UPDATE devices SET notify=?", (val,))
            else:
                conn.execute("UPDATE devices SET notify=? WHERE mac=?", (val, body.get("mac")))
            conn.commit()
        return jsonify(ok=True)

    return app

# ---------------------------------------------------------------- CLI / main

def setup_logging():
    handlers = [logging.StreamHandler()]
    if IS_WIN:  # Scheduled Tasks swallow stdout; keep a file too
        handlers.append(RotatingFileHandler(BASE / "netwatch.log", maxBytes=1_000_000, backupCount=2))
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")


def check_config(cfg):
    uid = cfg["discord"]["mention_user_id"]
    if uid and not uid.isdigit():
        log.warning("discord.mention_user_id %r is not numeric; mentions won't ping. "
                    "Use your Discord user ID (Settings > Advanced > Developer Mode, "
                    "right-click yourself > Copy User ID)", uid)


def run(cfg):
    setup_logging()
    check_config(cfg)
    if not cfg["password_hash"]:
        sys.exit("No dashboard password set. Run: python netwatch.py set-password")
    if not cfg["secret_key"]:
        cfg["secret_key"] = secrets.token_hex(32)
        save_config(cfg)

    conn = open_db(BASE / cfg["db_path"])
    baseline = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    tracker = Tracker(conn, cfg["offline_after_misses"])
    local_ip, net = detect_network(cfg)

    threading.Thread(target=scanner_loop, args=(cfg, tracker, net, local_ip, baseline),
                     daemon=True).start()

    from waitress import serve
    log.info("dashboard on http://%s:%s (LAN only - do not port-forward)", local_ip, cfg["bind_port"])
    serve(create_app(cfg, conn, tracker), host=cfg["bind_host"], port=cfg["bind_port"], threads=4)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    cfg = load_config()
    if cmd == "set-password":
        import getpass
        pw = getpass.getpass("New dashboard password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("Passwords don't match.")
        cfg["password_hash"] = hash_password(pw)
        save_config(cfg)
        print("Password saved.")
    elif cmd == "test-notify":
        setup_logging()
        check_config(cfg)
        dev = {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.1", "nickname": "test device", "vendor": None}
        results = notify(cfg, "join", dev)
        if not results:
            print("No channels configured (set discord.webhook_url or smtp.host).")
        for channel, err in results:
            print(f"{channel}: {'FAILED - ' + err if err else 'sent'}")
    elif cmd == "run":
        run(cfg)
    else:
        sys.exit(f"Unknown command: {cmd}. Use run | set-password | test-notify")


if __name__ == "__main__":
    main()
