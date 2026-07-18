"""netWatch — LAN device join/leave tracker.

Entry point: config/CLI glue over scanner.py (network + state), notify.py
(Discord/email), and web.py (Flask dashboard).
CLI: python netwatch.py [run | set-password | test-notify]
"""
import logging
import secrets
import sys
import threading
import time
from logging.handlers import RotatingFileHandler

from common import BASE, CONFIG_PATH, IS_WIN, load_config, save_config, hash_password, check_password
from notify import notify
from scanner import Tracker, detect_network, open_db, scanner_loop, sniffer_loop
from web import create_app

__version__ = "1.1.0"

log = logging.getLogger("netwatch")

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

    # Optional passive sniffer for instant (~1-3s) joins; degrades to sweep-only
    # if scapy/Npcap is unavailable. Shares the sweep's first-minute baseline
    # suppression so a fresh DB doesn't announce every existing device.
    sniffer_quiet_until = time.time() + 60 if baseline else 0

    def notify_cb(kind, dev):
        if time.time() >= sniffer_quiet_until:
            notify(cfg, kind, dev)

    threading.Thread(target=sniffer_loop, args=(cfg, tracker, net, notify_cb),
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
        results = notify(cfg, "join", dev, force=True)
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
