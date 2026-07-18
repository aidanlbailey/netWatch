"""Discord webhook + SMTP email notifications."""
import json
import logging
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage

log = logging.getLogger("netwatch")


def device_name(dev):
    return dev.get("nickname") or dev.get("auto_name") or dev.get("vendor") or dev["mac"]


def in_quiet_hours(quiet, now_dt):
    """quiet = {"start": 0-23 or None, "end": 0-23 or None}. Handles midnight wrap-around."""
    if not quiet:
        return False
    start, end = quiet.get("start"), quiet.get("end")
    if start is None or end is None:
        return False
    h = now_dt.hour
    if start == end:
        return False
    if start < end:
        return start <= h < end
    return h >= start or h < end  # wraps past midnight


def should_notify(cfg, kind, dev, now_dt):
    """Gate: per-device on/off (notify 0 = off) + global quiet hours."""
    if in_quiet_hours(cfg.get("quiet_hours"), now_dt):
        return False
    return dev.get("notify", 1) != 0  # 0 = off; anything else = on


def notify(cfg, kind, dev, force=False):
    """Send to each configured channel. Returns [(channel, error_or_None), ...].

    force=True bypasses the mode/quiet-hours gate — used by the Test button so it
    always fires and its empty result unambiguously means "no channels configured".
    """
    if not force and not should_notify(cfg, kind, dev, datetime.now()):
        return []
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
