"""Flask dashboard: login + /api/* routes."""
import logging
import time

from common import BASE, check_password, save_config
from notify import notify
from scanner import DB_LOCK

log = logging.getLogger("netwatch")

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
                "SELECT e.kind, e.ts, e.mac, d.nickname, d.auto_name, d.vendor FROM events e "
                "LEFT JOIN devices d USING(mac) ORDER BY e.id DESC LIMIT 50")]
        return jsonify(devices=devices, events=events, now=int(time.time()),
                       offline_after_misses=tracker.offline_after,
                       scan_interval_sec=cfg["scan_interval_sec"],
                       quiet_hours=cfg.get("quiet_hours", {"start": None, "end": None}))

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
        body = request.get_json()
        try:
            misses = max(1, min(120, int(body.get("offline_after_misses"))))
        except (TypeError, ValueError):
            return jsonify(error="offline_after_misses must be an integer"), 400

        def hour(v):
            if v is None:
                return None
            v = int(v)
            if not 0 <= v <= 23:
                raise ValueError
            return v

        try:
            qs = hour(body["quiet_start"]) if "quiet_start" in body else cfg.get("quiet_hours", {}).get("start")
            qe = hour(body["quiet_end"]) if "quiet_end" in body else cfg.get("quiet_hours", {}).get("end")
        except (TypeError, ValueError):
            return jsonify(error="quiet_start/quiet_end must be 0-23 or null"), 400

        tracker.offline_after = misses
        cfg["offline_after_misses"] = misses
        cfg["quiet_hours"] = {"start": qs, "end": qe}
        save_config(cfg)
        log.info("offline_after_misses set to %d via dashboard", misses)
        return jsonify(ok=True, offline_after_misses=misses, quiet_hours=cfg["quiet_hours"])

    @app.post("/api/notify")
    def api_notify():
        if not authed():
            return jsonify(error="unauthorized"), 401
        if not request.is_json:
            return jsonify(error="json required"), 400
        body = request.get_json()
        val = body.get("notify")
        if val not in (0, 1, 2):
            return jsonify(error="notify must be 0, 1, or 2"), 400
        with DB_LOCK:
            if body.get("mac") == "*":
                conn.execute("UPDATE devices SET notify=?", (val,))
            else:
                conn.execute("UPDATE devices SET notify=? WHERE mac=?", (val, body.get("mac")))
            conn.commit()
        return jsonify(ok=True)

    return app
