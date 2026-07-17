"""netWatch Install Wizard — localhost page that configures and installs the service.

Run: python installer.py (or double-click installer.bat on Windows).
Windows: manages a Scheduled Task. Linux: manages a systemd user unit (no sudo).
"""
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import netwatch  # for hash_password; imports nothing beyond stdlib at module level

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "config.json"
PORT = 8765
IS_WIN = os.name == "nt"


def sh(args):
    r = subprocess.run(args, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def sh_rc(args):
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def deps_ok():
    try:
        import flask, waitress  # noqa: F401
        return True
    except ImportError:
        return False


def read_config():
    src = CONFIG if CONFIG.exists() else BASE / "config.example.json"
    return json.loads(src.read_text())


def get_state():
    if IS_WIN:
        rc, out = sh_rc(["schtasks", "/Query", "/TN", "netWatch", "/FO", "LIST", "/V"])
        installed = rc == 0
        running = installed and "Running" in out
        if not installed:
            text, level = "Not installed", "off"
        elif running:
            text, level = "Installed and running", "ok"
        else:
            m = re.search(r"Last Result:\s*(-?\d+)", out)
            code = int(m.group(1)) if m else 0
            if code in (0, 267009):
                text, level = "Installed but stopped", "warn"
            else:
                text, level = f"Installed, last run failed (exit {code}, see Logs)", "err"
    else:
        installed = UNIT_PATH.exists()
        _, active = sh_rc(["systemctl", "--user", "is-active", "netwatch"])
        running = active in ("active", "activating")
        text, level = (("Not installed", "off") if not installed else
                       ("Installed and running", "ok") if active == "active" else
                       ("Installed, crashing and restarting (see Logs)", "err") if active == "activating" else
                       ("Installed, failed (see Logs)", "err") if active == "failed" else
                       ("Installed but stopped", "warn"))
    password_set, discord = False, {}
    try:
        if CONFIG.exists():
            cfg = json.loads(CONFIG.read_text())
            password_set = bool(cfg.get("password_hash"))
            discord = cfg.get("discord", {})
    except ValueError:
        pass
    return {"deps_ok": deps_ok(), "password_set": password_set,
            "installed": installed, "running": running,
            "status_text": text, "status_level": level,
            "webhook_url": discord.get("webhook_url", ""),
            "mention_user_id": discord.get("mention_user_id", "")}


def do_setup(body):
    pw = (body.get("password") or "").strip()
    if pw and len(pw) < 4:
        return "Password must be at least 4 characters."
    if not pw and not get_state()["password_set"]:
        return "Password is required on first setup."
    uid = (body.get("mention_user_id") or "").strip()
    if uid and not uid.isdigit():
        return ("Discord user ID must be numeric. In Discord: Settings > Advanced > "
                "enable Developer Mode, then right-click yourself > Copy User ID.")
    cfg = read_config()
    if pw:
        cfg["password_hash"] = netwatch.hash_password(pw)
    if (body.get("webhook_url") or "").strip():
        cfg["discord"]["webhook_url"] = body["webhook_url"].strip()
    if uid:
        cfg["discord"]["mention_user_id"] = uid
    CONFIG.write_text(json.dumps(cfg, indent=2))
    return "Configuration saved. Press Install / repair."


def _log_tail():
    log = BASE / "netwatch.log"
    if IS_WIN:
        tail = log.read_text(errors="replace").splitlines()[-10:] if log.exists() else []
    else:
        tail = sh(["journalctl", "--user", "-u", "netwatch", "-n", "10", "--no-pager"]).splitlines()
    return "\n\nRecent log:\n" + "\n".join(tail) if tail else ""


if IS_WIN:
    ACTIONS = {
        "status": lambda: sh(["schtasks", "/Query", "/TN", "netWatch", "/FO", "LIST", "/V"]) + _log_tail(),
        "start": lambda: sh(["schtasks", "/Run", "/TN", "netWatch"]),
        "stop": lambda: sh(["schtasks", "/End", "/TN", "netWatch"]),
        # install_task.ps1 self-elevates (UAC prompt); result shows in its own window
        "install": lambda: sh(["powershell", "-ExecutionPolicy", "Bypass", "-File",
                               str(BASE / "install_task.ps1")]) or "UAC prompt opened — approve it, then check status.",
        "uninstall": lambda: sh(["powershell", "-Command",
            "Start-Process powershell -Verb RunAs -Wait -ArgumentList "
            "'-Command','schtasks /End /TN netWatch; schtasks /Delete /TN netWatch /F'"])
            or "Uninstalled (approve the UAC prompt if one appeared).",
    }
else:
    UNIT_PATH = Path.home() / ".config/systemd/user/netwatch.service"
    UNIT = f"""[Unit]
Description=netWatch LAN device tracker
After=network-online.target

[Service]
WorkingDirectory={BASE}
ExecStart="{sys.executable}" "{BASE / 'netwatch.py'}"
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""

    def _install():
        UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        UNIT_PATH.write_text(UNIT)
        out = sh(["systemctl", "--user", "daemon-reload"])
        out += "\n" + sh(["systemctl", "--user", "enable", "--now", "netwatch"])
        # lets the user service run at boot without anyone logging in
        out += "\n" + sh(["loginctl", "enable-linger"])
        return out.strip() or "Installed and started."

    def _uninstall():
        out = sh(["systemctl", "--user", "disable", "--now", "netwatch"])
        UNIT_PATH.unlink(missing_ok=True)
        sh(["systemctl", "--user", "daemon-reload"])
        return out.strip() or "Uninstalled."

    ACTIONS = {
        "status": lambda: sh(["systemctl", "--user", "status", "netwatch", "--no-pager"]) + _log_tail(),
        "start": lambda: sh(["systemctl", "--user", "start", "netwatch"]) or "Started.",
        "stop": lambda: sh(["systemctl", "--user", "stop", "netwatch"]) or "Stopped.",
        "install": _install,
        "uninstall": _uninstall,
    }

def _open_config():
    if not CONFIG.exists():
        CONFIG.write_text(json.dumps(read_config(), indent=2))
    if IS_WIN:
        os.startfile(CONFIG)
    else:
        sh(["xdg-open", str(CONFIG)])
    return ("Opened config.json in your default editor. Most edits apply within "
            "one sweep; bind/port/password changes need a service restart.")


ACTIONS["config"] = _open_config

_platform_install = ACTIONS["install"]


def _checked_install():
    s = get_state()
    if not s["deps_ok"]:
        return ("Dependencies missing. Run: pip install -r requirements.txt\n"
                "(on Linux: python3 -m venv venv && venv/bin/pip install -r requirements.txt,\n"
                "then relaunch the wizard with venv/bin/python installer.py)")
    if not s["password_set"]:
        return "Set a dashboard password above first."
    return _platform_install()


ACTIONS["install"] = _checked_install

PAGE = """<!doctype html><meta charset="utf-8"><title>netWatch Install Wizard</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
  h1{font-size:1.2rem}
  fieldset{border:1px solid #ddd;margin-bottom:1rem;padding:1rem}
  label{display:block;margin:.5rem 0 .2rem}
  input{font:inherit;padding:.3rem;width:100%;max-width:24rem;box-sizing:border-box}
  button{font:inherit;font-size:.85rem;padding:.3rem .6rem;margin:0 .25rem .25rem 0}
  .row{margin:.4rem 0}
  .grp{display:inline-block;width:4.5rem;font-size:.8rem;color:#666}
  small{color:#666}
  #statusLine{font-weight:600}
  #statusLine::before{content:"\\25CF  "}
  .ok{color:#1a7f37}
  .warn{color:#9a6700}
  .err{color:#cf222e}
  .off{color:#57606a}
  pre{border:1px solid #ddd;padding:1rem;white-space:pre-wrap;min-height:6rem;font-size:.85rem}
</style>
<h1>netWatch Install Wizard</h1>
<p>Status: <span id="statusLine" class="off">checking...</span></p>
<p><small>Once installed and running, the dashboard is served at
<a href="http://localhost:8080" target="_blank">localhost:8080</a> (and this
machine's LAN IP on port 8080 for other devices). Visit it any time; this
wizard is only needed for install and service control.</small></p>

<div id="depsMsg" hidden>
  <p>Dependencies are missing. In this folder run:</p>
  <pre>pip install -r requirements.txt</pre>
  <p><small>Linux: python3 -m venv venv &amp;&amp; venv/bin/pip install -r requirements.txt,
  then relaunch with venv/bin/python installer.py</small></p>
</div>

<fieldset id="setup" hidden>
  <legend>Configure</legend>
  <label>Dashboard password (required on first setup; leave blank to keep current)</label>
  <input type="password" id="pw">
  <label>Discord webhook URL (optional)</label>
  <input id="hook" placeholder="https://discord.com/api/webhooks/...">
  <label>Discord user ID to @mention (optional)</label>
  <input id="uid" placeholder="numeric ID, not your username">
  <small>Settings &gt; Advanced &gt; Developer Mode, then right-click yourself &gt; Copy User ID.
  Email can be configured later in config.json.</small><br><br>
  <button onclick="saveSetup()">Save configuration</button>
</fieldset>

<div class="row"><span class="grp">Service</span>
  <button id="install" onclick="act('install')">Install / repair</button>
  <button id="uninstall" onclick="act('uninstall')">Uninstall</button>
  <button id="start" onclick="act('start')" hidden>Start</button>
  <button id="stop" onclick="act('stop')" hidden>Stop</button>
</div>
<div class="row"><span class="grp">Config</span>
  <button onclick="showSetup()">Config (assistive)</button>
  <button onclick="act('config')">Config (manual)</button>
</div>
<div class="row"><span class="grp">More</span>
  <button id="panel" onclick="window.open('http://localhost:8080')">Open panel</button>
  <button onclick="act('status')">Logs</button>
  <button onclick="window.open('https://github.com/aidanlbailey/netWatch#readme')">Help</button>
  <button onclick="act('quit')">Quit wizard</button>
</div>
<pre id="out"></pre>

<script>
const $ = id => document.getElementById(id);

let forceSetup = false;
let lastState = null;
let prefilled = false;

function prefill(s) {
  if (!s) return;
  $("hook").value = s.webhook_url || "";
  $("uid").value = s.mention_user_id || "";
}

function showSetup() { prefill(lastState); forceSetup = true; $("setup").hidden = false; }

async function loadState() {
  const s = await (await fetch("/state")).json();
  lastState = s;
  if (!prefilled) { prefill(s); prefilled = true; }
  $("statusLine").textContent = s.status_text;
  $("statusLine").className = s.status_level;
  $("depsMsg").hidden = s.deps_ok;
  $("setup").hidden = s.password_set && !forceSetup;
  $("install").disabled = !s.deps_ok || !s.password_set;
  $("uninstall").disabled = !s.installed;
  $("start").hidden = $("stop").hidden = !s.installed;
  $("start").disabled = s.running;
  $("stop").disabled = !s.running;
  $("panel").disabled = !s.installed;
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "X-Helper": "1", "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.text();
}

async function act(name) {
  $("out").textContent = "Running " + name + "...";
  $("out").textContent = await post("/" + name);
  if (name === "quit") { $("out").textContent = "Wizard stopped. Close this tab."; return; }
  loadState();
}

async function saveSetup() {
  const msg = await post("/setup",
    { password: $("pw").value, webhook_url: $("hook").value, mention_user_id: $("uid").value });
  $("out").textContent = msg;
  if (msg.startsWith("Configuration saved")) forceSetup = false;
  loadState();
}

loadState();
setInterval(loadState, 5000);
</script>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/state":
            return self._send(200, json.dumps(get_state()), "application/json")
        self._send(200, PAGE, "text/html; charset=utf-8")

    def do_POST(self):
        if self.headers.get("X-Helper") != "1":  # blocks cross-site POSTs from other pages
            return self._send(403, "forbidden")
        name = self.path.strip("/")
        if name == "quit":
            self._send(200, "bye")
            threading.Thread(target=server.shutdown).start()
            return
        if name == "setup":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._send(400, "bad json")
            return self._send(200, do_setup(body))
        fn = ACTIONS.get(name)
        self._send(200, fn() if fn else "unknown action")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"netWatch Install Wizard on http://127.0.0.1:{PORT} — Ctrl+C or the Quit button to exit")
    webbrowser.open(f"http://127.0.0.1:{PORT}")
    server.serve_forever()
