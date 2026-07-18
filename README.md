# netWatch

Tracks devices joining and leaving your home LAN. Names devices automatically,
sends Discord and/or email notifications, and serves a password-protected
dashboard on your LAN with per-device controls and presence history.

Every ~12 s it ARP-probes every host in the subnet (SendARP on Windows,
ping + neighbor state on Linux). Joins are detected within ~15 s. A device is
marked offline after ~5 min of missed sweeps, since [idle phones stop answering
for short stretches](https://discussions.apple.com/thread/255083854?answerId=259469966022&sortBy=rank#259469966022).
No admin rights or capture drivers needed.

## Features

- **Auto-naming**: devices label themselves via reverse-DNS and NetBIOS (and
  DHCP hostnames when the sniffer is on), so you see "living-room-tv" instead of
  a MAC. Override any name with a nickname (right-click a nickname to reset it).
- **Notifications**: Discord webhook and/or SMTP email on join/leave, with a
  Test button, a per-device on/off toggle, and global quiet hours. New devices
  notify by default.
- **Dashboard**: who's-home summary, device table, per-device presence timeline
  (click a device's status), adjustable offline grace period, service
  stop/restart, and a Settings panel to edit config (subnet, notifications,
  detection) without leaving the page.
- **Optional instant detection**: install scapy (plus Npcap on Windows) to add
  passive ARP/DHCP sniffing for ~1-3 s join detection. The dashboard shows
  whether it's active and how to enable it. Without it, the active sweep covers
  everything; nothing else changes.
- Runs 24/7 as a Scheduled Task (Windows) or systemd user unit (Linux).

## Install

Windows:

```
pip install -r requirements.txt
python installer.py
```

Linux:

```
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python installer.py
```

The Install Wizard opens in your browser. Set a dashboard password and your
Discord webhook there, press "Install / repair", done. The wizard shows the
service state and handles start, stop, uninstall, logs, and config editing:
"Config (assistive)" reopens the guided form, "Config (manual)" opens
config.json in your editor. Rerun the wizard any time.

- Windows: installs a Scheduled Task running at logon. Logs: `netwatch.log`.
- Linux: installs a systemd user unit, no sudo, starts at boot via lingering.
  Logs: `journalctl --user -u netwatch`.

Dashboard: `http://<machine-ip>:8080` from any device on your LAN.

### Discord

Webhooks post to a channel, not DMs. Make a private server with just you in it,
then: Channel settings > Integrations > Webhooks > New Webhook. Give the wizard
the webhook URL and your numeric user ID (Settings > Advanced > enable
Developer Mode, right-click yourself > Copy User ID). The @mention pushes to
your phone.

### Email

Fill in the `smtp` block (from the dashboard Settings panel or config.json). For
Gmail: `smtp.gmail.com`, port 587, and an
[app password](https://myaccount.google.com/apppasswords).

An empty `webhook_url` or `host` disables that channel. Test with the
dashboard's "Test notification" button or `python netwatch.py test-notify`.

## Controlling the service

The dashboard has Stop and Restart buttons. Start is not on the dashboard,
because a stopped service has nothing to serve it; start it from the install
wizard or the service manager:

```
schtasks /Run /TN netWatch                # Windows start
schtasks /End /TN netWatch                # Windows stop
systemctl --user start netwatch           # Linux start
systemctl --user stop netwatch            # Linux stop
```

`python netwatch.py` runs in the foreground instead, and
`python netwatch.py set-password` changes the password.

## Security

- LAN only. Don't port-forward 8080.
- Password required (PBKDF2 hash in config.json). 5 failed logins per IP is a
  15-minute lockout.
- Plain HTTP on your LAN. Put Caddy in front if you want TLS.
- `config.json` holds secrets and is gitignored.

## Config

Edit config from the dashboard Settings panel or by hand in config.json. Most
edits apply within one sweep; changes to `bind_host`, `bind_port`, `passive`,
`subnet`, or the password need a restart.

| key | meaning |
|---|---|
| `subnet` | `null` auto-detects the local /24. Pin it (e.g. `"192.168.1.0/24"`) if you use a VPN, otherwise the VPN's subnet gets scanned. |
| `scan_interval_sec` | sweep frequency in seconds |
| `offline_after_misses` | missed sweeps before a leave fires. Adjustable with the dashboard slider. Default 25 (~5 min). Lower it if you only track always-on devices. |
| `passive` | `"auto"` uses the scapy sniffer if available, else the sweep only. `true` forces it (warns if unavailable), `false` disables it. |
| `quiet_hours` | `{"start": null, "end": null}` = off. Hours are on the 24-hour clock, 0 to 23, local time, and wrap past midnight (e.g. start 22, end 7 means 10pm to 7am). Suppresses all notifications in that window. Editable from the dashboard. |
| `bind_host` / `bind_port` | dashboard listen address |
| `db_path` | SQLite file, relative to the script |

## Instant detection (optional)

For ~1-3 s join detection instead of ~15 s, install the sniffer:

```
pip install scapy          # plus Npcap on Windows: https://npcap.com
```

netWatch picks it up automatically (`passive: "auto"`). It passively watches
ARP/DHCP to catch devices the instant they announce themselves; the active
sweep still runs for leave detection. Without scapy, nothing changes.

On Linux the sniffer needs raw-socket access, which the unprivileged systemd
user service lacks by default (you'll see "passive sniffing unavailable ... no
permission" in the logs). Grant the capability to the interpreter the service
runs, then restart:

```
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
systemctl --user restart netwatch
```

This lets that Python open raw sockets without running the whole service as
root. On Windows, installing Npcap grants the equivalent access.

## Limits

Single IPv4 /24. No VLANs, IPv6, or HTTPS. One shared password.
