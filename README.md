# netWatch

Tracks devices joining and leaving your home LAN. Sends Discord and/or email
notifications and serves a password-protected dashboard on your LAN.

Every ~12 s it ARP-probes every host in the subnet (SendARP on Windows,
ping + neighbor state on Linux). Joins are detected within ~15 s. A device is
marked offline after ~5 min of missed sweeps, since [idle phones stop answering
for short stretches](https://discussions.apple.com/thread/255083854?answerId=259469966022&sortBy=rank#259469966022).
No admin rights or capture drivers needed.

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

Both the wizard and the dashboard have a Help button that opens these docs.

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

Fill in the `smtp` block in config.json. For Gmail: `smtp.gmail.com`, port 587,
and an [app password](https://myaccount.google.com/apppasswords).

An empty `webhook_url` or `host` disables that channel. Test with the
dashboard's "Test notification" button or `python netwatch.py test-notify`.

## Service control without the wizard

```
schtasks /End /TN netWatch                # Windows
schtasks /Run /TN netWatch
systemctl --user stop netwatch            # Linux
systemctl --user start netwatch
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

Edits to config.json apply within one sweep. Changes to `bind_host`,
`bind_port`, or the password need a restart.

| key | meaning |
|---|---|
| `subnet` | `null` auto-detects the local /24. Pin it (e.g. `"192.168.1.0/24"`) if you use a VPN, otherwise the VPN's subnet gets scanned. |
| `scan_interval_sec` | sweep frequency |
| `offline_after_misses` | missed sweeps before a leave fires. Adjustable with the dashboard slider. Default 25 (~5 min). Lower it if you only track always-on devices. |
| `bind_host` / `bind_port` | dashboard listen address |
| `db_path` | SQLite file, relative to the script |

## Limits

Single IPv4 /24. No VLANs, IPv6, or HTTPS. One shared password.
