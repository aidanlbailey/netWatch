"""Network sweep (ping/ARP), online/offline state machine, SQLite persistence,
vendor lookup, and the scanner thread loop."""
import ctypes
import ipaddress
import logging
import re
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import CONFIG_PATH, IS_WIN, load_config
from notify import device_name, notify

log = logging.getLogger("netwatch")

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
  auto_name  TEXT,
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
# notify modes: 0 = off, 1 = all join/leave events, 2 = new-device-only


def open_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:  # migrate DBs created before the notify column existed
        conn.execute("ALTER TABLE devices ADD COLUMN notify INTEGER NOT NULL DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    try:  # migrate DBs created before the auto_name column existed
        conn.execute("ALTER TABLE devices ADD COLUMN auto_name TEXT")
    except sqlite3.OperationalError:
        pass
    return conn


class Tracker:
    """Online/offline state machine. Devices keyed by MAC; DB is the source of truth."""

    def __init__(self, conn, offline_after_misses):
        self.conn = conn
        self.offline_after = offline_after_misses
        self.misses = {}  # mac -> consecutive sweeps unseen while online

    def mark_present(self, mac, ip, now):
        """Handle one observed device: insert-if-new, mark-online-if-was-offline, or
        just refresh ip/last_seen. Returns [(kind, device_dict), ...] (0 or 1 "join"
        events), same shape as process(). Resets self.misses for mac.

        DB access + misses mutation are locked so this is safe to call concurrently
        with process() (e.g. from a passive sniffer thread alongside the sweep loop).
        """
        events = []
        with DB_LOCK:
            self.misses.pop(mac, None)
            r = self.conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            row = dict(r) if r else None
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
            for kind, dev in events:
                self.conn.execute("INSERT INTO events (mac, kind, ts) VALUES (?,?,?)",
                                  (dev["mac"], kind, now))
            self.conn.commit()
        return events

    def process(self, seen, now):
        """Apply one sweep result. Returns [(kind, device_dict), ...] to notify."""
        events = []
        for mac, ip in seen.items():
            events.extend(self.mark_present(mac, ip, now))
        with DB_LOCK:
            online = {r["mac"]: dict(r) for r in self.conn.execute("SELECT * FROM devices WHERE online=1")}
            leaves = []
            for mac, row in online.items():
                if mac in seen:
                    continue
                n = self.misses.get(mac, 0) + 1
                if n >= self.offline_after:
                    self.misses.pop(mac, None)
                    self.conn.execute("UPDATE devices SET online=0 WHERE mac=?", (mac,))
                    leaves.append(("leave", row))
                else:
                    self.misses[mac] = n
            for kind, dev in leaves:
                self.conn.execute("INSERT INTO events (mac, kind, ts) VALUES (?,?,?)",
                                  (dev["mac"], kind, now))
            self.conn.commit()
        events.extend(leaves)
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

    _lookup_names(conn)

# ---------------------------------------------------------------- name resolution

_name_attempted = set()


def _lookup_names(conn):
    """Fill in auto_name via reverse DNS / NetBIOS. Best-effort, stdlib only."""
    with DB_LOCK:
        rows = [(r["mac"], r["ip"]) for r in
                 conn.execute("SELECT mac, ip FROM devices WHERE auto_name IS NULL")]
    for mac, ip in [(m, i) for m, i in rows if m not in _name_attempted][:3]:
        _name_attempted.add(mac)
        name = resolve_name(ip) if ip else None
        if name:
            with DB_LOCK:
                conn.execute("UPDATE devices SET auto_name=? WHERE mac=?", (name, mac))
                conn.commit()


def resolve_name(ip):
    """Best-effort hostname for ip: reverse DNS, falling back to a NetBIOS node-status
    query. Returns a cleaned name (<=63 chars) or None. Never raises."""
    name = None
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.5)
        host = socket.gethostbyaddr(ip)[0]
        label = host.split(".")[0].strip()
        if label and label != ip:
            name = label
    except (OSError, UnicodeError):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    if not name:
        try:
            name = _netbios_query(ip)
        except Exception:
            name = None
    return name[:63] if name else None


def _netbios_query(ip):
    """Send a UDP/137 NBSTAT node-status request and return the first workstation
    name found in the reply, or None. Best-effort: any socket error yields None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.0)
            s.sendto(_netbios_query_packet(), (ip, 137))
            data, _addr = s.recvfrom(1024)
        return _parse_netbios_response(data)
    except OSError:
        return None


def _netbios_query_packet():
    """~50-byte NBSTAT query for the wildcard name '*' (node status request)."""
    padded = b"*" + b"\x00" * 15
    encoded = bytes(c for byte in padded for c in (0x41 + (byte >> 4), 0x41 + (byte & 0xF)))
    header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    question = bytes([32]) + encoded + b"\x00" + struct.pack(">HH", 0x21, 0x01)
    return header + question


def _parse_netbios_response(data):
    """Pure parser for an NBSTAT response: return the first non-group (workstation)
    NetBIOS name in the name table, or None. Format (after the 12-byte header):
    a name field (either a compression pointer or an encoded label), then
    type/class/ttl/rdlength (10 bytes), then a 1-byte name count and that many
    18-byte entries (15-char name + 1 suffix byte + 2 flag bytes; bit 0x8000 of
    the flags marks a group name)."""
    try:
        if data[12] == 0xC0:  # compression pointer back to the question name
            off = 12 + 2
        else:  # length-prefixed encoded label, terminated by a 0x00 byte
            off = 12 + 1 + data[12] + 1
        off += 2 + 2 + 4 + 2  # type + class + ttl + rdlength
        num_names = data[off]
        off += 1
        for i in range(num_names):
            entry = data[off + i * 18: off + i * 18 + 18]
            if len(entry) < 18:
                break
            flags = struct.unpack(">H", entry[16:18])[0]
            if not flags & 0x8000:  # unique name, not a group name
                name = entry[:15].decode("ascii", "ignore").rstrip(" \x00")
                if name:
                    return name
        return None
    except (IndexError, struct.error):
        return None

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

# ---------------------------------------------------------------- passive sniffer (optional)

def sniffer_loop(cfg, tracker, net, notify_cb):
    """Optional passive listener: ARP/DHCP traffic gives near-instant (~1-3s) join
    detection, a complement to the periodic active sweep() used by scanner_loop.
    Requires `pip install scapy` and Npcap (Windows) / libpcap (Linux/macOS); when
    either is missing this logs one line and returns, leaving detection to the
    active sweep exactly as before this feature existed. Never raises.

    Wiring (in netwatch.py's run(), started alongside the existing scanner_loop
    thread and sharing the same tracker/net):

        threading.Thread(target=sniffer_loop, args=(cfg, tracker, net, notify_cb),
                         daemon=True).start()

    `notify_cb(kind, dev)` should match what scanner_loop does for each event, e.g.:

        def notify_cb(kind, dev):
            if dev.get("notify", 1):
                notify(cfg, kind, dev)

    cfg["passive"]: "auto" (default) = use the sniffer if available, silently fall
    back otherwise; True = same, but warn (not just info-log) if unavailable;
    False = disabled, this function returns immediately.
    """
    mode = cfg.get("passive", "auto")
    if mode is False:
        return
    warn = log.warning if mode is True else log.info

    try:
        from scapy.all import AsyncSniffer, ARP, DHCP, BOOTP
    except Exception:
        warn("passive sniffing unavailable (scapy not installed); using active sweep only")
        return

    def set_hostname(mac, hostname):
        with DB_LOCK:
            r = tracker.conn.execute("SELECT auto_name FROM devices WHERE mac=?", (mac,)).fetchone()
            if r is not None and not r["auto_name"]:
                tracker.conn.execute("UPDATE devices SET auto_name=? WHERE mac=?", (hostname, mac))
                tracker.conn.commit()

    def handler(pkt):
        try:
            mac = ip = hostname = None
            if pkt.haslayer(ARP):
                mac, ip = normalize_mac(pkt[ARP].hwsrc), pkt[ARP].psrc
            elif pkt.haslayer(BOOTP):
                mac = normalize_mac(pkt[BOOTP].chaddr[:6].hex(":"))
                ip = pkt[BOOTP].yiaddr if pkt[BOOTP].yiaddr not in (None, "0.0.0.0") else pkt[BOOTP].ciaddr
                if pkt.haslayer(DHCP):
                    for opt in pkt[DHCP].options:  # option 12 = hostname
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            hostname = opt[1].decode() if isinstance(opt[1], bytes) else opt[1]
            if not mac or not ip or int(mac[:2], 16) & 1:
                return  # no address, or multicast/broadcast source
            if ip in (None, "0.0.0.0") or ipaddress.ip_address(ip) not in net:
                return
            for kind, dev in tracker.mark_present(mac, ip, int(time.time())):
                notify_cb(kind, dev)
            if hostname:
                set_hostname(mac, hostname)
        except Exception:
            log.exception("passive sniffer: bad packet")

    try:
        AsyncSniffer(filter="arp or (udp and (port 67 or 68))", prn=handler, store=False).start()
    except Exception as e:
        warn("passive sniffing unavailable (scapy/Npcap missing or no permission): %s", e)
        return

    log.info("passive sniffer active (ARP/DHCP)")
    threading.Event().wait()  # AsyncSniffer runs in its own thread; keep this daemon alive
