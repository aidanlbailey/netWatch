"""Self-check for netWatch's pure logic: ARP parsing, MAC normalization, state machine.
Run: python test_netwatch.py
"""
import sqlite3
import sys
from datetime import datetime

import scanner
from common import check_password, hash_password
from notify import in_quiet_hours, should_notify

LINUX_IP_NEIGH = """192.168.1.1 dev eth0 lladdr a4:2b:b0:11:22:33 REACHABLE
192.168.1.42 dev eth0 lladdr f0:2f:4b:aa:bb:cc DELAY
192.168.1.68 dev eth0 lladdr 22:79:f2:32:66:f7 STALE
192.168.1.99 dev eth0  FAILED
"""

LINUX_PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        eth0
192.168.1.42     0x1         0x2         f0:2f:4b:aa:bb:cc     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
"""

EXPECTED = {"a4:2b:b0:11:22:33": "192.168.1.1", "f0:2f:4b:aa:bb:cc": "192.168.1.42"}


def filtered(pairs):
    return {mac: ip for ip, mac in pairs
            if mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 1}


def test_parse():
    # stale entries (departed devices) must be excluded; in-flight verification kept
    assert filtered(scanner.parse_arp(LINUX_IP_NEIGH,
                                      require=("REACHABLE", "DELAY", "PROBE"))) == EXPECTED
    assert filtered(scanner.parse_arp(LINUX_PROC_ARP)) == EXPECTED
    assert scanner.normalize_mac("F0-2F-4B-AA-BB-CC") == "f0:2f:4b:aa:bb:cc"


def test_tracker():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(scanner.SCHEMA)
    t = scanner.Tracker(conn, offline_after_misses=3)
    phone, tv = "aa:aa:aa:00:00:01", "bb:bb:bb:00:00:02"

    # both appear -> two new-device joins
    events = t.process({phone: "192.168.1.2", tv: "192.168.1.3"}, now=1000)
    assert sorted(k for k, _ in events) == ["join", "join"]
    assert all(d["new"] for _, d in events)

    # phone stays, tv misses twice -> no events yet (grace period)
    assert t.process({phone: "192.168.1.2"}, now=1012) == []
    assert t.process({phone: "192.168.1.2"}, now=1024) == []

    # third miss -> leave
    events = t.process({phone: "192.168.1.2"}, now=1036)
    assert [(k, d["mac"]) for k, d in events] == [("leave", tv)]

    # tv returns with a new DHCP ip -> rejoin (not "new"), ip updated
    events = t.process({phone: "192.168.1.2", tv: "192.168.1.77"}, now=1048)
    assert [(k, d["mac"], d["new"]) for k, d in events] == [("join", tv, False)]
    row = conn.execute("SELECT * FROM devices WHERE mac=?", (tv,)).fetchone()
    assert row["ip"] == "192.168.1.77" and row["online"] == 1

    # a single missed sweep never fires a leave
    t.process({tv: "192.168.1.77"}, now=1060)
    row = conn.execute("SELECT online FROM devices WHERE mac=?", (phone,)).fetchone()
    assert row["online"] == 1

    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4

    # notifications default on for new devices; rejoin events carry the flag
    assert conn.execute("SELECT notify FROM devices WHERE mac=?", (tv,)).fetchone()[0] == 1
    conn.execute("UPDATE devices SET notify=0 WHERE mac=?", (tv,))
    t.process({phone: "192.168.1.2"}, now=1072)  # tv misses
    t.process({phone: "192.168.1.2"}, now=1084)
    events = t.process({phone: "192.168.1.2"}, now=1096)  # third miss -> leave event
    assert [(k, d["mac"], d["notify"]) for k, d in events] == [("leave", tv, 0)]


def test_mark_present():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(scanner.SCHEMA)
    t = scanner.Tracker(conn, offline_after_misses=3)
    phone = "cc:cc:cc:00:00:03"

    # first sighting of a new mac -> new-device join
    events = t.mark_present(phone, "192.168.1.5", now=1000)
    assert [(k, d["new"]) for k, d in events] == [("join", True)]

    # still online -> no event, just refreshed
    assert t.mark_present(phone, "192.168.1.5", now=1006) == []
    row = conn.execute("SELECT * FROM devices WHERE mac=?", (phone,)).fetchone()
    assert row["online"] == 1 and row["last_seen"] == 1006

    # the leave path (via process) still works after using mark_present directly
    assert t.process({}, now=1018) == []
    assert t.process({}, now=1030) == []
    events = t.process({}, now=1042)
    assert [(k, d["mac"]) for k, d in events] == [("leave", phone)]

    # comes back -> rejoin, not "new"
    events = t.mark_present(phone, "192.168.1.5", now=1054)
    assert [(k, d["new"]) for k, d in events] == [("join", False)]


def test_sniffer_loop_without_scapy():
    # sniffer_loop must degrade silently (log and return) rather than raise or block
    # when scapy is missing -- force that regardless of whether it happens to be
    # installed in this environment (sys.modules[name] = None makes `import` raise
    # ImportError, same as if the package were absent).
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(scanner.SCHEMA)
    t = scanner.Tracker(conn, offline_after_misses=3)
    net = __import__("ipaddress").ip_network("192.168.1.0/24")

    saved = {m: sys.modules.get(m) for m in list(sys.modules) if m == "scapy" or m.startswith("scapy.")}
    for m in saved:
        del sys.modules[m]
    sys.modules["scapy"] = None
    try:
        scanner.sniffer_loop({"passive": "auto"}, t, net, lambda kind, dev: None)
    finally:
        del sys.modules["scapy"]
        sys.modules.update(saved)

    # passive=False must short-circuit before ever touching scapy
    scanner.sniffer_loop({"passive": False}, t, net, lambda kind, dev: None)


def test_netbios_parse():
    # synthetic NBSTAT response: name field is a compression pointer (0xc0 0x0c) back
    # to the question, then type/class/ttl/rdlength, then 2 name-table entries:
    # a group name ("WORKGROUP", group bit 0x8000 set) and a unique workstation
    # name ("TESTHOST", group bit clear). The parser should skip the group name.
    resp = (b"\x12\x34\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"  # header
            b"\xc0\x0c"                                          # name = pointer
            b"\x00\x21\x00\x01\x00\x00\x00\x00"                  # type, class, ttl
            b"\x00\x25"                                          # rdlength
            b"\x02"                                              # num_names
            b"WORKGROUP      \x00\x80\x04"                       # group name
            b"TESTHOST       \x00\x00\x04")                      # workstation name
    assert scanner._parse_netbios_response(resp) == "TESTHOST"
    assert scanner._parse_netbios_response(b"garbage") is None


def test_quiet_hours():
    assert in_quiet_hours(None, datetime(2026, 1, 1, 12)) is False
    assert in_quiet_hours({"start": None, "end": None}, datetime(2026, 1, 1, 12)) is False
    # wrap-around window: 22 -> 7
    wrap = {"start": 22, "end": 7}
    assert in_quiet_hours(wrap, datetime(2026, 1, 1, 23)) is True
    assert in_quiet_hours(wrap, datetime(2026, 1, 1, 3)) is True
    assert in_quiet_hours(wrap, datetime(2026, 1, 1, 12)) is False
    # non-wrap window: 1 -> 5
    plain = {"start": 1, "end": 5}
    assert in_quiet_hours(plain, datetime(2026, 1, 1, 3)) is True
    assert in_quiet_hours(plain, datetime(2026, 1, 1, 5)) is False
    assert in_quiet_hours(plain, datetime(2026, 1, 1, 0)) is False


def test_notify_modes():
    cfg = {"discord": {"webhook_url": ""}, "smtp": {"host": ""}}
    now = datetime(2026, 1, 1, 12)
    known = {"mac": "aa:aa:aa:00:00:01", "new": False}
    new_dev = {"mac": "aa:aa:aa:00:00:01", "new": True}

    assert should_notify(cfg, "join", {**known, "notify": 0}, now) is False
    assert should_notify(cfg, "leave", {**known, "notify": 0}, now) is False

    assert should_notify(cfg, "join", {**known, "notify": 1}, now) is True
    assert should_notify(cfg, "leave", {**known, "notify": 1}, now) is True

    assert should_notify(cfg, "join", {**known, "notify": 2}, now) is False
    assert should_notify(cfg, "join", {**new_dev, "notify": 2}, now) is True
    assert should_notify(cfg, "leave", {**known, "notify": 2}, now) is False

    # missing/None notify defaults to "all"
    assert should_notify(cfg, "join", known, now) is True
    assert should_notify(cfg, "join", {**known, "notify": None}, now) is True

    # quiet hours suppress everything regardless of mode
    cfg_quiet = {**cfg, "quiet_hours": {"start": 10, "end": 14}}
    assert should_notify(cfg_quiet, "join", {**new_dev, "notify": 2}, now) is False
    assert should_notify(cfg_quiet, "join", {**known, "notify": 1}, now) is False


def test_notify_force_bypasses_gate():
    from notify import notify
    # quiet hours active + mode off would normally suppress; force must still try to send.
    cfg = {"discord": {"webhook_url": "", "mention_user_id": ""}, "smtp": {"host": ""},
           "quiet_hours": {"start": 0, "end": 23}}
    dev = {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.1", "notify": 0}
    # no channels configured -> empty either way, but force must not short-circuit on the gate
    assert notify(cfg, "join", dev) == []          # gated (would be [] anyway)
    assert notify(cfg, "join", dev, force=True) == []  # no channels -> still [], but reached send path
    # with a channel "configured", gate blocks normally but force reaches the (failing) send
    cfg2 = {**cfg, "discord": {"webhook_url": "http://127.0.0.1:9/x", "mention_user_id": ""}}
    assert notify(cfg2, "join", dev) == []                    # suppressed by gate
    assert [c for c, _ in notify(cfg2, "join", dev, force=True)] == ["Discord"]  # attempted


def test_password():
    h = hash_password("hunter2")
    assert check_password("hunter2", h)
    assert not check_password("hunter3", h)
    assert not check_password("x", "garbage")


if __name__ == "__main__":
    test_parse()
    test_tracker()
    test_mark_present()
    test_sniffer_loop_without_scapy()
    test_netbios_parse()
    test_quiet_hours()
    test_notify_modes()
    test_notify_force_bypasses_gate()
    test_password()
    print("all checks passed")
