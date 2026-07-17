"""Self-check for netWatch's pure logic: ARP parsing, MAC normalization, state machine.
Run: python test_netwatch.py
"""
import sqlite3

import netwatch

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
    assert filtered(netwatch.parse_arp(LINUX_IP_NEIGH,
                                       require=("REACHABLE", "DELAY", "PROBE"))) == EXPECTED
    assert filtered(netwatch.parse_arp(LINUX_PROC_ARP)) == EXPECTED
    assert netwatch.normalize_mac("F0-2F-4B-AA-BB-CC") == "f0:2f:4b:aa:bb:cc"


def test_tracker():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(netwatch.SCHEMA)
    t = netwatch.Tracker(conn, offline_after_misses=3)
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


def test_password():
    h = netwatch.hash_password("hunter2")
    assert netwatch.check_password("hunter2", h)
    assert not netwatch.check_password("hunter3", h)
    assert not netwatch.check_password("x", "garbage")


if __name__ == "__main__":
    test_parse()
    test_tracker()
    test_password()
    print("all checks passed")
