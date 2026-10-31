"""Replays hand-built packets through the detector. No network or root needed."""
import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from netwatch import db
from netwatch.detector import Detector, base_domain

# First octet 00 = globally administered (a real vendor MAC), so no "randomised" note.
TV, PHONE, ROUTER = "00:bb:cc:00:00:01", "00:bb:cc:00:00:02", "00:bb:cc:00:00:ff"
T0 = 1_000_000.0
LEARN_END = T0 + 3600


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def send(self, title, message, severity="medium", tags=""):
        self.sent.append((title, message))


@pytest.fixture
def env(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    n = FakeNotifier()
    return Detector(conn, n, LEARN_END, new_device_grace_hours=1), n, conn


def dns_query(mac, ip, name):
    return (Ether(src=mac) / IP(src=ip, dst="192.168.1.1") / UDP(sport=4000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name)))


def dns_answer(name, *ips):
    an = DNSRR(rrname=name, rdata=ips[0])
    for extra in ips[1:]:
        an = an / DNSRR(rrname=name, rdata=extra)
    return (Ether(src=ROUTER) / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=4000)
            / DNS(qr=1, qd=DNSQR(qname=name), an=an, ancount=len(ips)))


def syn(mac, ip, dst, port=443):
    return Ether(src=mac) / IP(src=ip, dst=dst) / TCP(sport=5000, dport=port, flags="S")


def test_base_domain():
    assert base_domain("a.b.samsung.com.") == "samsung.com"
    assert base_domain("www.abc.net.au") == "abc.net.au"
    assert base_domain("example.com") == "example.com"


def test_learning_period_is_silent(env):
    det, n, conn = env
    det.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), T0 + 10)
    det.handle_packet(syn(TV, "192.168.1.10", "93.184.216.9"), T0 + 11)
    assert n.sent == []
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM dns_seen").fetchone()[0] == 1


def test_new_device_alerts_once(env):
    det, n, _ = env
    t = LEARN_END + 10
    det.handle_packet(syn(PHONE, "192.168.1.20", "93.184.216.5"), t)
    det.handle_packet(syn(PHONE, "192.168.1.20", "93.184.216.6"), t + 1)
    assert [x[0] for x in n.sent] == ["netwatch: New device on the network"]


def test_new_device_gets_grace_period(env):
    det, n, _ = env
    t = LEARN_END + 10
    det.handle_packet(syn(PHONE, "192.168.1.20", "93.184.216.5"), t)
    det.handle_packet(dns_query(PHONE, "192.168.1.20", "setup.example.org"), t + 60)
    assert len(n.sent) == 1                                    # only the new-device alert
    det.handle_packet(dns_query(PHONE, "192.168.1.20", "later.example.net"), t + 7200)
    assert len(n.sent) == 2                                    # grace over, now it counts


def test_new_domain_alerts_once_and_groups_subdomains(env):
    det, n, _ = env
    det.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), T0 + 1)   # learned
    t = LEARN_END + 10
    det.handle_packet(dns_query(TV, "192.168.1.10", "cdn.samsung.com"), t)        # same base
    assert n.sent == []
    det.handle_packet(dns_query(TV, "192.168.1.10", "tracker.badsite.ru"), t + 1)
    det.handle_packet(dns_query(TV, "192.168.1.10", "tracker.badsite.ru"), t + 2)
    assert len(n.sent) == 1 and "badsite.ru" in n.sent[0][1]


def test_dns_explained_destination_is_quiet_but_raw_ip_alerts(env):
    det, n, _ = env
    det.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), T0 + 1)   # register TV
    det.handle_packet(Ether(src=ROUTER) / ARP(op=2, hwsrc=ROUTER, psrc="192.168.1.1"), T0 + 2)  # and router
    t = LEARN_END + 10
    det.handle_packet(dns_answer("api.samsung.com", "151.101.1.69"), t)
    det.handle_packet(syn(TV, "192.168.1.10", "151.101.1.69"), t + 1)
    assert n.sent == []                                        # explained by DNS
    det.handle_packet(syn(TV, "192.168.1.10", "93.184.216.34", 8443), t + 2)
    det.handle_packet(syn(TV, "192.168.1.10", "93.184.216.34", 8443), t + 3)
    assert len(n.sent) == 1 and "93.184.216.34" in n.sent[0][1]


def test_lan_traffic_and_multicast_ignored(env):
    det, n, conn = env
    det.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), T0 + 1)
    t = LEARN_END + 10
    det.handle_packet(syn(TV, "192.168.1.10", "192.168.1.50"), t)               # LAN peer
    det.handle_packet(syn("01:00:5e:00:00:fb", "192.168.1.10", "93.184.216.1"), t)  # multicast MAC
    assert n.sent == []
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_arp_reveals_new_device(env):
    det, n, _ = env
    arp = Ether(src=PHONE) / ARP(op=1, hwsrc=PHONE, psrc="192.168.1.20", pdst="192.168.1.1")
    det.handle_packet(arp, LEARN_END + 5)
    assert len(n.sent) == 1


def test_randomised_mac_is_flagged(env):
    det, n, conn = env
    mac = "da:a1:19:00:00:01"                                  # locally administered bit set
    det.handle_packet(syn(mac, "192.168.1.30", "93.184.216.5"), LEARN_END + 5)
    assert "randomised" in n.sent[0][1]
    assert conn.execute("SELECT randomised FROM devices WHERE mac=?", (mac,)).fetchone()[0] == 1


def test_baseline_survives_restart(env, tmp_path):
    det, n, conn = env
    det.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), T0 + 1)
    det2 = Detector(conn, n, LEARN_END, 1)
    det2.handle_packet(dns_query(TV, "192.168.1.10", "api.samsung.com"), LEARN_END + 10)
    assert n.sent == []
