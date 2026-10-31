"""Core logic: turn packets into a per-device baseline, then flag what's new.

Three rules (see README for the reasoning):
  new_device              a MAC address appears that we have never seen
  new_domain              a known device looks up a domain it has never looked up
  unexplained_destination a known device connects to an outside IP that no DNS
                          answer explains (hard-coded server, bypassing DNS)

Everything is "first time seen" logic. During the learning period we record
silently; afterwards the first sighting of anything new raises one alert and
then joins the baseline, so you are never told about the same thing twice.
"""
import ipaddress
import time

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

# Two-label public suffixes, so "bbc.co.uk" is the base domain, not "co.uk".
MULTI_SUFFIX = {
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.nz", "co.jp", "com.br", "co.in",
}
SKIP_SUFFIXES = (".arpa", ".local", ".lan", ".home", ".internal")
FLUSH_EVERY = 30  # seconds between last_seen writes
MAX_DNS_MAP = 50_000


def base_domain(name: str) -> str:
    name = name.rstrip(".").lower()
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_lan_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private and not (a.is_loopback or a.is_link_local
                                 or a.is_unspecified or a.is_multicast)


def is_outside_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


class Detector:
    def __init__(self, conn, notifier, learning_until, new_device_grace_hours=24.0):
        self.conn, self.notifier = conn, notifier
        self.learning_until = float(learning_until)
        self.grace = new_device_grace_hours * 3600

        # In-memory copies of the baseline: most packets match and touch no disk.
        self.devices = {
            r["mac"]: {"ip": r["ip"], "last_seen": r["last_seen"], "learn_until": r["learn_until"]}
            for r in conn.execute("SELECT mac, ip, last_seen, learn_until FROM devices")
        }
        self.known_dns = {(r["mac"], r["domain"]) for r in conn.execute("SELECT mac, domain FROM dns_seen")}
        self.known_dest = {(r["mac"], r["dest"], r["port"]) for r in conn.execute("SELECT mac, dest, port FROM dest_seen")}
        self.ip_to_domain = {}      # learned from DNS answers, not persisted
        self._dirty = set()
        self._last_flush = 0.0

    # ------------------------------------------------------------ packet entry
    def handle_packet(self, pkt, ts=None):
        ts = ts or time.time()
        if ts - self._last_flush > FLUSH_EVERY:
            self.flush(ts)

        if ARP in pkt:                       # ARP broadcasts reveal new devices anywhere
            a = pkt[ARP]
            if a.op in (1, 2) and a.psrc not in ("0.0.0.0", "") and is_lan_ip(a.psrc):
                self._see_device(a.hwsrc.lower(), a.psrc, ts)
            return

        if IP not in pkt or Ether not in pkt:
            return
        ip = pkt[IP]

        if DNS in pkt and pkt[DNS].qr == 1:  # answers from router or public resolver
            self._learn_answers(pkt[DNS])

        if not is_lan_ip(ip.src):
            return                           # inbound traffic: nothing more to learn
        mac = pkt[Ether].src.lower()
        if not self._see_device(mac, ip.src, ts):
            return

        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
            self._dns_query(mac, _qname(pkt[DNS]), ts)

        if TCP in pkt:
            f = int(pkt[TCP].flags)
            if f & 0x02 and not f & 0x10:    # SYN without ACK = new outbound connection
                self._destination(mac, ip.dst, pkt[TCP].dport, "tcp", ts)
        elif UDP in pkt:
            self._destination(mac, ip.dst, pkt[UDP].dport, "udp", ts)

    # ----------------------------------------------------------------- devices
    def _see_device(self, mac, ip, ts):
        """Register/refresh a device. False means: not a real unicast device, ignore."""
        if int(mac[:2], 16) & 1:             # multicast/broadcast source
            return False
        d = self.devices.get(mac)
        if d is None:
            learning = ts < self.learning_until
            learn_until = self.learning_until if learning else ts + self.grace
            randomised = int(bool(int(mac[:2], 16) & 2))
            self.conn.execute(
                "INSERT INTO devices(mac, ip, randomised, first_seen, last_seen, learn_until) "
                "VALUES(?,?,?,?,?,?)", (mac, ip, randomised, ts, ts, learn_until))
            self.conn.commit()
            self.devices[mac] = {"ip": ip, "last_seen": ts, "learn_until": learn_until}
            if not learning:
                note = " It uses a randomised (private) Wi-Fi address, so it may be a known phone or laptop." if randomised else ""
                self._alert(mac, "new_device", "high", "New device on the network", f"{mac} appeared at {ip}.{note}")
        else:
            d["ip"], d["last_seen"] = ip, ts
            self._dirty.add(mac)
        return True

    def _quiet(self, mac, ts):
        return ts < self.devices[mac]["learn_until"]

    # --------------------------------------------------------------------- DNS
    def _learn_answers(self, dns):
        if not dns.qd or not dns.ancount:
            return
        domain = base_domain(_qname(dns))
        for i in range(dns.ancount):
            rr = dns.an[i]
            if getattr(rr, "type", None) == 1:           # A record
                self.ip_to_domain[str(rr.rdata)] = domain
        if len(self.ip_to_domain) > MAX_DNS_MAP:
            self.ip_to_domain.clear()

    def _dns_query(self, mac, qname, ts):
        if qname.endswith(SKIP_SUFFIXES):
            return
        domain = base_domain(qname)
        if (mac, domain) in self.known_dns:
            return
        self.known_dns.add((mac, domain))
        self.conn.execute("INSERT OR IGNORE INTO dns_seen VALUES(?,?,?)", (mac, domain, ts))
        self.conn.commit()
        if not self._quiet(mac, ts):
            self._alert(mac, "new_domain", "medium", "Device asked for a new domain",
                        f"{self._name(mac)} looked up {domain} for the first time.")

    # ------------------------------------------------------------ destinations
    def _destination(self, mac, dst_ip, port, proto, ts):
        if not is_outside_ip(dst_ip):
            return
        domain = self.ip_to_domain.get(dst_ip)
        dest = domain or dst_ip
        key = (mac, dest, port)
        if key in self.known_dest:
            return
        self.known_dest.add(key)
        self.conn.execute("INSERT OR IGNORE INTO dest_seen VALUES(?,?,?,?,?,?)",
                          (mac, dest, port, proto, int(domain is None), ts))
        self.conn.commit()
        # Domains are already covered by new_domain; only raw IPs are suspicious here.
        if domain is None and not self._quiet(mac, ts):
            self._alert(mac, "unexplained_destination", "high", "Connection to unexplained server",
                        f"{self._name(mac)} connected to {dst_ip}:{port}/{proto} "
                        f"with no DNS lookup behind it.")

    # ---------------------------------------------------------------- plumbing
    def _name(self, mac):
        row = self.conn.execute("SELECT label, ip FROM devices WHERE mac=?", (mac,)).fetchone()
        if row and row["label"]:
            return f'{row["label"]} ({mac})'
        return f'{mac} ({row["ip"]})' if row else mac

    def _alert(self, mac, kind, severity, title, message):
        self.conn.execute(
            "INSERT INTO alerts(ts, mac, kind, severity, message) VALUES(?,?,?,?,?)",
            (time.time(), mac, kind, severity, message))
        self.conn.commit()
        print(f"[ALERT] {kind}: {message}")
        tags = {"high": "rotating_light", "medium": "warning", "low": "information_source"}[severity]
        self.notifier.send(f"netwatch: {title}", message, severity, tags)

    def flush(self, ts=None):
        ts = ts or time.time()
        for mac in self._dirty:
            d = self.devices[mac]
            self.conn.execute("UPDATE devices SET ip=?, last_seen=? WHERE mac=?",
                              (d["ip"], d["last_seen"], mac))
        self.conn.commit()
        self._dirty.clear()
        self._last_flush = ts


def _qname(dns) -> str:
    q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
    n = q.qname
    return n.decode(errors="replace") if isinstance(n, bytes) else str(n)
