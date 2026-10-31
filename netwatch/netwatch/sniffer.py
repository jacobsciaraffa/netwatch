"""Run the capture. Needs root (raw sockets):  sudo python -m netwatch.sniffer"""
import argparse
import os
import time

from scapy.all import sniff

from . import config, db
from .detector import Detector
from .notify import Notifier

# Kernel-level filter: ARP, all UDP (DNS, QUIC...), and only the first packet (SYN) of TCP flows.
BPF = "arp or udp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"


def _give_db_back_to_user():
    """Under sudo the database is created as root, which locks the dashboard out.
    Hand the files to the user who ran sudo."""
    sudo_uid = os.environ.get("SUDO_UID")
    if os.geteuid() == 0 and sudo_uid:
        gid = int(os.environ.get("SUDO_GID", sudo_uid))
        for suffix in ("", "-wal", "-shm"):
            path = config.DB_PATH + suffix
            if os.path.exists(path):
                os.chown(path, int(sudo_uid), gid)


def main():
    p = argparse.ArgumentParser(description="netwatch sniffer")
    p.add_argument("-i", "--iface", default=config.IFACE, help="interface to capture on")
    p.add_argument("--relearn", action="store_true", help="restart the learning period now")
    p.add_argument("--test-notify", action="store_true", help="send one test notification and exit")
    args = p.parse_args()

    notifier = Notifier(config.NTFY_URL, config.NTFY_TOPIC, config.DASHBOARD_URL,
                        config.MAX_NOTIFICATIONS_PER_HOUR)
    if args.test_notify:
        ok = notifier.send("netwatch: test", "If you can read this, phone alerts work.", "low", "white_check_mark")
        print("sent" if ok else "NOT sent (is NETWATCH_NTFY_TOPIC set? is the network reachable?)")
        return

    conn = db.connect(config.DB_PATH)
    _give_db_back_to_user()
    if args.relearn or db.get_meta(conn, "learning_until") is None:
        db.set_meta(conn, "learning_until", time.time() + config.LEARNING_HOURS * 3600)
        db.set_meta(conn, "learning_announced", "0")
    learning_until = float(db.get_meta(conn, "learning_until"))

    det = Detector(conn, notifier, learning_until, config.NEW_DEVICE_GRACE_HOURS)
    left = (learning_until - time.time()) / 3600
    print(f"Learning for another {left:.1f}h (alerts start after that)." if left > 0
          else "Learning finished, alerting is live.")

    announced = db.get_meta(conn, "learning_announced") == "1"

    def on_packet(pkt):
        nonlocal announced
        det.handle_packet(pkt)
        if not announced and time.time() >= learning_until:
            announced = True
            db.set_meta(conn, "learning_announced", "1")
            notifier.send("netwatch: learning finished",
                          "Baseline built. You'll now get alerts for anything new.", "low", "mortar_board")

    try:
        sniff(iface=args.iface, filter=BPF, prn=on_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        det.flush()


if __name__ == "__main__":
    main()
