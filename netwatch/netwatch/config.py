"""All settings come from environment variables, with safe defaults."""
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = os.environ.get("NETWATCH_DB", str(_ROOT / "netwatch.db"))
IFACE = os.environ.get("NETWATCH_IFACE") or None          # None = scapy default

# How long to observe silently before alerting starts.
LEARNING_HOURS = float(os.environ.get("NETWATCH_LEARNING_HOURS", 72))
# A device first seen AFTER learning ends gets its own quiet period, so one
# new phone doesn't fire 200 "new domain" alerts while it sets itself up.
NEW_DEVICE_GRACE_HOURS = float(os.environ.get("NETWATCH_NEW_DEVICE_GRACE_HOURS", 24))

# Phone notifications through ntfy (https://ntfy.sh or your own server).
NTFY_URL = os.environ.get("NETWATCH_NTFY_URL", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.environ.get("NETWATCH_NTFY_TOPIC", "")    # empty = notifications off
MAX_NOTIFICATIONS_PER_HOUR = int(os.environ.get("NETWATCH_MAX_NOTIFS_PER_HOUR", 20))

# Dashboard.
DASHBOARD_HOST = os.environ.get("NETWATCH_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("NETWATCH_DASHBOARD_PORT", 8080))
# Optional: tapping a phone notification opens this URL.
DASHBOARD_URL = os.environ.get("NETWATCH_DASHBOARD_URL", "")
