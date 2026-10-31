"""SQLite storage. The sniffer writes, the dashboard reads (WAL lets both run at once)."""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- One row per MAC address ever seen on the LAN.
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    label       TEXT,              -- friendly name, set from the dashboard
    randomised  INTEGER NOT NULL,  -- 1 = locally administered (private Wi-Fi address)
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    learn_until REAL NOT NULL      -- no per-device alerts before this time
);

-- Baseline: which domains each device has looked up.
CREATE TABLE IF NOT EXISTS dns_seen (
    mac        TEXT NOT NULL,
    domain     TEXT NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (mac, domain)
);

-- Baseline: which outside destinations each device has connected to.
-- dest is a domain when a DNS answer explains the IP, otherwise the raw IP.
CREATE TABLE IF NOT EXISTS dest_seen (
    mac        TEXT NOT NULL,
    dest       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL,
    raw_ip     INTEGER NOT NULL,   -- 1 = no DNS lookup explained this destination
    first_seen REAL NOT NULL,
    PRIMARY KEY (mac, dest, port)
);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    mac      TEXT NOT NULL,
    kind     TEXT NOT NULL,        -- new_device | new_domain | unexplained_destination
    severity TEXT NOT NULL,        -- high | medium | low
    message  TEXT NOT NULL,
    acked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    conn.commit()
