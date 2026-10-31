# Build netwatch from scratch: a Python tutorial

By the end you will have typed every file in this repository yourself and be able to explain every line, every Python feature it uses, and every networking idea behind it.

## How to use this tutorial

**Assumed level.** You can read basic Python: variables, `if`, `for`, functions, lists, dicts. Everything beyond that (classes, modules, comprehensions, decorators, SQL, Flask, bit operations, packet parsing) is explained here when it first appears.

**The rules that make it work:**

1. **Type the code. Do not paste it.** Typing forces you to read every character. The finished version lives in the repo; compare yours against it after each chapter.
2. **Run something after every chapter.** Each chapter ends with a "Try it" step. If it doesn't work, stop and fix it before moving on, because later chapters build on it.
3. **Answer the "Check yourself" questions before reading the answers.** If you can't answer one, reread that chapter. Do not move on with a gap.
4. **Use the REPL.** Open it with `python` (or `.venv/bin/python` once the venv exists). Most concepts are clearest when you type them in and see the result.

**The finished system:**

```
 Network traffic
       │
       ▼
 sniffer.py ───► detector.py ───► SQLite (netwatch.db) ◄─── dashboard.py ◄── your browser
 (Scapy, root)   (the rules)            │
                       │                │
                       └──► notify.py ──┴──► your phone (ntfy)

 config.py (settings) is used by all of them. db.py opens the database for all of them.
```

**Chapters:**

| # | Chapter | New Python | New networking / security idea |
|---|---|---|---|
| 1 | Network concepts | none | MAC, IP, ARP, DNS, TCP, UDP, capture position |
| 2 | Project setup | venv, pip, packages, imports | |
| 3 | `config.py` | environment variables, `pathlib` | secrets stay out of code |
| 4 | `db.py` | SQLite, SQL, transactions | SQL injection |
| 5 | Scapy | packet objects, bytes, bit operations | BPF filters |
| 6 | `detector.py` | classes, comprehensions, sets | baselining, false positives |
| 7 | `notify.py` | HTTP with `requests`, `deque`, `try/except` | rate limiting |
| 8 | `sniffer.py` | `argparse`, closures, `finally` | privileges and file ownership |
| 9 | `dashboard.py` | Flask, decorators, Jinja | XSS, why there is no login |
| 10 | Tests | `pytest`, fixtures, test doubles | |
| 11 | Wrap-up | | self-test and extensions |

---

# Chapter 1: The network concepts (no code yet)

You cannot write a network detector without knowing what a packet is. Read this chapter slowly. Every later chapter leans on it.

## 1.1 A packet is a stack of envelopes

Data on a network travels in **packets**. Each packet is wrapped in layers, like envelopes inside envelopes. Each layer adds an address for a different job.

```
┌───────────────────────────────────────────────────────────┐
│ Ethernet layer   src MAC, dst MAC        (device → device on the same LAN)
│ ┌───────────────────────────────────────────────────────┐ │
│ │ IP layer       src IP, dst IP          (host → host across networks)
│ │ ┌───────────────────────────────────────────────────┐ │ │
│ │ │ TCP or UDP   src port, dst port      (which program/service)
│ │ │ ┌───────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload    DNS question, HTTPS data, ...         │ │ │ │
│ │ │ └───────────────────────────────────────────────┘ │ │ │
│ │ └───────────────────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

Scapy represents exactly this: one Python object per layer, stacked together. You will see it in Chapter 5.

## 1.2 MAC addresses identify devices on the LAN

A **MAC address** looks like `b0:be:83:2b:28:6c`. It is six bytes written in hexadecimal. It identifies a network card on the local network. netwatch uses the MAC as the device's identity, because an IP address can change (DHCP hands them out) but a MAC usually does not.

The **first byte** carries two flags, in its lowest two bits:

```
 first byte of the MAC, written in binary:      x x x x x x [L] [M]
                                                             │   └─ M = 1: multicast/broadcast address
                                                             └───── L = 1: "locally administered" (randomised)
```

- **M bit (value 1).** A packet *from* a device never has this set. If you see it, it is not a real device.
- **L bit (value 2).** Phones and laptops now generate random MAC addresses per Wi-Fi network for privacy ("private address"). They set this bit. So a MAC whose second hex digit is `2`, `6`, `a`, or `e` is randomised.

Example: `da:11:...` → `0xda` is `11011010` in binary. The last two bits are `10`, so M = 0, L = 1: a unicast, randomised address. You will write the code that tests these bits in Chapter 6.

## 1.3 IP addresses: inside and outside

An **IP address** like `192.168.1.10` identifies a host. Three kinds matter here:

- **Private (LAN) addresses**: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`. These only exist inside your home. Your devices have these.
- **Public (global) addresses**: everything else, like `8.8.8.8`. These are servers on the internet.
- **Special**: loopback `127.x`, link-local `169.254.x`, multicast `224+`, `0.0.0.0`. netwatch ignores these.

Your router performs **NAT**: it rewrites private source addresses to its one public address when traffic leaves. That is why *where you capture* matters (section 1.7).

## 1.4 ARP: "who has this IP?"

Before one device can send to another on the LAN it needs the other's MAC. It **broadcasts** an ARP question to everyone: "Who has 192.168.1.1?" The owner replies "I do, my MAC is ...".

ARP matters to netwatch because ARP broadcasts reach every device on the LAN, even on a switched or Wi-Fi network where you can't see other devices' normal traffic. So ARP is how a plain laptop can still discover that a new device has joined.

## 1.5 DNS: names to addresses

Humans use names (`api.samsung.com`). Computers need IPs. A device first asks a DNS server:

```
 TV ── UDP port 53: "what is api.samsung.com?" ────────────► router / resolver
 TV ◄── UDP port 53: "api.samsung.com = 203.0.113.9" ───────  router / resolver
 TV ── TCP port 443: connect to 203.0.113.9 ────────────────► the server
```

Key facts used in the code:

- A DNS **query** and a DNS **response** are both DNS packets. A flag called `qr` says which: `qr = 0` is a question, `qr = 1` is an answer.
- An **A record** is an answer that maps a name to an IPv4 address. A response can hold several records, including **CNAME** records (an alias such as `www.x.com` → `cdn.y.net`).
- netwatch remembers every IP that a DNS answer mentioned, so it can later say "this connection to 203.0.113.9 is explained: the device asked for `samsung.com` a moment ago." A connection to an IP *with no lookup behind it* is suspicious. Malware and some IoT firmware use hard-coded IPs.
- A name like `cdn.eu.samsung.com` has many sub-domains. We care about the **base domain** (`samsung.com`), otherwise a streaming app would trigger a thousand alerts. Base domains usually are the last two labels, except under suffixes like `.com.au` or `.co.uk`, where it is the last three.

## 1.6 TCP, UDP and the SYN packet

- **UDP** just sends. DNS and QUIC use it.
- **TCP** sets up a connection first, with a three-step handshake:

```
 client ── SYN ───────────► server      "I'd like to connect"
 client ◄── SYN + ACK ───── server      "OK"
 client ── ACK ───────────► server      "Connected"
```

SYN and ACK are **flags**: single bits in the TCP header. A packet with SYN set and ACK *not* set is the very first packet of a new connection. netwatch only wants that one packet per connection, which is far cheaper than capturing every packet. You will see the bit test in Chapter 5.

## 1.7 Capture position: what can you actually see?

A network card normally ignores packets addressed to other devices. And on a switched network, packets are only delivered to their destination anyway. So a program on your laptop sees:

```
 Laptop on Wi-Fi sees:                  Laptop on Wi-Fi does NOT see:
 ───────────────────────────────        ───────────────────────────────
 its own DNS + connections (all)        other devices' DNS and connections
 broadcasts/multicast (ARP, mDNS)
```

To see everyone's traffic you must sit where it flows: on the router, or on a switch **mirror port** (the switch copies all traffic to one port). This is a physical constraint. No code can get around it.

```
 Modem/Router ──► Managed switch ──► Wi-Fi access point ──► your devices
                       │  (mirror port)
                       └─► machine running netwatch
```

## 1.8 The detection idea: a baseline of "first seen"

netwatch does not know what "bad" is. It learns what is *normal* for each device, then flags *new* things. The whole detector is a set of "have I seen this before?" questions:

```
 phase 1: LEARNING (default 72 h)    record everything silently
 phase 2: ALERTING                   first time something new appears → alert once → add to baseline
```

Three questions, three alerts:

| Question | Alert |
|---|---|
| Have I seen this MAC before? | `new_device` |
| Has this device asked for this domain before? | `new_domain` |
| Has this device connected to this server before, and did DNS explain it? | `unexplained_destination` |

## Check yourself: Chapter 1

1. What is the difference between `qr = 0` and `qr = 1` in a DNS packet?
2. Why does netwatch use the MAC address, not the IP address, to identify a device?
3. The MAC `3e:aa:bb:cc:dd:ee` starts with `0x3e` = `00111110`. Is it multicast? Is it randomised?
4. Why does a laptop on Wi-Fi still see new devices join, but not see what the smart TV is doing?
5. Why only capture the SYN packet of a TCP connection?

<details><summary>Answers</summary>

1. `qr = 0` is a question (a device asking for a name). `qr = 1` is an answer (a server replying).
2. IPs are handed out by DHCP and can change; a MAC normally stays with the hardware.
3. Last two bits are `10`: M = 0 (not multicast), L = 1 (randomised).
4. ARP and similar broadcasts reach everyone. Other devices' unicast traffic is never delivered to your laptop.
5. The SYN marks the start of a connection. Capturing only that gives one packet per connection instead of thousands, so it is far cheaper.

</details>

---

# Chapter 2: Project setup

**Goal:** an empty project that can run Python code from a package, with an isolated set of libraries.

## 2.1 New concepts

**Virtual environment (venv).** A private folder holding a copy of the Python interpreter and its own installed libraries. Without it, `pip install` puts libraries in your system Python and different projects fight over versions. With it, each project has its own. You *activate* it so that `python` and `pip` mean "the ones inside this folder".

**pip and requirements.txt.** `pip` installs libraries from PyPI. A `requirements.txt` file lists what the project needs so anyone can recreate the setup with one command.

**Module, package, `__init__.py`.** A **module** is a single `.py` file. A **package** is a folder of modules that contains a file named `__init__.py` (it can be empty or hold a one-line docstring). A package lets you write `from netwatch import config`.

**Absolute vs relative imports.**
- `from netwatch import config` is absolute: it starts at the top of the package.
- `from . import config` is relative: the dot means "this package". Inside the package we use relative imports so the code keeps working even if you rename the package folder.

**`python -m`.** Running `python netwatch/sniffer.py` runs the file as a loose script, and relative imports break (Python doesn't know it belongs to a package). Running `python -m netwatch.sniffer` tells Python "run this module as part of the `netwatch` package", and relative imports work. This is why every command in this project uses `-m`.

## 2.2 Build it

```zsh
mkdir -p netwatch-tutorial && cd netwatch-tutorial     # the project folder
python3 -m venv .venv                                  # create the virtual environment
source .venv/bin/activate                              # activate it (prompt shows (.venv))
```

Create the layout:

```
netwatch-tutorial/
  requirements.txt
  netwatch/              <- the package
    __init__.py
    templates/           <- HTML later
  tests/
    __init__.py
```

```zsh
mkdir -p netwatch/templates tests
touch netwatch/__init__.py tests/__init__.py
```

Put this in `netwatch/__init__.py`:

```python
# netwatch/__init__.py
"""netwatch: learn what normal looks like on a home network, alert on what doesn't."""
```

And this in `requirements.txt`:

```text
scapy>=2.5
flask>=3.0
requests>=2.31
pytest>=8.0
```

Install:

```zsh
python -m pip install -r requirements.txt
```

We use `python -m pip` instead of plain `pip` so the install is guaranteed to go to the Python you are running. (Using bare `pip` can install into a different Python. This is exactly what produced your earlier `No module named 'scapy'` error.)

What each library is for:

| Library | Used for |
|---|---|
| `scapy` | reading and building network packets |
| `flask` | the web dashboard |
| `requests` | sending the phone notification (HTTP) |
| `pytest` | running tests |

## 2.3 Try it

```zsh
python -c "import scapy, flask, requests; print('all imports work')"
python -c "import netwatch; print(netwatch.__doc__)"
```

The second command prints the docstring from `__init__.py`. That proves Python sees `netwatch` as a package.

## Check yourself: Chapter 2

1. What problem does a virtual environment solve?
2. Why run `python -m netwatch.sniffer` rather than `python netwatch/sniffer.py`?
3. What does the `.` in `from . import config` mean?
4. What file turns a folder into a package?

<details><summary>Answers</summary>

1. It gives each project its own libraries, so projects don't conflict and your system Python stays clean.
2. Relative imports (`from . import ...`) only work when Python knows the file is inside a package. `-m` provides that.
3. "The current package", i.e. the folder this file is in.
4. `__init__.py`.

</details>

---

# Chapter 3: `config.py`: settings from the environment

**Goal:** one place that holds every setting, which you can change without editing code.

## 3.1 New concepts

**Environment variables.** Key/value text settings attached to a running process, set in your shell with `export NAME=value`. Programs read them. They are the standard way to configure software because:
- you change behaviour without editing code,
- secrets (like your ntfy topic) stay out of the files you commit to GitHub,
- the same code runs on your Mac and on a Raspberry Pi with different settings.

**Everything from the environment is a string.** `os.environ.get("X")` returns `"72"`, not the number 72. You must convert with `float(...)` or `int(...)`.

**`dict.get(key, default)`.** Returns the default if the key is missing, instead of crashing. `os.environ` behaves like a dict.

**`pathlib.Path`.** An object-oriented way to handle file paths. `__file__` is a special variable holding the path of the current source file.

**Truthiness.** In Python, empty strings, `0`, `None`, empty lists/dicts are *falsy*. Anything else is *truthy*. `x or y` returns `x` if it is truthy, otherwise `y`.

**Constants.** `UPPER_CASE` names signal "set once, don't change". Python doesn't enforce this; it is a convention.

## 3.2 The code

```python
# netwatch/config.py
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
```

## 3.3 Walkthrough

**Paths.**
```python
_ROOT = Path(__file__).resolve().parent.parent
```
Read it from the left: `__file__` is `.../netwatch/netwatch/config.py`. `Path(...)` wraps it. `.resolve()` makes it absolute and removes `..` tricks. `.parent` is the folder containing the file (the package folder). A second `.parent` is the project folder. The leading underscore on `_ROOT` means "internal to this module".

**Defaults with conversion.**
```python
LEARNING_HOURS = float(os.environ.get("NETWATCH_LEARNING_HOURS", 72))
```
Evaluated inside-out: get the variable (or the default `72`), then `float()` it. If you export `NETWATCH_LEARNING_HOURS=0.1`, you get the number `0.1`. If it isn't set, you get `72.0`.

**`or None`.**
```python
IFACE = os.environ.get("NETWATCH_IFACE") or None
```
If the variable is unset, `.get` returns `None` already. If it is set but empty (`NETWATCH_IFACE=`), you'd get `""`. `"" or None` gives `None`. The result: "no interface chosen" is always `None`, never an empty string.

**`.rstrip("/")`.** Removes trailing slashes so we can safely build `f"{url}/{topic}"` later without producing `//`.

**Read at import time.** These lines run once, when the module is first imported. That means the environment variable must be set *before* the program starts. Changing it afterwards has no effect on a running program.

## 3.4 Try it

```zsh
python -c "from netwatch import config; print(config.LEARNING_HOURS, type(config.LEARNING_HOURS))"
NETWATCH_LEARNING_HOURS=0.1 python -c "from netwatch import config; print(config.LEARNING_HOURS)"
python -c "from netwatch import config; print(config.DB_PATH)"
```

Expected: `72.0 <class 'float'>`, then `0.1`, then an absolute path ending in `netwatch.db`.

## Check yourself: Chapter 3

1. What does `os.environ.get("X", 5)` return if `X` is set to `"9"`? What type is it?
2. Why is `float(...)` needed?
3. What is the value of `"" or None`? Of `"abc" or None`?
4. You `export NETWATCH_NTFY_TOPIC=abc` *after* starting the sniffer. Does the running sniffer notice? Why not?

<details><summary>Answers</summary>

1. The string `"9"`. The default `5` is only used when the variable is missing.
2. Environment variables are always strings, and we need numbers for arithmetic and comparisons.
3. `None`, and `"abc"`.
4. No. `config.py` reads the environment once, at import time. You must restart the sniffer.

</details>

---

# Chapter 4: `db.py`: storing the baseline in SQLite

**Goal:** a small module that creates the database tables and opens connections.

## 4.1 New concepts

**Database, table, row, column.** A relational database stores data in **tables**. Each **row** is one record, each **column** is one field. Think of a spreadsheet with strict column types.

**SQLite.** A database in a single file (`netwatch.db`). No server to install: Python includes the `sqlite3` module. Perfect for a small project.

**Primary key.** The column (or combination of columns) that uniquely identifies a row. The database refuses duplicates. `devices` uses `mac` as its key. `dns_seen` uses the *pair* `(mac, domain)`: a **composite key**, so each device/domain combination can only exist once. This is what makes "have I seen this before?" safe.

**SQL statements you will meet:**

| Statement | Does |
|---|---|
| `CREATE TABLE IF NOT EXISTS` | makes a table, but only if it's missing (safe to run on every start) |
| `INSERT INTO t(a,b) VALUES(?,?)` | adds a row |
| `INSERT OR IGNORE ...` | adds a row, but silently skips it if the key already exists |
| `SELECT ... FROM t WHERE ...` | reads rows |
| `UPDATE t SET a=? WHERE ...` | changes rows |
| `ON CONFLICT(key) DO UPDATE SET ...` | "upsert": insert, or update if the key exists |

**Transaction and `commit()`.** Changes are held in a pending transaction until you call `conn.commit()`. Only then are they saved to disk and visible to other connections. Forgetting `commit()` is the most common SQLite bug: your program seems to work, but the data is gone.

**Parameterised queries (`?`).** Never build SQL by gluing strings together. See 4.4.

**WAL mode.** By default a writer blocks readers. `PRAGMA journal_mode=WAL` (write-ahead log) lets one writer and many readers work at once. We need this because the sniffer writes while the dashboard reads.

**`row_factory = sqlite3.Row`.** By default a row is a plain tuple, accessed by position (`row[2]`). With `sqlite3.Row` you can use names (`row["mac"]`), which is far more readable.

**Python:** triple-quoted strings (`""" ... """`) hold multi-line text, so the SQL stays readable; default arguments (`default=None`); a conditional expression (`A if condition else B`); type hints (`path: str`, `-> sqlite3.Connection`). Hints document the code and help editors; Python does **not** enforce them.

## 4.2 The code

```python
# netwatch/db.py
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
```

## 4.3 Walkthrough, table by table

**`meta`** is a simple key/value store (`learning_until`, `learning_announced`). Small facts that don't deserve their own table.

**`devices`** has one row per MAC:
- `randomised` is 0 or 1 (SQLite has no true boolean).
- `first_seen`, `last_seen` are `REAL`: Unix timestamps (seconds since 1 Jan 1970, as returned by `time.time()`). Storing numbers makes comparing times trivial: `ts < learn_until`.
- `learn_until` is the per-device quiet period from Chapter 1.8: before this time, the device may not raise alerts.

**`dns_seen`** is the domain baseline. The composite primary key `(mac, domain)` means the same pair can't be inserted twice.

**`dest_seen`** is the server baseline: `(mac, dest, port)`. `dest` is a domain if DNS explained the IP, otherwise the raw IP. `raw_ip` records which.

**`alerts`**: `INTEGER PRIMARY KEY AUTOINCREMENT` makes SQLite number rows 1, 2, 3 for you. `acked DEFAULT 0` means a new alert starts as "not dismissed". The `CREATE INDEX` line builds a lookup structure so `ORDER BY ts DESC` (newest first) stays fast when there are thousands of alerts.

**`connect()`**:
1. `sqlite3.connect(path, timeout=10)` opens (or creates) the file. `timeout=10` means "if another process has the database locked, wait up to 10 seconds before failing".
2. `row_factory` enables name access.
3. `PRAGMA journal_mode=WAL` enables WAL.
4. `executescript(SCHEMA)` runs every `CREATE` statement. Because they say `IF NOT EXISTS`, running it on an existing database changes nothing. That is how the program upgrades "no database" to "database" automatically.

**`get_meta`** uses `fetchone()`, which returns one row or `None`. The line
```python
return row["value"] if row else default
```
means: if a row was found, return its value; otherwise return the default.

**`set_meta`** is an upsert. `excluded.value` refers to the value you tried to insert. So: insert the key, or if the key already exists, overwrite its value.

## 4.4 Why `?` and never f-strings: SQL injection

The domains and device names in this project come from the network. **Attackers control them.** A device can send a DNS query for any name it likes. Suppose we wrote:

```python
conn.execute(f"INSERT INTO dns_seen VALUES('{mac}', '{domain}', {ts})")   # DANGEROUS
```

and a device looked up the "domain" `x'); DROP TABLE alerts; --`. The string would become SQL and run. This is **SQL injection**.

With placeholders:

```python
conn.execute("INSERT INTO dns_seen VALUES(?,?,?)", (mac, domain, ts))      # SAFE
```

the values are sent separately from the SQL text, so they can only ever be data. Every query in this project uses `?`. Make it a lifelong habit.

## 4.5 Try it

Type this into the REPL (`python`):

```python
import time
from netwatch import db

conn = db.connect("/tmp/practice.db")
conn.execute("INSERT INTO devices(mac, ip, randomised, first_seen, last_seen, learn_until) "
             "VALUES(?,?,?,?,?,?)", ("aa:bb:cc:dd:ee:ff", "192.168.1.5", 0, time.time(), time.time(), 0))
conn.commit()

row = conn.execute("SELECT * FROM devices").fetchone()
print(row["mac"], row["ip"])          # access by name
print(tuple(row))                      # the same row as a plain tuple

db.set_meta(conn, "colour", "blue")
print(db.get_meta(conn, "colour"))     # blue
print(db.get_meta(conn, "missing", "fallback"))   # fallback

try:                                   # duplicate primary key is refused
    conn.execute("INSERT INTO devices(mac, ip, randomised, first_seen, last_seen, learn_until) "
                 "VALUES('aa:bb:cc:dd:ee:ff','x',0,0,0,0)")
except Exception as e:
    print(type(e).__name__, e)
```

The last block should print an `IntegrityError`. That error is the database enforcing "this MAC exists once". Now run `INSERT OR IGNORE` with the same MAC and notice that nothing happens and nothing breaks. Delete `/tmp/practice.db*` when you are done.

## Check yourself: Chapter 4

1. What does the composite key `(mac, domain)` guarantee?
2. You `INSERT` a row but forget `commit()`. The program exits. Is the row saved?
3. Why do we need WAL mode here?
4. What does `row["value"] if row else default` do when `row` is `None`?
5. Why is `f"... '{domain}' ..."` in a SQL query dangerous in *this* project specifically?

<details><summary>Answers</summary>

1. A given device can have a given domain only once in the table.
2. No. Without `commit()` the transaction is discarded.
3. The sniffer writes while the dashboard reads; WAL lets them do both at once without blocking.
4. Returns `default`.
5. Domain names come from packets that any device (including a compromised one) can craft, so the text could contain SQL.

</details>

---

# Chapter 5: Scapy, bytes and bit operations

**Goal:** understand how a captured packet becomes Python objects, and the two bit tricks the detector uses. There is no project file in this chapter; you will experiment in the REPL.

## 5.1 New concepts

**Scapy** turns raw network bytes into Python objects (one per layer) and can build packets from scratch.

**Packets are just bytes.** A network card hands Scapy a block of bytes. Scapy reads the bytes in order: "first 14 bytes are Ethernet... next bytes are IP..." and builds a layer object for each.

**Operator overloading.** Scapy gives the `/` operator a new meaning for packets: `Ether()/IP()/UDP()` *stacks* layers. (In normal Python `/` is division; classes can redefine operators.)

**`in` and `[]` on packets.** `IP in pkt` asks "does this packet have an IP layer?" `pkt[IP]` returns that layer so you can read `pkt[IP].src`.

**`bytes` vs `str`.** Network data is bytes: `b'www.example.com.'`. Python text is `str`: `'www.example.com.'`. Convert with `.decode()`. Packet contents are attacker-controlled, so we decode with `errors="replace"` (bad bytes become `?` instead of crashing).

**Hexadecimal and bit operations.**
- `0x02` is the number 2 written in hex. `0x10` is 16. A byte is two hex digits: `0xda` = 218.
- `int("da", 16)` parses a hex string.
- `&` is bitwise AND: result bit is 1 only where *both* inputs have 1.

```
   0xda      = 1 1 0 1 1 0 1 0
   & 0x02    = 0 0 0 0 0 0 1 0
   ─────────────────────────────
   result    = 0 0 0 0 0 0 1 0   → non-zero → "the L bit is set"
```

A result that is non-zero is truthy, so `if value & 0x02:` reads as "if that bit is on".

**BPF (Berkeley Packet Filter).** A tiny filter language that runs inside the operating system. Packets that don't match are dropped *before* they reach Python, which is much cheaper than filtering in Python.

## 5.2 Experiments (type these in the REPL)

**Build and inspect a packet.**

```python
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR

pkt = Ether(src="00:11:22:33:44:55") / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="api.samsung.com"))

pkt.show()                      # prints every layer and field
print(IP in pkt, TCP in pkt)     # True False
print(pkt[IP].src, pkt[UDP].dport)
print(pkt[DNS].qr)              # 0: it's a question
print(pkt[DNS].qd[0].qname)     # b'api.samsung.com.'  <- bytes, with a trailing dot
```

**Packets are bytes.**

```python
raw = bytes(pkt)                # what would go over the wire
print(len(raw), raw[:20])
parsed = Ether(raw)             # Scapy turns the bytes back into layers
print(parsed[IP].dst)           # 192.168.1.1
```

This round trip is exactly what happens when the sniffer captures a packet.

**A DNS answer with several records.**

```python
from scapy.all import DNSRR
resp = (Ether()/IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53)
        / DNS(qr=1, qd=DNSQR(qname="www.example.com"),
              an=DNSRR(rrname="www.example.com", type="CNAME", rdata="cdn.example.net")
                 / DNSRR(rrname="cdn.example.net", rdata="93.184.216.34"),
              ancount=2))
resp = Ether(bytes(resp))       # re-parse, like a real capture
d = resp[DNS]
print(d.ancount)                # 2
for i in range(d.ancount):
    rr = d.an[i]
    print(rr.type, rr.rdata)    # 5 b'cdn.example.net.'  then  1 93.184.216.34
```

`type == 1` is an A record (an IPv4 address); `5` is a CNAME. That is why the detector checks `type == 1`.

**Bit tests on TCP flags.**

```python
from scapy.all import TCP
syn     = int(TCP(flags="S").flags)      # 2
synack  = int(TCP(flags="SA").flags)     # 18
print(syn, synack, format(synack, "08b"))
for f in (syn, synack):
    print(f, "is a new connection" if (f & 0x02 and not f & 0x10) else "ignore")
```

`SYN = 0x02`, `ACK = 0x10`. "New connection" means SYN on and ACK off.

**Bit tests on MAC addresses.**

```python
for mac in ("00:11:22:33:44:55", "da:11:22:33:44:55", "01:00:5e:00:00:fb"):
    first = int(mac[:2], 16)         # first two hex characters → a number
    print(mac, format(first, "08b"), "multicast" if first & 1 else "unicast",
          "randomised" if first & 2 else "vendor")
```

**Capture a few real packets** (needs root, and a few seconds of normal browsing):

```zsh
sudo .venv/bin/python -c "from scapy.all import sniff; sniff(count=5, prn=lambda p: print(p.summary()))"
```

`lambda p: ...` is a one-line anonymous function. `prn` ("print/process") is the callback that Scapy calls for every packet. If macOS asks for permission, allow it.

## 5.3 The BPF filter we will use

```
arp or udp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)
```

Read it as: keep ARP packets; keep all UDP (that includes DNS and QUIC); keep TCP packets where, looking at the flags byte, SYN is on and ACK is off. It is the same bit test you just did in Python, but executed by the operating system so that thousands of irrelevant packets never reach your program.

## 5.4 Why sniffing needs root

Reading raw packets means opening a low-level device that the operating system protects. Normal programs can't do that; a root program can. Remember this: it is also why we keep the dashboard *out* of the root process.

## Check yourself: Chapter 5

1. What does `Ether()/IP()/UDP()` do, and why does `/` work for that?
2. What is the result of `0xda & 0x02`, and what does a non-zero result mean for a MAC?
3. `f = 18` (SYN+ACK). Is `f & 0x02 and not f & 0x10` true? Why?
4. Why does the code call `.decode(errors="replace")` on a DNS name?
5. Why filter with BPF instead of an `if` in Python?

<details><summary>Answers</summary>

1. It stacks layers into one packet. Scapy redefines the `/` operator for its packet classes.
2. `2` (non-zero). The "locally administered" bit is set, so the MAC is randomised.
3. False. `18 & 0x10` is non-zero, so `not` makes it false. It is the second packet of a handshake, not the first.
4. The bytes come from the network and could be malformed or malicious; `errors="replace"` swaps bad bytes for a placeholder instead of raising an error.
5. The filter runs in the operating system and discards unwanted packets before they reach Python, saving a lot of CPU.

</details>

---

# Chapter 6: `detector.py`, the heart of netwatch

This is the longest chapter because it holds all the logic. Take it in sections and run the tests (Chapter 10) once you have typed it. Everything before this chapter was preparation for this file.

## 6.1 Design first

Before any code, decide how the detector thinks.

**Rule 1: everything is a "first time seen" test.** For each device we keep sets of things we've already seen. A packet either matches the baseline (nothing to do) or is new (record it, maybe alert).

**Rule 2: two quiet periods.**
- *Global learning period*: after the very first start, record everything silently.
- *Per-device grace period*: a device that first appears **after** learning gets a quiet window (default 24 h) so it doesn't fire hundreds of alerts while it sets itself up.

**Rule 3: baseline lives in two places.** The database is permanent. A copy in Python memory (sets and dicts) makes the common case fast: for 99.9% of packets the answer is "seen it before", and answering that must not touch the disk. When something *new* appears we write to both.

```
                    packet arrives
                          │
   ┌── ARP? ────────────► register the sender as a device ──► done
   ├── no IP layer? ────► ignore
   ├── DNS answer? ─────► remember "IP → domain"           (then keep going)
   ├── source not LAN? ─► ignore (inbound traffic)
   ├── register device ─► multicast MAC? ignore
   ├── DNS question? ───► new domain for this device? ──► alert
   └── TCP SYN or UDP? ─► new server for this device? ──► alert only if the IP was never explained by DNS
```

## 6.2 New concepts in this chapter

- **Classes and objects.** A class bundles data (attributes) and behaviour (methods). `Detector(...)` creates an *instance*. `self` is the instance inside each method. Methods starting with `_` are internal by convention.
- **`__init__`.** The method Python runs when you create an instance. It sets up the starting state.
- **Sets.** Collections of unique items with very fast `in` checks. Perfect for "have I seen this?".
- **Tuples as keys.** `(mac, domain)` is immutable, so it can live in a set or be a dict key.
- **Comprehensions.** A compact loop that builds a list, set or dict.
- **Guard clauses.** Early `return` statements that exit a function when there's nothing to do, keeping the main logic un-indented.
- **Default arguments and `None`.** `ts=None` means "use the real clock unless told otherwise".

## 6.3 The module header

```python
# netwatch/detector.py
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
```

**Imports.** `ipaddress` and `time` come with Python. The `scapy.layers...` lines import the layer classes. `from X import A, B` brings in just those names.

**Constants.**
- `MULTI_SUFFIX` is a *set literal* (curly braces, comma-separated values). We only ask "is it in here?", so a set is ideal.
- `SKIP_SUFFIXES` is a *tuple* (round brackets). It has to be a tuple because `str.endswith()` accepts a tuple of options but not a set.
- `FLUSH_EVERY` and `MAX_DNS_MAP` are tuning numbers. The underscore in `50_000` is only for readability; Python ignores it.

## 6.4 `base_domain()`

```python
# netwatch/detector.py
def base_domain(name: str) -> str:
    name = name.rstrip(".").lower()
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
```

Step by step for `"a.b.samsung.com."`:

1. `name.rstrip(".")` removes the trailing dot DNS adds → `"a.b.samsung.com"`. `.lower()` makes the comparison case-insensitive.
2. `.split(".")` → `["a", "b", "samsung", "com"]`.
3. `len(parts) <= 2` means it is already a base domain (`example.com`), so return it.
4. `parts[-2:]` is a **negative slice**: the last two items → `["samsung", "com"]`. `".".join(...)` glues them back → `"samsung.com"`.
5. If those last two labels are a known two-part suffix (like `com.au`), the base domain needs *three* labels: `parts[-3:]`. So `www.abc.net.au` → `abc.net.au`.

Using `return` early in each branch means each case is handled once, with no nested `else` blocks.

This is a simplification. A complete solution uses the Public Suffix List; ours covers the common cases for an Australian home network.

## 6.5 `is_lan_ip()` and `is_outside_ip()`

```python
# netwatch/detector.py
def is_lan_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private and not (a.is_loopback or a.is_link_local
                                 or a.is_unspecified or a.is_multicast)


def is_outside_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global
```

`ipaddress.ip_address("192.168.1.5")` creates an object with helper properties: `.is_private`, `.is_global`, `.is_loopback`, `.is_multicast` and so on. The parentheses after `and not` let the expression span two lines.

`is_lan_ip` means "private, but not one of the special private-looking ranges". `is_outside_ip` uses `.is_global`.

> **A real bug we hit:** our first tests used `203.0.113.x` and `198.51.100.x`. Those are reserved *documentation* addresses. Python says `is_global` is **False** for them, so the detector silently ignored those connections and the test failed. We fixed the tests by using real public addresses. Lesson: when a test fails, the bug can be in the test's assumptions, and it's worth knowing *why* before changing anything.

## 6.6 The constructor

```python
# netwatch/detector.py
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
```

- `self.conn, self.notifier = conn, notifier` is *tuple unpacking*: two assignments in one line.
- `self.grace = new_device_grace_hours * 3600` converts hours to seconds, because every timestamp in the system is in seconds.
- `self.devices = {...}` is a **dict comprehension**. It reads: "for each row `r` in the query result, make an entry `r["mac"]: {...}`". The long way to write it:

```python
self.devices = {}
for r in conn.execute("SELECT mac, ip, last_seen, learn_until FROM devices"):
    self.devices[r["mac"]] = {"ip": r["ip"], "last_seen": r["last_seen"], "learn_until": r["learn_until"]}
```

- `self.known_dns = {(r["mac"], r["domain"]) for r in ...}` is a **set comprehension**: curly braces, no colon, one value per row. Each value is a tuple.
- On a restart these lines reload the whole baseline from the database. That is why netwatch remembers what it learned.
- `self.ip_to_domain` is deliberately **not** in the database. It's a short-lived hint (the IP a DNS answer gave a moment ago), not a permanent fact.
- `self._dirty` is a set of MACs whose `last_seen` changed in memory but hasn't been written yet (see `flush`).

## 6.7 `handle_packet()`: the entry point

```python
# netwatch/detector.py
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
```

Read it with the flow diagram from 6.1 beside it.

- **`ts=None` / `ts = ts or time.time()`.** Real use never passes `ts`, so it uses the clock. Tests pass fake timestamps, which lets us "fast-forward" three days in a millisecond. Designing code so that time can be injected is a core testing technique. (Edge case worth knowing: `ts or ...` also replaces a timestamp of `0`. A stricter version is `if ts is None: ts = time.time()`.)
- **Flush on a timer.** Every 30 seconds, write the pending `last_seen` updates in one go instead of on every packet.
- **ARP branch.** `ARP in pkt` is true for ARP packets. `a.op in (1, 2)` means request or reply. `a.hwsrc` / `a.psrc` are the sender's MAC and IP. We then `return`, because an ARP packet has no IP layer to analyse.
- **DNS answers are processed before the "is the source on the LAN?" check**, because answers often come from outside (a public resolver like 8.8.8.8), and we still want to learn from them.
- **`mac = pkt[Ether].src.lower()`**: for a packet *leaving* a LAN device, the Ethernet source is that device. `.lower()` normalises case so `AA:BB` and `aa:bb` are the same key.
- **`if not self._see_device(...): return`**: `_see_device` returns `False` for multicast MACs, and we stop there.
- **`pkt[DNS].qd`** is truthy when the question section isn't empty. The `and` stops us reading an empty list.
- **TCP vs UDP.** `elif UDP in pkt` only runs when it's not TCP. For TCP the code applies exactly the bit test from Chapter 5.

## 6.8 Devices

```python
# netwatch/detector.py
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
```

Walk through the first-time branch (`d is None`):

1. `learning = ts < self.learning_until` is a boolean: are we still in the global learning window?
2. `learn_until = self.learning_until if learning else ts + self.grace` is a **conditional expression**. During learning, the device is quiet until learning ends. After learning, it gets its own quiet period starting now.
3. `randomised = int(bool(int(mac[:2], 16) & 2))`: parse the first byte as hex, test the L bit (Chapter 5), turn the result into `True/False`, then into `1/0` for SQLite.
4. Insert the row, `commit()`, mirror it into `self.devices`.
5. Only if we are *not* learning do we raise a `new_device` alert. The `note` string is built with another conditional expression.

Else-branch: a known device. Update its IP and last-seen in memory and mark it dirty. No disk access.

`.get(mac)` returns `None` when the key is missing (a plain `self.devices[mac]` would raise `KeyError`), which is why the code can test `if d is None`.

## 6.9 DNS

```python
# netwatch/detector.py
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
```

**`_learn_answers`:**
- `dns.ancount` is how many answer records the packet holds. `dns.an[i]` is record number `i`.
- `getattr(rr, "type", None)` reads the attribute `type`, or gives `None` if the record has none. It is a safe way to read something that might not exist.
- `type == 1` selects A records. `str(rr.rdata)` is the IPv4 address as text.
- We map every answer IP to the domain the *question* asked for (`_qname(dns)`), not the record's own name. That way a CNAME chain like `www.x.com → cdn.y.net → 1.2.3.4` still maps the IP back to what the device originally requested.
- The cache is cleared if it grows past 50,000 entries. A cheap protection against unbounded memory growth. (Think about why that matters if an attacker floods you with DNS answers.)

**`_dns_query`:**
- `qname.endswith(SKIP_SUFFIXES)` ignores reverse lookups and local names.
- `(mac, domain) in self.known_dns` is the "seen it?" check. If yes, `return` (the common case, no disk).
- If new: add to the set, `INSERT OR IGNORE` into the database, `commit()`, then alert only if the device isn't in its quiet period.

## 6.10 Destinations

```python
# netwatch/detector.py
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
```

- Non-public destinations are ignored (`not is_outside_ip`): LAN-to-LAN traffic isn't interesting here.
- `domain = self.ip_to_domain.get(dst_ip)` → the domain or `None`. `dest = domain or dst_ip` is the **`or` idiom**: use the domain if there is one, otherwise the raw IP.
- The key includes the port, so a device that suddenly uses a new port on a known server is recorded as new.
- `int(domain is None)` turns `True/False` into `1/0` for the `raw_ip` column.
- **The important decision:** we alert only when `domain is None`. A connection to a known-by-DNS domain was already covered by `new_domain`, and alerting twice for the same event would be noise. A connection to an IP *no lookup explains* is the interesting case.

## 6.11 Plumbing

```python
# netwatch/detector.py
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
```

- **`_name`** builds a friendly string for alerts. It reads the label from the database each time (alerts are rare) so a name you set in the dashboard shows up immediately. If the in-memory copy held the label, it would go stale. This is a deliberate trade-off.
- **`_alert`** writes the alert row, prints it to your terminal, then notifies the phone. `{...}[severity]` is a dict used as a lookup table to choose an emoji tag name. The notifier object is *passed in*, so the detector doesn't know or care how notifications are delivered. This is why tests can pass a fake.
- **`flush`** writes all pending `last_seen` changes in one transaction then empties the dirty set. The sniffer also calls it on shutdown so nothing is lost.

```python
# netwatch/detector.py
def _qname(dns) -> str:
    q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
    n = q.qname
    return n.decode(errors="replace") if isinstance(n, bytes) else str(n)
```

`dns.qd` might be a list (with several questions) or one object depending on the Scapy version; `isinstance(dns.qd, list)` handles both. The name is `bytes`, so we decode it with `errors="replace"`.

## 6.12 Trace one event end to end

State: learning is over. The TV (`00:11:22:33:44:55`) is known. It sends a DNS question for `tracker.badsite.ru`.

1. `handle_packet` → there is an IP layer; it is a DNS question (`qr == 0`), so skip answer learning.
2. `is_lan_ip("192.168.1.10")` → true, continue. `mac` = the TV's MAC.
3. `_see_device` → TV is in `self.devices`, so refresh `ip`/`last_seen`, add to `_dirty`, return `True`.
4. `_dns_query(mac, "tracker.badsite.ru.", ts)` → not a skip suffix → `base_domain` → `badsite.ru`.
5. `("00:11:...", "badsite.ru")` is not in `known_dns` → add it, `INSERT OR IGNORE`, `commit`.
6. `_quiet(mac, ts)` → `ts` is after the TV's `learn_until` → `False`, so alert.
7. `_alert` → insert row into `alerts`, print, `notifier.send(...)` → your phone buzzes.
8. Next time the TV asks for `badsite.ru`, step 5 finds it in the set and returns silently.

Draw this trace on paper once from memory. If you can, you understand the detector.

## Check yourself: Chapter 6

1. Why keep a copy of the baseline in memory *and* in the database?
2. What does `base_domain("video.cdn.bbc.co.uk")` return, and which line decides that?
3. Why is `SKIP_SUFFIXES` a tuple and `MULTI_SUFFIX` a set?
4. Why does `handle_packet` take an optional `ts`?
5. A phone joins the network after learning and visits 50 new sites in its first hour. How many alerts fire, and why?
6. Why doesn't a connection to an IP that DNS explained raise `unexplained_destination`?
7. What is lost if the sniffer crashes before `flush()` runs?
8. What is the difference between `d is None` and `not d`? When would they differ here?

<details><summary>Answers</summary>

1. Memory makes the usual "seen it" check instant; the database makes the baseline survive restarts.
2. `bbc.co.uk`. The last two labels `co.uk` are in `MULTI_SUFFIX`, so it returns the last three labels.
3. `endswith` accepts a tuple but not a set. For `MULTI_SUFFIX` we only need fast membership tests, which sets give.
4. Tests (and replays) can supply their own time, so we can simulate days of traffic instantly and deterministically.
5. One (`new_device`). The device's own grace period silences the `new_domain` alerts.
6. The matching `new_domain` alert already covered it; alerting twice would only add noise.
7. Only `last_seen`/`ip` updates since the last flush (at most about 30 seconds). New devices, domains, servers and alerts are committed immediately.
8. `d is None` is true only for a missing entry. `not d` would also be true for an empty dict. Here the dict is never empty, so they behave the same, but `is None` states the intent exactly.

</details>

---

# Chapter 7: `notify.py`, sending alerts to your phone

**Goal:** a small class that sends a message to your phone and never lets notifications spam you or crash the sniffer.

## 7.1 New concepts

**HTTP in 60 seconds.** A client sends a *request* (method, URL, headers, body); the server returns a *response* (status code, headers, body). A `POST` sends data to the server. Status codes in the 200s mean success.

**ntfy.** A free notification service. You POST a message to `https://ntfy.sh/<topic>` and every phone subscribed to that topic gets it. Headers control the look: `Title`, `Priority`, `Tags` (tag names that become emoji), `Click` (a URL to open when tapped). The topic name is the only secret, so treat it like a password.

**`requests`.** The standard Python HTTP library. `requests.post(url, data=..., headers=..., timeout=5)`.

**Exceptions.** `try: ... except SomeError: ...` runs recovery code instead of crashing. Always catch the *specific* error you expect (here `requests.RequestException`, the base class of all `requests` errors). A bare `except:` hides real bugs.

**`@property`.** Makes a method readable as an attribute: `notifier.enabled` instead of `notifier.enabled()`.

**`collections.deque`.** A double-ended list that is fast at adding and removing at both ends. Ideal for a sliding window of timestamps.

**Rate limiting with a sliding window.** Remember when each notification was sent. Before sending, throw away timestamps older than one hour. If at least `max_per_hour` remain, you are over the limit.

## 7.2 The code

```python
# netwatch/notify.py
"""Phone notifications via ntfy. Install the ntfy app, subscribe to your topic, done."""
import time
from collections import deque

import requests

_PRIORITY = {"high": "high", "medium": "default", "low": "low"}


class Notifier:
    def __init__(self, url, topic, click_url="", max_per_hour=20):
        self.url, self.topic, self.click_url = url, topic, click_url
        self.max_per_hour = max_per_hour
        self._sent = deque()
        self._suppressed = 0

    @property
    def enabled(self):
        return bool(self.topic)

    def send(self, title, message, severity="medium", tags="", _bypass=False):
        """title must be ASCII (it travels in an HTTP header). Returns True if sent."""
        if not self.enabled:
            return False
        now = time.time()
        while self._sent and now - self._sent[0] > 3600:
            self._sent.popleft()

        if not _bypass:
            if len(self._sent) >= self.max_per_hour:
                self._suppressed += 1
                if self._suppressed == 1:   # say so once, then stay quiet
                    self.send("netwatch: alert limit reached",
                              "Further alerts are saved to the dashboard only.",
                              "low", "mute", _bypass=True)
                return False
            self._suppressed = 0
            self._sent.append(now)

        headers = {"Title": title, "Priority": _PRIORITY.get(severity, "default")}
        if tags:
            headers["Tags"] = tags
        if self.click_url:
            headers["Click"] = self.click_url
        try:
            r = requests.post(f"{self.url}/{self.topic}",
                              data=message.encode("utf-8"), headers=headers, timeout=5)
            return r.ok
        except requests.RequestException as exc:
            print(f"[notify] failed: {exc}")
            return False
```

## 7.3 Walkthrough

- `__init__` stores the settings and creates the two pieces of state: the `deque` of send times and the `_suppressed` counter.
- `enabled` is `bool(self.topic)`: an empty topic means "notifications are off". `send` returns `False` straight away so the rest of the program never needs to care.
- **The window:**
  ```python
  while self._sent and now - self._sent[0] > 3600:
      self._sent.popleft()
  ```
  `self._sent[0]` is the oldest. If it is over an hour old, remove it, and repeat. Afterwards `len(self._sent)` is "how many I sent in the last hour".
- **Over the limit:** the first suppressed alert triggers *one* "alert limit reached" notice, then silence. It calls itself with `_bypass=True` so that notice isn't blocked by the limit it is announcing (this is a small *recursion*: a function calling itself). Dashboard alerts are never limited, only phone notifications.
- **Headers vs body.** HTTP headers must be plain ASCII, so the `title` is always an ASCII string we control. The `message` (which may contain a device name with any character) goes in the *body*, encoded as UTF-8 bytes with `.encode("utf-8")`.
- **`timeout=5`.** Without a timeout, a dead network could freeze the sniffer forever. Always set one.
- **Fail soft.** Any network failure prints a line and returns `False`. A notification problem must never stop the monitor.
- `r.ok` is `True` for status codes below 400.

Sliding window example with a limit of 3 per hour:

```
 t=0m  send #1 ✔   t=10m send #2 ✔   t=20m send #3 ✔
 t=30m send #4 ✘ (3 in the last hour → suppressed, one notice sent)
 t=61m send #5 ✔ (the t=0m entry just expired, so there is room)
```

## 7.4 Try it

```python
from netwatch.notify import Notifier
print(Notifier("https://ntfy.sh", "").send("t", "m"))     # False: no topic, so disabled
```

Watch what it really sends. In one terminal run `nc -l 8099` (it prints whatever connects). In the REPL:

```python
from netwatch.notify import Notifier
n = Notifier("http://localhost:8099", "demo", "http://localhost:8080")
n.send("netwatch: test", "héllo from netwatch", "high", "warning")
```

You should see the raw `POST /demo` request with the `Title`, `Priority`, `Tags` and `Click` headers and the body. (`nc` never replies, so the REPL line waits 5 seconds, hits the `timeout=5`, and prints a failure. That is expected, and it shows the timeout and the fail-soft behaviour working.) Then try `Notifier("https://ntfy.sh", "your-topic").send(...)` for your phone, or run `python -m netwatch.sniffer --test-notify` once Chapter 8 is done.

Experiment with the limit: `n = Notifier("http://localhost:1", "t", max_per_hour=2)` and call `n.send(...)` four times. The port is closed, so each call fails with a printed error, and read the output: you should see three "failed" lines (two real attempts plus the one-time "limit reached" notice) and nothing at all for the fourth call. Afterwards `n._suppressed` is `2`.

## Check yourself: Chapter 7

1. Why must the title be ASCII, but the message needn't be?
2. What does `while self._sent and now - self._sent[0] > 3600` do?
3. Why call `send(..., _bypass=True)` for the "limit reached" notice?
4. What happens to the sniffer if ntfy.sh is unreachable?
5. Why does the code catch `requests.RequestException` rather than a bare `except:`?

<details><summary>Answers</summary>

1. The title travels in an HTTP header, which must be plain ASCII. The message is the request body, which can be any bytes (we encode UTF-8).
2. Removes timestamps older than an hour from the front of the deque, stopping at the first recent one.
3. Otherwise the notice would itself be blocked by the limit it is reporting.
4. `requests.post` raises an error, it is caught, a line is printed and `send` returns `False`. The sniffer carries on.
5. A bare `except:` would also swallow unrelated bugs (typos, `KeyboardInterrupt`), making them invisible.

</details>

---

# Chapter 8: `sniffer.py`, running the capture

**Goal:** the program you start from the terminal. It connects everything: settings, database, detector, notifier, and the live packet capture.

## 8.1 New concepts

**`argparse`.** Python's standard tool for command-line options. You describe the options; it parses `sys.argv`, validates, and writes `-h` help for you.

**Closures and `nonlocal`.** A function defined inside another function can *use* the outer function's variables. That is a **closure**. But if the inner function *assigns* to an outer variable, Python assumes you meant a brand-new local one, unless you declare `nonlocal name`.

**`try / except / finally`.** `finally` runs no matter how the block ends (normal finish, error, or Ctrl+C). It is where cleanup belongs.

**`KeyboardInterrupt`.** The exception Python raises when you press Ctrl+C.

**`if __name__ == "__main__":`.** When a file is run directly (or with `-m`), Python sets its `__name__` to `"__main__"`. When it is merely imported, `__name__` is the module's name. This guard means "only start the program if I was launched on purpose, not imported by something else (like a test)".

**Process privileges.** Capturing needs root. Whatever root creates is *owned by root*. A second program running as you (the dashboard) may then be unable to write those files. You hit this earlier: `attempt to write a readonly database`.

## 8.2 The code

```python
# netwatch/sniffer.py
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
```

## 8.3 Walkthrough

**Imports.** `from scapy.all import sniff` imports one function. `from . import config, db` are relative imports (Chapter 2). `from .detector import Detector` imports one class from a sibling module.

**`BPF`** is the filter explained in Chapter 5.

**Argument parsing.**
- `add_argument("-i", "--iface", default=config.IFACE, help=...)` defines an option that takes a value.
- `action="store_true"` defines a *flag* with no value: `args.relearn` is `True` if you typed `--relearn`, otherwise `False`.
- Dashes become underscores on the result: `--test-notify` is read as `args.test_notify`.
- Try `python -m netwatch.sniffer -h` to see the free help text.

**`--test-notify` exits early.** It sends one message and `return`s from `main()` before touching the database or the network interface, so it is a safe way to test your phone setup.

**Starting the learning period.**
```python
if args.relearn or db.get_meta(conn, "learning_until") is None:
```
`or` is *short-circuit*: if `--relearn` is given, the database isn't even queried. Otherwise it checks whether this is the very first run (no saved value). Either way we save `now + hours * 3600`. `float(db.get_meta(...))` converts the stored text back into a number.

**Status message.** `{left:.1f}` is an f-string *format spec*: one decimal place. The `print(...)` takes a conditional expression (`A if left > 0 else B`) spread over two lines.

**The callback and the closure.** `on_packet` is defined inside `main()` and uses `det`, `notifier`, `conn`, `learning_until` and `announced` from the outer scope. Scapy calls it once per packet. Because it assigns `announced = True`, it must declare `nonlocal announced`. Delete that line and run it to see the error Python raises (`UnboundLocalError`): Python decides `announced` is a local variable because of the assignment, then fails because you read it first.

**`announced` is a plain Python variable** so the check `not announced` costs nothing per packet. (An earlier version of this file asked the database on every single packet. It worked, but it was wasteful. Moving the check into memory is the same idea as the detector's cache.)

**`sniff(..., store=False)`.** `store=False` tells Scapy not to keep captured packets in memory; without it, memory use would grow forever.

**`try / except KeyboardInterrupt / finally`.** Ctrl+C is caught and ignored (`pass`), so it stops the loop quietly, and `finally` runs `det.flush()` to save pending `last_seen` updates.

**`_give_db_back_to_user()`**:
- `os.geteuid()` is the *effective user id*; `0` means root.
- When you run `sudo`, it sets `SUDO_UID` and `SUDO_GID` to your real IDs. We read them from `os.environ`.
- `os.chown(path, uid, gid)` changes the owner of a file. The loop covers the main file plus the two WAL helper files (`-wal`, `-shm`).
- The guard `os.geteuid() == 0 and sudo_uid` means: only do this when running as root *via sudo*; as a normal user it does nothing.
- This is **least privilege** in practice: only the sniffer runs as root; the dashboard never does.
- `sudo -E` keeps your environment variables (like `NETWATCH_NTFY_TOPIC`); plain `sudo` normally strips them.

## 8.4 Try it

```zsh
python -m netwatch.sniffer -h
NETWATCH_NTFY_TOPIC=your-topic python -m netwatch.sniffer --test-notify
sudo -E .venv/bin/python -m netwatch.sniffer -i en0 --relearn
ls -l netwatch.db*      # owner should be YOUR username, not root
```

Press Ctrl+C after a minute. Re-run the same command without `--relearn` and notice that the learning time carries on from before.

## Check yourself: Chapter 8

1. Why does `--test-notify` run before the database is opened?
2. What does `action="store_true"` do?
3. What would happen if you removed `nonlocal announced`? Why?
4. Why is `det.flush()` in a `finally` block?
5. Why does the code `chown` the database files?
6. What does `if __name__ == "__main__":` protect against?

<details><summary>Answers</summary>

1. So you can test phone alerts without needing root, a network interface or a database.
2. Makes the option a boolean flag: `True` when present, `False` when absent.
3. `UnboundLocalError`. Assigning to `announced` makes it a local variable, which has no value when first read.
4. `finally` always runs, including after Ctrl+C or a crash, so pending updates are saved.
5. Under `sudo` the database is created owned by root, which stops the non-root dashboard from writing to it.
6. Code running merely because the module was imported (for example by a test) instead of being started deliberately.

</details>

---

# Chapter 9: `dashboard.py`, a web interface with Flask

**Goal:** a small website that reads the database and lets you name devices and dismiss alerts.

## 9.1 New concepts

**The request/response cycle.** Your browser sends a request (`GET /device/aa:bb:...`). The server runs code and returns HTML. `GET` reads; `POST` changes something (like a form submit).

**Flask.** A web framework: you write Python functions, and Flask connects them to URLs.

**Decorators.** A decorator is a function that takes a function and returns a (usually modified) function. The `@name` line above a `def` is shorthand. From scratch:

```python
def shout(func):
    def wrapper():
        return func().upper()
    return wrapper

@shout                 # exactly the same as: greet = shout(greet)
def greet():
    return "hello"

print(greet())         # HELLO
```

In Flask, `@app.get("/")` registers the function below it as the handler for `GET /`. (`app.get("/")` returns a decorator; the decorator stores your function in Flask's routing table and returns it.)

**`g` and the app context.** `flask.g` is a scratchpad that lives for exactly one request. We use it to hold that request's database connection.

**Templates (Jinja).** HTML files with placeholders and simple logic. Python passes data in; Jinja renders HTML out. Keeping HTML out of Python keeps both readable.

**Generator expressions.** Like a list comprehension, but lazy: `sum(1 for a in alerts if not a["acked"])` counts matching items without building a list.

**SQL joins and subqueries.** Used in the overview queries (explained below).

**Post/Redirect/Get.** After handling a `POST`, you *redirect* to a normal `GET` page. Otherwise, pressing refresh would resubmit the form.

## 9.2 Setup, filters and helpers

```python
# netwatch/dashboard.py
from flask import Flask, abort, g, redirect, render_template, request, url_for

from . import config, db

app = Flask(__name__)


def conn():
    if "db" not in g:
        g.db = db.connect(config.DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    c = g.pop("db", None)
    if c:
        c.close()


@app.template_filter("when")
def when(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b %H:%M")


@app.template_filter("ago")
def ago(ts):
    s = max(0, int(time.time() - ts))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= size:
            return f"{s // size}{unit} ago"
    return "just now"


def status():
    until = float(db.get_meta(conn(), "learning_until", 0) or 0)
    if until == 0:
        return {"learning": True, "text": "Sniffer has not started yet", "left": None}
    left = (until - time.time()) / 3600
    if left > 0:
        return {"learning": True, "text": f"Learning, {left:.0f}h left", "left": left}
    return {"learning": False, "text": "Alerting live", "left": 0}
```

- `app = Flask(__name__)`: `__name__` tells Flask where this package lives, so it can find the `templates/` folder.
- **`conn()`** opens a connection the first time it is called in a request, then reuses it: `if "db" not in g`. Each request gets its own connection because SQLite connections shouldn't be shared between threads, and Flask's development server uses threads.
- **`@app.teardown_appcontext`** registers a cleanup function that Flask runs after every request. `g.pop("db", None)` removes the connection (or `None` if there wasn't one) and we close it.
- **`@app.template_filter("when")`** makes a Python function usable inside templates: `{{ a.ts|when }}` calls `when(a.ts)`.
- **`ago()`** loops over `(unit, size)` pairs from biggest to smallest, and returns on the first unit that fits. `s // size` is integer division.
- **`status()`** returns a dict the template reads. `float(... or 0)` handles "no value yet".

## 9.3 The overview page

```python
# netwatch/dashboard.py
@app.get("/")
def index():
    c = conn()
    alerts = c.execute(
        "SELECT a.*, d.label, d.ip FROM alerts a LEFT JOIN devices d ON d.mac = a.mac "
        "ORDER BY a.ts DESC LIMIT 50").fetchall()
    devices = c.execute(
        "SELECT d.*, (SELECT COUNT(*) FROM dns_seen s WHERE s.mac = d.mac) AS domains, "
        "(SELECT COUNT(*) FROM dest_seen t WHERE t.mac = d.mac) AS dests, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.mac = d.mac AND a.acked = 0) AS open_alerts "
        "FROM devices d ORDER BY d.last_seen DESC").fetchall()

    # Alerts per day, last 7 days, for the little bar strip.
    start = time.time() - 6 * 86400
    counts = {r["day"]: r["n"] for r in c.execute(
        "SELECT date(ts, 'unixepoch', 'localtime') AS day, COUNT(*) AS n "
        "FROM alerts WHERE ts >= ? GROUP BY day", (start,))}
    days = []
    for i in range(6, -1, -1):
        d = datetime.fromtimestamp(time.time() - i * 86400)
        days.append({"label": d.strftime("%a"), "n": counts.get(d.strftime("%Y-%m-%d"), 0)})
    peak = max([d["n"] for d in days] + [1])
    for d in days:
        d["pct"] = int(d["n"] / peak * 100)

    unacked = sum(1 for a in alerts if not a["acked"])
    return render_template("index.html", alerts=alerts, devices=devices, days=days,
                           status=status(), unacked=unacked)
```

**Query 1: alerts with device names.** `LEFT JOIN devices d ON d.mac = a.mac` attaches each alert's device row. "Left" means alerts are kept even if the device row were missing. `a.*` means "every column of alerts". `ORDER BY a.ts DESC LIMIT 50` is newest first, capped at 50.

**Query 2: devices with counts.** The three `(SELECT COUNT(*) ... WHERE s.mac = d.mac)` parts are *correlated subqueries*: for each device row, run a small count query about that device. `AS domains` names the result column.

**`fetchall()`** returns a list of rows. (`fetchone()` returned one row in Chapter 4.)

**The 7-day bar chart:**
1. `date(ts, 'unixepoch', 'localtime')` is a SQLite function that turns a timestamp into `YYYY-MM-DD` in your timezone. `GROUP BY day` + `COUNT(*)` gives alerts per day.
2. The `{r["day"]: r["n"] for r in c.execute(...)}` dict comprehension turns that into `{"2026-10-09": 4, ...}`.
3. `for i in range(6, -1, -1)` counts 6, 5, ... 0 (start 6, stop before -1, step -1): oldest day first.
4. For each day, `datetime.fromtimestamp(now - i * 86400)` (86400 seconds = one day), `strftime` formats it, and `counts.get(..., 0)` gives zero for days with no alerts.
5. `peak = max([d["n"] for d in days] + [1])` finds the biggest day, and the extra `[1]` guarantees it is never 0 (avoiding division by zero on the next line).
6. `d["pct"] = int(d["n"] / peak * 100)` computes bar heights as percentages. Changing `d` inside the loop works because `d` is the same dict object that is in the list.

**`render_template("index.html", alerts=alerts, ...)`**: each keyword argument becomes a variable inside the template.

## 9.4 Device page, forms and actions

```python
# netwatch/dashboard.py
@app.get("/device/<mac>")
def device(mac):
    c = conn()
    d = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
    if not d:
        abort(404)
    domains = c.execute("SELECT * FROM dns_seen WHERE mac=? ORDER BY first_seen DESC", (mac,)).fetchall()
    dests = c.execute("SELECT * FROM dest_seen WHERE mac=? ORDER BY raw_ip DESC, first_seen DESC", (mac,)).fetchall()
    alerts = c.execute("SELECT * FROM alerts WHERE mac=? ORDER BY ts DESC LIMIT 20", (mac,)).fetchall()
    return render_template("device.html", d=d, domains=domains, dests=dests, alerts=alerts)


@app.post("/device/<mac>/label")
def set_label(mac):
    c = conn()
    c.execute("UPDATE devices SET label=? WHERE mac=?", (request.form.get("label", "").strip() or None, mac))
    c.commit()
    return redirect(url_for("device", mac=mac))


@app.post("/alert/<int:alert_id>/ack")
def ack(alert_id):
    c = conn()
    c.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))
    c.commit()
    return redirect(request.referrer or url_for("index"))


@app.post("/alerts/ack-all")
def ack_all():
    c = conn()
    c.execute("UPDATE alerts SET acked=1")
    c.commit()
    return redirect(url_for("index"))
```

- **URL variables:** `<mac>` captures that part of the URL and passes it as the argument `mac`. `<int:alert_id>` captures it and converts it to an integer (non-numbers get a 404 automatically).
- **`abort(404)`** stops immediately and returns "Not Found".
- **`@app.post(...)`** handles only POST requests (the HTML forms use `method="post"`).
- **`request.form.get("label", "").strip() or None`**: read the form field, trim spaces, and if the result is empty store `None` (database NULL). This is the same `or None` idiom as Chapter 3.
- **`redirect(url_for("device", mac=mac))`**: `url_for` builds a URL from a *function name*, so you can rename routes without breaking links. This is the Post/Redirect/Get pattern.
- **`request.referrer or url_for("index")`** sends you back to the page you came from, with a fallback.

## 9.5 Starting the server

```python
# netwatch/dashboard.py
def main():
    # No login: keep it on 127.0.0.1, or put it behind a VPN/reverse proxy before exposing it.
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)


if __name__ == "__main__":
    main()
```

`app.run(host, port)` starts Flask's built-in development server. `127.0.0.1` means "only this computer can connect". Change it to `0.0.0.0` and anyone on your network can reach it, **with no password**. Keep it local.

## 9.6 The templates

**`base.html`**, the page skeleton. The `<style>` block is visual design, not logic, so copy it from the repo file rather than typing it. The structure around it is the important part:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}netwatch{% endblock %}</title>
{% block refresh %}<meta http-equiv="refresh" content="20">{% endblock %}
```

```html
<style> ... copy the CSS from netwatch/templates/base.html ... </style>
```

```html
</style>
</head>
<body><main>
<header>
  <h1><a href="{{ url_for('index') }}">netwatch</a></h1>
  {% block status %}{% endblock %}
</header>
{% block body %}{% endblock %}
</main></body></html>
```

**Jinja syntax you need:**

| Syntax | Meaning |
|---|---|
| `{{ expression }}` | print a value (HTML-escaped automatically) |
| `{% if x %} ... {% endif %}` | condition |
| `{% for a in alerts %} ... {% endfor %}` | loop |
| `{{ value\|filter }}` | pass through a filter (`when`, `ago`, `length`) |
| `{% block name %}...{% endblock %}` | a slot that child templates can fill |
| `{% extends "base.html" %}` | "start from that skeleton" |
| `{{ url_for('index') }}` | build a URL |

`base.html` defines the shared page and empty blocks (`status`, `body`, `title`, `refresh`). Each child fills the blocks it cares about. `device.html` overrides `refresh` with *nothing*, so the device page doesn't auto-reload while you type a name.

**`index.html`:**

```html
{% extends "base.html" %}
{% block status %}
  <span class="pill {{ 'live' if not status.learning }}">{{ status.text }}</span>
  <span class="pill">{{ devices|length }} devices</span>
  <span class="pill">{{ unacked }} open alerts</span>
{% endblock %}
{% block body %}

<section>
  <h2>Alerts in the last 7 days</h2>
  <div class="bars">
    {% for d in days %}
      <div class="bar" title="{{ d.n }} alerts"><span>{{ d.n }}</span><i style="height: {{ d.pct }}%"></i><span>{{ d.label }}</span></div>
    {% endfor %}
  </div>
</section>

<section>
  <h2>Alerts
    {% if unacked %}<form method="post" action="{{ url_for('ack_all') }}"><button>Dismiss all</button></form>{% endif %}
  </h2>
  {% if not alerts %}
    <p class="empty">{{ 'Nothing yet. Alerts start once learning finishes.' if status.learning else 'No alerts. Everything seen so far matches the baseline.' }}</p>
  {% else %}
  <div class="scroll"><table>
    {% for a in alerts %}
    <tr class="{{ 'acked' if a.acked }}">
      <td style="white-space:nowrap"><span class="dot {{ a.severity }}"></span><span class="muted">{{ a.ts|when }}</span></td>
      <td>{{ a.message }} <a href="{{ url_for('device', mac=a.mac) }}">device</a></td>
      <td style="text-align:right">
        {% if not a.acked %}<form method="post" action="{{ url_for('ack', alert_id=a.id) }}"><button>Dismiss</button></form>{% endif %}
      </td>
    </tr>
    {% endfor %}
  </table></div>
  {% endif %}
</section>

<section>
  <h2>Devices</h2>
  {% if not devices %}
    <p class="empty">No devices seen yet. Check the sniffer is running and sees LAN traffic.</p>
  {% else %}
  <div class="scroll"><table>
    <tr><th>Name</th><th>Address</th><th>Last seen</th><th>Domains</th><th>Servers</th><th></th></tr>
    {% for d in devices %}
    <tr>
      <td><a href="{{ url_for('device', mac=d.mac) }}">{{ d.label or d.mac }}</a>
          {% if d.randomised %}<span class="muted" title="Private Wi-Fi address, changes per network">(private address)</span>{% endif %}</td>
      <td class="mono">{{ d.ip }}</td>
      <td class="muted">{{ d.last_seen|ago }}</td>
      <td>{{ d.domains }}</td>
      <td>{{ d.dests }}</td>
      <td>{% if d.open_alerts %}<span class="tag">{{ d.open_alerts }} open</span>{% endif %}</td>
    </tr>
    {% endfor %}
  </table></div>
  {% endif %}
</section>
{% endblock %}
```

Things to notice:
- `{{ 'acked' if a.acked }}` is a Jinja conditional expression that prints `acked` or nothing; it is used to add a CSS class.
- Each "Dismiss" button is a tiny `<form method="post" action="...">`. A button click is a POST to the matching route.
- `a.message`, `a.ts` and so on work because rows can be read by name.
- `devices|length` counts items.

**`device.html`:**

```html
{% extends "base.html" %}
{% block title %}{{ d.label or d.mac }} · netwatch{% endblock %}
{% block refresh %}{% endblock %}
{% block body %}
<section>
  <h2>{{ d.label or d.mac }}</h2>
  <p class="muted mono">{{ d.mac }} · {{ d.ip }} · first seen {{ d.first_seen|when }} · last seen {{ d.last_seen|ago }}</p>
  <form method="post" action="{{ url_for('set_label', mac=d.mac) }}">
    <input type="text" name="label" value="{{ d.label or '' }}" placeholder="Name this device, e.g. Living room TV" aria-label="Device name" size="32">
    <button>Save name</button>
  </form>
</section>

<section>
  <h2>Servers it connects to</h2>
  {% if not dests %}<p class="empty">None recorded yet.</p>{% else %}
  <div class="scroll"><table>
    <tr><th>Destination</th><th>Port</th><th>First seen</th><th></th></tr>
    {% for t in dests %}
    <tr>
      <td class="mono">{{ t.dest }}</td><td>{{ t.port }}/{{ t.proto }}</td><td class="muted">{{ t.first_seen|when }}</td>
      <td>{% if t.raw_ip %}<span class="tag">no DNS lookup</span>{% endif %}</td>
    </tr>
    {% endfor %}
  </table></div>{% endif %}
</section>

<section>
  <h2>Domains it has looked up</h2>
  {% if not domains %}<p class="empty">None recorded yet.</p>{% else %}
  <div class="scroll"><table>
    <tr><th>Domain</th><th>First seen</th></tr>
    {% for s in domains %}<tr><td class="mono">{{ s.domain }}</td><td class="muted">{{ s.first_seen|when }}</td></tr>{% endfor %}
  </table></div>{% endif %}
</section>

<section>
  <h2>Recent alerts</h2>
  {% if not alerts %}<p class="empty">No alerts for this device.</p>{% else %}
  <table>
    {% for a in alerts %}
    <tr class="{{ 'acked' if a.acked }}"><td style="white-space:nowrap"><span class="dot {{ a.severity }}"></span><span class="muted">{{ a.ts|when }}</span></td><td>{{ a.message }}</td></tr>
    {% endfor %}
  </table>{% endif %}
</section>
<p><a href="{{ url_for('index') }}">Back to overview</a></p>
{% endblock %}
```

## 9.7 Security notes (you are studying cybersecurity, so think like an attacker)

1. **XSS (cross-site scripting).** Device names and domains are attacker-influenced text. If we pasted them into HTML unescaped, a device that looked up `<script>…</script>` as a "domain" could run code in your browser. Jinja **escapes** `<` and `>` by default, so it is displayed as text. Do not turn autoescaping off, and be wary of the `|safe` filter.
2. **No authentication.** Anyone who can reach the port can read your network data and dismiss alerts. Keep the host at `127.0.0.1`, or put it behind a VPN or an authenticating reverse proxy.
3. **No CSRF protection.** A malicious web page could make your browser send a POST to `http://127.0.0.1:8080/alerts/ack-all`. The impact is small here (dismissing alerts), but it is the reason real apps use CSRF tokens.
4. **Development server.** Flask's built-in server isn't hardened for production.

## 9.8 Try it

```zsh
python -m netwatch.dashboard       # open http://127.0.0.1:8080
```

1. Click a device and give it a name. Watch the table and future alerts use it.
2. Name a device `<script>alert(1)</script>`. The text should show on screen and nothing should pop up. Right-click, "View source", and find `&lt;script&gt;`. That is the escaping.
3. Visit `http://127.0.0.1:8080/device/nope` to see your `abort(404)`.
4. Press the "Dismiss all" button, then reload.

## Check yourself: Chapter 9

1. What does `@app.get("/")` actually do?
2. Why does each request open its own database connection?
3. Why `redirect(...)` after a POST?
4. Why `max([...] + [1])` in the bar-chart code?
5. Why is a device name like `<script>` harmless in this dashboard? What setting would make it dangerous?
6. What changes if you set the host to `0.0.0.0`?
7. What does `<int:alert_id>` do compared with `<mac>`?

<details><summary>Answers</summary>

1. Registers the function below it as the handler for GET requests to `/`.
2. SQLite connections shouldn't be shared across threads, and Flask handles requests in separate threads. Per-request connections are safe and simple.
3. Post/Redirect/Get: so refreshing the page doesn't resubmit the form.
4. It guarantees a minimum of 1, so `d["n"] / peak` never divides by zero when there were no alerts.
5. Jinja escapes it into harmless text. Disabling autoescape or using `|safe` on untrusted text would make it dangerous.
6. Every device on your network can open the dashboard, with no password.
7. `<int:...>` converts the value to an integer and returns 404 if it isn't one; `<mac>` passes a string.

</details>

---

# Chapter 10: Tests

**Goal:** prove the rules work without needing a real network, a router, or root.

## 10.1 New concepts

**Why test.** You can't wait 72 hours and wave a smart TV around to check a rule. Tests replay *fabricated packets* through the detector and assert on the outcome, in milliseconds, every time you change the code.

**pytest.** Finds files named `test_*.py` and functions named `test_*`, runs them, and reports failures. A test passes if it finishes without an exception.

**`assert`.** `assert x == 3` raises an error if the condition is false. pytest rewrites asserts to show you both sides when they fail.

**Fixtures.** A function marked `@pytest.fixture` builds something tests need. A test asks for it simply by naming it as a parameter. This is *dependency injection*: pytest sees `def test_x(env):`, calls the `env` fixture, and passes the result in.

**`tmp_path`.** A built-in fixture: a fresh temporary folder for each test, so tests never share a database.

**Test doubles ("fakes").** `FakeNotifier` has a `send` method with the same shape as the real `Notifier` but just records calls in a list. Python doesn't check types: if it has a `send` method, the detector will happily use it. (This is called **duck typing**: "if it quacks like a duck".) Tests then assert on `n.sent` instead of waiting for a phone.

**Arrange, act, assert.** Each test sets things up, does one thing, then checks the result.

## 10.2 Fixtures and packet builders

```python
# tests/test_detector.py
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
```

- `T0` and `LEARN_END` are fake timestamps. Learning "ends" one hour after `T0`. Passing explicit `ts` values into `handle_packet` is why that parameter exists (Chapter 6).
- The first-octet comment matters: test MACs starting with `0x00` are normal vendor MACs, so tests don't trigger the "randomised" wording by accident. (A previous version used `aa:`, whose bit pattern is "randomised". A good reminder that Chapter 1's bit facts really matter.)
- `dns_query`, `dns_answer` and `syn` are **helper functions** that build packets, so each test stays one or two lines.

## 10.3 The tests

```python
# tests/test_detector.py
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
```

```python
# tests/test_detector.py
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
```

```python
# tests/test_detector.py
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
```

What each test protects:

| Test | Rule it locks down |
|---|---|
| `test_base_domain` | `.com.au` handling and subdomain trimming |
| `test_learning_period_is_silent` | nothing alerts during learning, but everything is recorded |
| `test_new_device_alerts_once` | a new device alerts exactly once |
| `test_new_device_gets_grace_period` | the per-device quiet window starts and ends correctly |
| `test_new_domain_alerts_once_and_groups_subdomains` | subdomains share a baseline; no repeat alerts |
| `test_dns_explained_destination_is_quiet_but_raw_ip_alerts` | DNS-explained connections stay quiet; raw IPs alert once |
| `test_lan_traffic_and_multicast_ignored` | LAN peers and multicast sources are ignored |
| `test_arp_reveals_new_device` | ARP broadcasts discover devices |
| `test_randomised_mac_is_flagged` | the L-bit logic and the alert wording |
| `test_baseline_survives_restart` | a second `Detector` on the same database remembers everything |

## 10.4 Running and reading tests

```zsh
python -m pytest -q          # quiet summary
python -m pytest -v          # one line per test
python -m pytest -x          # stop at the first failure
python -m pytest -k grace    # only tests with "grace" in the name
```

Read a failure from the bottom up: the `E` lines show what the assert expected versus what it got. When we built this project, one test failed with `assert 0 == 1`: it expected one alert but got none. The cause wasn't the detector; it was the test's documentation IP addresses (Chapter 6.5). Reading the failure carefully, then checking assumptions, solved it.

## 10.5 Exercise: write a test first

Add a new test to the file: a device that asks for the *same* domain at two different times (after learning) fires **no** alert the second time. Run it and confirm it passes. Then break the detector on purpose (comment out the `self.known_dns.add(...)` line) and confirm your test *fails*. A test you have never seen fail proves little.

## Check yourself: Chapter 10

1. How does pytest know to pass a database into a test?
2. Why is `FakeNotifier` allowed to stand in for `Notifier`?
3. Why do tests pass explicit timestamps instead of using the real clock?
4. What does `test_baseline_survives_restart` do to simulate a restart?
5. Why bother making a test fail on purpose?

<details><summary>Answers</summary>

1. The test declares a parameter with the fixture's name (`env`); pytest calls the fixture and injects the result.
2. Python uses duck typing: the detector only calls `.send(...)`, and the fake has that method.
3. So time is deterministic and can jump days ahead instantly.
4. It builds a second `Detector` on the same database connection, which reloads its baseline from SQLite.
5. To check the test actually detects the bug it is meant to catch.

</details>

---

# Chapter 11: Wrap-up

## 11.1 The whole system in one picture

```
 packet ──► sniffer.py (root) ─ on_packet ─► Detector.handle_packet
                                                │
                  ┌─────────────────────────────┼──────────────────────────────┐
                  ▼                             ▼                              ▼
           _see_device                    _dns_query                    _destination
           (new MAC?)                    (new domain?)              (raw IP, no DNS?)
                  └──────────────┬──────────────┴──────────────────────────────┘
                                 ▼
                    baseline sets in memory  +  rows in SQLite
                                 │ new + not in a quiet period
                                 ▼
                              _alert ──► alerts table ──► dashboard.py (reads, as you)
                                 └──────► Notifier.send ──► ntfy ──► phone
```

## 11.2 Concept index

If you can't explain a row, go to that chapter.

| Concept | Chapter |
|---|---|
| Packet layers, MAC, IP, ARP, DNS, TCP, UDP | 1 |
| Capture position and visibility | 1.7 |
| Baselining ("first seen") | 1.8, 6.1 |
| venv, pip, requirements | 2 |
| Modules, packages, `__init__.py`, relative imports, `python -m` | 2 |
| Environment variables, `os.environ.get`, type conversion | 3 |
| `pathlib`, `__file__` | 3 |
| Truthiness, `or` idiom | 3, 6.10 |
| SQL: tables, keys, INSERT/SELECT/UPDATE, upsert | 4 |
| Transactions, `commit()` | 4 |
| Parameterised queries, SQL injection | 4.4 |
| WAL mode, `row_factory` | 4 |
| Hex, bits, `&`, bytes vs str | 5 |
| BPF filters, root for sniffing | 5 |
| Classes, `self`, `__init__` | 6 |
| Sets, tuples as keys, comprehensions | 6 |
| Guard clauses, default arguments | 6 |
| Conditional expressions | 4, 6, 8 |
| Memory cache vs database | 6.1 |
| Injecting time for testing | 6.7, 10 |
| `getattr`, `isinstance`, slicing | 6 |
| HTTP, headers, `requests` | 7 |
| Exceptions and failing softly | 7 |
| `@property`, `deque`, sliding-window rate limit | 7 |
| `argparse`, short-circuit `or` | 8 |
| Closures and `nonlocal` | 8 |
| `try/finally`, `KeyboardInterrupt` | 8 |
| `__name__ == "__main__"` | 8 |
| File ownership, least privilege | 8 |
| Decorators | 9 |
| Flask routes, `g`, teardown, `url_for`, `abort` | 9 |
| Joins, subqueries, `GROUP BY` | 9.3 |
| Generator expressions | 9 |
| Jinja, template inheritance | 9.6 |
| Post/Redirect/Get | 9 |
| XSS, CSRF, exposure risk | 9.7 |
| pytest, fixtures, fakes, duck typing | 10 |

## 11.3 Final self-test

Answer all of these aloud or on paper without looking back. Then check the key.

1. Why can a laptop on Wi-Fi discover new devices but not see the TV's DNS lookups?
2. Explain the two quiet periods and why each exists.
3. Why is `(mac, domain)` a composite primary key?
4. What would go wrong if the detector ran `SELECT` for every packet?
5. What does `SYN and not ACK` mean, and how is it computed from the flags number?
6. Write `base_domain("a.b.example.com.au")` and explain the result.
7. What is SQL injection and why would it be easy to trigger in this project without `?`?
8. Why is `ip_to_domain` kept in memory only?
9. Why must `commit()` follow every write?
10. What does `ts or time.time()` do and what is its weakness?
11. What is `nonlocal` for?
12. Why does the sniffer `chown` the database?
13. What is a decorator? Write one.
14. What does Post/Redirect/Get prevent?
15. Why does Jinja's autoescape matter for this dashboard?
16. Why does the notifier return `False` instead of raising when the network fails?
17. How does `FakeNotifier` work with code expecting a `Notifier`?
18. A device compromised during the learning period starts contacting a malicious server. Will netwatch alert? Why or why not?
19. A smart TV uses DNS-over-HTTPS. What does netwatch see?
20. Why doesn't `new_domain` fire on the connection that follows a DNS answer?

<details><summary>Answer key</summary>

1. ARP/mDNS broadcasts reach everyone, but unicast traffic is only delivered to its destination.
2. Global learning builds the initial baseline silently. The per-device grace period stops a newly joined device from flooding alerts while it builds its own baseline.
3. So a device/domain pair can exist only once, making "seen before?" and `INSERT OR IGNORE` correct.
4. Thousands of disk queries per second; the program would fall behind. The in-memory sets answer the usual case instantly.
5. The first packet of a TCP connection. `flags & 0x02` (SYN on) and `not flags & 0x10` (ACK off).
6. `example.com.au`, because `com.au` is in `MULTI_SUFFIX`, so three labels are kept.
7. Untrusted text is executed as SQL. Domain names come from packets, so any device could craft one. Placeholders keep values as data.
8. It's a short-lived hint from recent DNS answers, not a permanent fact; persisting it would waste space and go stale.
9. Uncommitted changes aren't saved or visible to other connections (like the dashboard).
10. It uses the real clock when `ts` is missing. Weakness: it also replaces a legitimate `0` timestamp.
11. To assign to a variable of an enclosing function from an inner function.
12. Root created the file, so the non-root dashboard couldn't write to it.
13. A function that takes a function and returns a modified one, e.g. the `shout` example in 9.1.
14. Resubmitting a form when the user refreshes after a POST.
15. It stops attacker-controlled names (domains, labels) from running as HTML or JavaScript.
16. A failed notification shouldn't stop monitoring. Dashboard alerts are saved regardless.
17. Python doesn't check types; any object with a `send` method works (duck typing).
18. No. Its bad behaviour became part of the baseline. This is a stated limitation.
19. No lookups on port 53. Its connections look like raw-IP destinations, so you may get `unexplained_destination` alerts.
20. The lookup already raised (or recorded) the domain. The connection check alerts only on IPs no lookup explains.

</details>

## 11.4 The mastery test

Understanding is easiest to prove by rebuilding. Copy the project, **delete `detector.py`**, and rewrite it using only `tests/test_detector.py` as the specification. When all ten tests pass, you truly understand the detector. Compare your version with the original and note where your design differs.

## 11.5 Extension projects (each one teaches something new)

1. **`--ignore-mac` option.** Skip the machine running the sniffer so alerts are about *other* devices. *Hint:* add a parameter to `Detector`, return early in `handle_packet`, write a test first.
2. **Vendor names.** Map the first three bytes of a MAC to a manufacturer (a small CSV or dict) and show it on the device page. *Teaches:* file parsing, dictionaries, a new column.
3. **Traffic volume spikes.** Count bytes per device per hour and alert when one hour is far above that device's average. *Teaches:* aggregation, statistics, a new table.
4. **DNS tunnelling heuristic.** Alert if one base domain receives many unique long subdomains from a device. *Teaches:* counting with `collections.Counter`, thresholds.
5. **Alert filters on the dashboard.** Filter by severity or by device using URL query parameters (`request.args`). *Teaches:* GET parameters, SQL `WHERE` built safely.
6. **Run as services.** Write systemd units (Linux) or `launchd` plists (macOS) for the sniffer and dashboard. *Teaches:* process supervision.
7. **IPv6.** Extend the filter and detector to `IPv6`. *Teaches:* how much of this design depended on IPv4.

You have now seen every line of this project. The goal is not to remember it, but to be able to *rebuild it from the ideas*, which is what the exercises are for.
