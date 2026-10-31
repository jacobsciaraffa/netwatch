"""Small Flask dashboard.  python -m netwatch.dashboard   (no root needed)"""
import time
from datetime import datetime

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


def main():
    # No login: keep it on 127.0.0.1, or put it behind a VPN/reverse proxy before exposing it.
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)


if __name__ == "__main__":
    main()
