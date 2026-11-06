"""Verkehrs- und Systemstatistik.

Der Dienst vpn-stats.service (``vpnctl stats-daemon``) erfasst:

* alle 2 s den Durchsatz aller VPN-Clients (nftables-Zaehler im Forward-Pfad,
  unabhaengig vom Protokoll) sowie die CPU-Last -> /run/vpn-server/live.json
  (die letzten 5 Minuten),
* alle 10 s die Verbindungen mit ihren Byte-Zaehlern -> Datenvolumen je Benutzer
  in Stunden-Buckets (31 Tage) und das Verbindungsprotokoll (Anmelden/Abmelden).

"Download" ist dabei der Verkehr zu den Clients, "Upload" der von den Clients.
Die Weboberflaeche liest nur die Dateien und belastet die Dienste nicht.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import time

from . import util

LIVE_FILE = util.RUN_DIR + "/live.json"
LIB_DIR = "/var/lib/vpn-server"
HIST_FILE = LIB_DIR + "/stats.json"
EVENTS_FILE = LIB_DIR + "/events.jsonl"
PUBLIC_IP_FILE = util.RUN_DIR + "/public-ip"

LIVE_INTERVAL = 2
SESSION_INTERVAL = 10
FLUSH_INTERVAL = 20
LIVE_POINTS = 150          # 5 Minuten
HIST_HOURS = 24 * 31
EVENTS_KEEP = 1000


# --------------------------------------------------------------------------
# Messwerte
# --------------------------------------------------------------------------

def nft_counters() -> dict[str, int]:
    """Byte-Zaehler der benannten nftables-Zaehler (vpn_up, vpn_down, vlanN_up ...)."""
    res = util.run(["nft", "-j", "list", "counters", "table", "inet", "vpnserver"])
    out: dict[str, int] = {}
    try:
        for item in json.loads(res.stdout or "{}").get("nftables", []):
            c = item.get("counter")
            if c and "name" in c:
                out[c["name"]] = int(c.get("bytes", 0))
    except (ValueError, AttributeError):
        pass
    return out


def cpu_times() -> tuple[int, int]:
    """(Leerlauf, gesamt) aus /proc/stat."""
    try:
        with open("/proc/stat") as fh:
            parts = [int(x) for x in fh.readline().split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        return idle, sum(parts)
    except (OSError, ValueError, IndexError):
        return 0, 0


def _read(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


def system_info() -> dict:
    info: dict = {"cpus": os.cpu_count() or 1}
    mem = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        try:
            mem[key] = int(rest.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    if mem.get("MemTotal"):
        avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        info["mem_total"] = mem["MemTotal"]
        info["mem_used"] = mem["MemTotal"] - avail
    try:
        st = os.statvfs("/")
        info["disk_total"] = st.f_blocks * st.f_frsize
        info["disk_used"] = (st.f_blocks - st.f_bfree) * st.f_frsize
    except OSError:
        pass
    load = _read("/proc/loadavg").split()
    if load:
        info["load"] = [float(x) for x in load[:3]]
    up = _read("/proc/uptime").split()
    if up:
        info["uptime"] = int(float(up[0]))
    temps = []
    base = "/sys/class/thermal"
    if os.path.isdir(base):
        for name in os.listdir(base):
            raw = _read(f"{base}/{name}/temp").strip()
            if raw.lstrip("-").isdigit() and int(raw) > 0:
                temps.append(int(raw) / 1000)
    if temps:
        info["temp"] = round(max(temps), 1)
    return info


def _hour(ts: float) -> int:
    return int(ts // 3600 * 3600)


# --------------------------------------------------------------------------
# Erfassung (Dienst)
# --------------------------------------------------------------------------

class Collector:
    def __init__(self) -> None:
        self.points: list[list] = []
        self.cpu_ring: list[float] = []
        self.prev_counters: dict[str, int] = {}
        self.prev_cpu = cpu_times()
        self.prev_ts = time.time()
        self.prev_sessions: dict[str, dict] = {}
        self.sessions: list[dict] = []
        self.hist = load_history()
        self.dirty = False
        self.system: dict = {}

    # -- Live-Durchsatz -------------------------------------------------
    def tick_live(self) -> None:
        now = time.time()
        counters = nft_counters()
        dt_s = max(now - self.prev_ts, 0.5)
        deltas = {}
        for name, value in counters.items():
            prev = self.prev_counters.get(name)
            if prev is None:
                continue
            deltas[name] = value - prev if value >= prev else value  # Neustart der Firewall
        first = not self.prev_counters
        self.prev_counters = counters
        self.prev_ts = now
        idle, total = cpu_times()
        pidle, ptotal = self.prev_cpu
        self.prev_cpu = (idle, total)
        if total > ptotal:
            self.cpu_ring.append(round(100 * (1 - (idle - pidle) / (total - ptotal)), 1))
            self.cpu_ring = self.cpu_ring[-LIVE_POINTS:]
        if not first:
            down = deltas.get("vpn_down", 0)
            up = deltas.get("vpn_up", 0)
            self.points.append([int(now), int(down / dt_s), int(up / dt_s)])
            self.points = self.points[-LIVE_POINTS:]
            self._add_volume(now, deltas)
        self.system = system_info()
        self.write_live()

    def _bucket(self, ts: float) -> dict:
        h = _hour(ts)
        buckets = self.hist["buckets"]
        if not buckets or buckets[-1]["t"] != h:
            buckets.append({"t": h, "down": 0, "up": 0, "vlan": {}, "c": {}})
            del buckets[:-HIST_HOURS]
        return buckets[-1]

    def _add_volume(self, now: float, deltas: dict) -> None:
        b = self._bucket(now)
        b["down"] += deltas.get("vpn_down", 0)
        b["up"] += deltas.get("vpn_up", 0)
        for name, value in deltas.items():
            if name.startswith("vlan") and value:
                vid, _, direction = name[4:].partition("_")
                entry = b["vlan"].setdefault(vid, [0, 0])
                entry[0 if direction == "down" else 1] += value
        self.dirty = True

    # -- Verbindungen ---------------------------------------------------
    def tick_sessions(self) -> None:
        from . import state as st, status
        try:
            state = st.load()
        except (FileNotFoundError, ValueError):
            return
        sessions = status.all_sessions(state)
        now = time.time()
        b = self._bucket(now)
        current = {}
        for sess in sessions:
            sid = sess.get("sid") or f"{sess.get('proto')}:{sess.get('user')}"
            current[sid] = sess
            prev = self.prev_sessions.get(sid)
            down, up = sess.get("tx_bytes", 0), sess.get("rx_bytes", 0)
            if prev is not None:
                d_down = down - prev["tx_bytes"] if down >= prev["tx_bytes"] else down
                d_up = up - prev["rx_bytes"] if up >= prev["rx_bytes"] else up
            elif sid.startswith("wg:"):
                d_down = d_up = 0     # WireGuard-Zaehler laufen seit dem Start von wg0
            else:
                d_down, d_up = down, up
            if d_down or d_up:
                entry = b["c"].setdefault(sess.get("user") or "?", [0, 0])
                entry[0] += max(d_down, 0)
                entry[1] += max(d_up, 0)
                self.dirty = True
            if sid not in self.prev_sessions or self.prev_sessions[sid].get("_gone"):
                log_event({"type": "connect", "user": sess.get("user", ""), "proto": sess.get("proto", ""),
                           "vip": sess.get("vip", ""), "remote": sess.get("remote", ""),
                           "vlan": sess.get("vlan", ""), "radius": sess.get("radius", False)})
            sess["_first"] = (self.prev_sessions.get(sid) or {}).get("_first", now)
        for sid, prev in self.prev_sessions.items():
            if sid not in current and not prev.get("_gone"):
                log_event({"type": "disconnect", "user": prev.get("user", ""), "proto": prev.get("proto", ""),
                           "vip": prev.get("vip", ""), "remote": prev.get("remote", ""),
                           "duration": int(now - prev.get("_first", now)),
                           "down": prev.get("tx_bytes", 0), "up": prev.get("rx_bytes", 0)})
                if sid.startswith("wg:"):
                    # WireGuard-Zaehler bleiben erhalten -> fuer die naechste Verbindung merken
                    current[sid] = dict(prev, _gone=True)
        self.prev_sessions = current
        self.sessions = [{k: v for k, v in s.items() if not k.startswith("_")} for s in sessions]

    def write_live(self) -> None:
        data = {"ts": int(time.time()), "interval": LIVE_INTERVAL, "points": self.points,
                "cpu": self.cpu_ring, "system": self.system, "sessions": self.sessions}
        util.write_file(LIVE_FILE, json.dumps(data, separators=(",", ":")), mode=0o644)

    def flush(self) -> None:
        if self.dirty:
            util.write_file(HIST_FILE, json.dumps(self.hist, separators=(",", ":")), mode=0o600)
            self.dirty = False


def load_history() -> dict:
    try:
        data = json.loads(util.read_file(HIST_FILE) or "{}")
    except ValueError:
        data = {}
    data.setdefault("buckets", [])
    return data


def log_event(event: dict) -> None:
    event = dict(event, t=int(time.time()))
    path = util.P(EVENTS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    try:
        if os.path.getsize(path) > 600_000:
            lines = open(path).read().splitlines()[-EVENTS_KEEP:]
            util.write_file(EVENTS_FILE, "\n".join(lines) + "\n", mode=0o600)
    except OSError:
        pass


def run_daemon() -> None:
    """Hauptschleife von vpn-stats.service."""
    col = Collector()
    stop = {"now": False}

    def handler(_sig, _frm):
        stop["now"] = True
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    last_sessions = last_flush = last_ip = 0.0
    while not stop["now"]:
        start = time.time()
        try:
            col.tick_live()
            if start - last_sessions >= SESSION_INTERVAL:
                col.tick_sessions()
                last_sessions = start
            if start - last_flush >= FLUSH_INTERVAL:
                col.flush()
                last_flush = start
            if start - last_ip >= 1800:
                from .system import detect_public_ip
                ip = detect_public_ip()
                if ip:
                    util.write_file(PUBLIC_IP_FILE, ip, mode=0o644)
                last_ip = start
        except Exception as exc:  # noqa: BLE001 - der Dienst soll weiterlaufen
            util.log.warning("Statistik: %s", exc)
        time.sleep(max(0.2, LIVE_INTERVAL - (time.time() - start)))
    col.flush()


# --------------------------------------------------------------------------
# Auswertung (Weboberflaeche)
# --------------------------------------------------------------------------

def live() -> dict:
    try:
        data = json.loads(util.read_file(LIVE_FILE) or "{}")
    except ValueError:
        data = {}
    if not data or time.time() - data.get("ts", 0) > 30:
        data = dict(data, stale=True)
    data.setdefault("points", [])
    data.setdefault("cpu", [])
    data.setdefault("sessions", [])
    data.setdefault("system", {})
    if not data["system"]:
        data["system"] = system_info()
    return data


RANGES = {"24h": (24, "hour"), "7d": (7, "day"), "30d": (30, "day")}


def history(rng: str = "24h") -> dict:
    count, unit = RANGES.get(rng, RANGES["24h"])
    buckets = load_history()["buckets"]
    now = time.time()
    if unit == "hour":
        start = _hour(now) - (count - 1) * 3600
        keys = [start + i * 3600 for i in range(count)]

        def key(ts):
            return _hour(ts)

        def label(k):
            return dt.datetime.fromtimestamp(k).strftime("%H:00")
    else:
        today = dt.datetime.fromtimestamp(now).date()
        days = [today - dt.timedelta(days=count - 1 - i) for i in range(count)]
        keys = [d.isoformat() for d in days]

        def key(ts):
            return dt.datetime.fromtimestamp(ts).date().isoformat()

        def label(k):
            return dt.date.fromisoformat(k).strftime("%d.%m.")
    slots = {k: {"down": 0, "up": 0} for k in keys}
    clients: dict[str, list] = {}
    vlans: dict[str, list] = {}
    for b in buckets:
        k = key(b["t"])
        if k not in slots:
            continue
        slots[k]["down"] += b.get("down", 0)
        slots[k]["up"] += b.get("up", 0)
        for name, (d, u) in b.get("c", {}).items():
            e = clients.setdefault(name, [0, 0])
            e[0] += d
            e[1] += u
        for vid, (d, u) in b.get("vlan", {}).items():
            e = vlans.setdefault(vid, [0, 0])
            e[0] += d
            e[1] += u
    series = [{"key": k, "label": label(k), "down": v["down"], "up": v["up"]} for k, v in slots.items()]
    top = sorted(({"name": n, "down": d, "up": u} for n, (d, u) in clients.items()),
                 key=lambda x: -(x["down"] + x["up"]))
    return {"range": rng, "unit": unit, "series": series, "clients": top,
            "vlans": {k: {"down": d, "up": u} for k, (d, u) in vlans.items()},
            "total": {"down": sum(s["down"] for s in series), "up": sum(s["up"] for s in series)}}


def events(limit: int = 200) -> list[dict]:
    lines = (util.read_file(EVENTS_FILE) or "").splitlines()[-limit:]
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def today_volume() -> dict:
    h = history("24h")
    midnight = dt.datetime.combine(dt.date.today(), dt.time()).timestamp()
    down = up = 0
    for b in load_history()["buckets"]:
        if b["t"] >= midnight:
            down += b.get("down", 0)
            up += b.get("up", 0)
    return {"down": down, "up": up, "last24": h["total"]}
