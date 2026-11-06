"""Diagnose-Werkzeuge der Weboberflaeche: Ping, Traceroute, DNS, Speedtest,
Wake-on-LAN und Paketmitschnitt. Alle Eingaben werden streng geprueft und nie
ueber eine Shell ausgefuehrt."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
import urllib.request

from . import util

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})(\2[0-9A-Fa-f]{2}){4}$")
FILTER_RE = re.compile(r"^[A-Za-z0-9 .:/()!=<>-]{0,200}$")
DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA")


class ToolError(ValueError):
    pass


def _host(value: str) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not HOST_RE.match(value):
        raise ToolError("Ungültige Adresse (IP-Adresse oder DNS-Name).")
    return value


def _run(argv: list[str], timeout: int) -> str:
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (res.stdout + res.stderr).strip() or f"(keine Ausgabe, Rückgabewert {res.returncode})"
    except FileNotFoundError:
        return f"{argv[0]} ist nicht installiert."
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return (out + "\n(Zeitlimit erreicht)").strip()


def ping(host: str, count: int = 4) -> str:
    host = _host(host)
    count = max(1, min(int(count or 4), 10))
    return _run(["ping", "-c", str(count), "-W", "2", "-i", "0.5", host], timeout=count * 3 + 5)


def traceroute(host: str) -> str:
    host = _host(host)
    if util.have("traceroute"):
        return _run(["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", host], timeout=60)
    return _run(["tracepath", "-n", "-m", "20", host], timeout=60)


def dns(name: str, rtype: str = "A", server: str = "") -> str:
    name = _host(name.rstrip(".")) if name else ""
    if not name:
        raise ToolError("Bitte einen Namen eingeben.")
    rtype = rtype.upper() if rtype and rtype.upper() in DNS_TYPES else "A"
    argv = ["dig", "+time=3", "+tries=1", "+noall", "+answer", "+stats"]
    if server:
        argv.append("@" + _host(server))
    if rtype == "PTR":
        try:
            argv += ["-x", str(ipaddress.ip_address(name))]
        except ValueError:
            raise ToolError("Für PTR bitte eine IP-Adresse eingeben.") from None
    else:
        argv += [name, rtype]
    return _run(argv, timeout=15)


# --------------------------------------------------------------------------
# Speedtest (Server <-> Internet) ueber speed.cloudflare.com
# --------------------------------------------------------------------------

SPEED_HOST = "https://speed.cloudflare.com"


def speedtest(down_bytes: int = 25_000_000, up_bytes: int = 8_000_000) -> dict:
    opener = urllib.request.build_opener()
    opener.addheaders = [("User-Agent", "vpn-server-speedtest")]
    result: dict = {"server": SPEED_HOST}
    # Latenz: kleinste Antwortzeit von 5 kleinen Anfragen
    lat = []
    for _ in range(5):
        t0 = time.monotonic()
        try:
            with opener.open(f"{SPEED_HOST}/__down?bytes=0", timeout=5) as resp:
                resp.read()
            lat.append((time.monotonic() - t0) * 1000)
        except OSError:
            pass
    if not lat:
        raise ToolError("speed.cloudflare.com ist nicht erreichbar.")
    result["latency_ms"] = round(min(lat), 1)
    t0 = time.monotonic()
    got = 0
    with opener.open(f"{SPEED_HOST}/__down?bytes={down_bytes}", timeout=30) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            got += len(chunk)
            if time.monotonic() - t0 > 20:
                break
    secs = max(time.monotonic() - t0, 0.001)
    result["down_mbit"] = round(got * 8 / secs / 1e6, 1)
    data = b"0" * up_bytes
    req = urllib.request.Request(f"{SPEED_HOST}/__up", data=data, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    t0 = time.monotonic()
    with opener.open(req, timeout=40) as resp:
        resp.read()
    secs = max(time.monotonic() - t0, 0.001)
    result["up_mbit"] = round(len(data) * 8 / secs / 1e6, 1)
    return result


# --------------------------------------------------------------------------
# Wake-on-LAN
# --------------------------------------------------------------------------

def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip()
    if not MAC_RE.match(mac):
        raise ToolError("Ungültige MAC-Adresse (z. B. 00:11:22:33:44:55).")
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def wake(mac: str) -> str:
    mac = normalize_mac(mac)
    payload = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
    targets = {"255.255.255.255"}
    info = util.default_route_info()
    if info.get("ip"):
        net = ipaddress.ip_interface(f"{info['ip']}/{info.get('prefixlen', 24)}").network
        targets.add(str(net.broadcast_address))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for t in sorted(targets):
            for port in (9, 7):
                s.sendto(payload, (t, port))
    return f"Weckpaket für {mac} gesendet ({', '.join(sorted(targets))}, UDP 9 und 7)."


# --------------------------------------------------------------------------
# Paketmitschnitt
# --------------------------------------------------------------------------

def capture_interfaces() -> list[str]:
    res = util.run(["ip", "-j", "link", "show"])
    try:
        names = [l["ifname"] for l in json.loads(res.stdout or "[]")]
    except (ValueError, KeyError):
        names = []
    return ["any"] + [n for n in names if n != "lo"]


def capture(iface: str, seconds: int, expr: str, max_bytes: int = 25_000_000) -> bytes:
    if iface not in capture_interfaces():
        raise ToolError("Unbekannte Schnittstelle.")
    seconds = max(1, min(int(seconds or 10), 60))
    expr = (expr or "").strip()
    if not FILTER_RE.match(expr):
        raise ToolError("Ungültiger Filter (erlaubt z. B.: udp port 51820, host 192.168.1.10).")
    argv = ["timeout", str(seconds), "tcpdump", "-i", iface, "-U", "-s", "262144", "-w", "-"]
    if expr:
        argv += expr.split()
    try:
        res = subprocess.run(argv, capture_output=True, timeout=seconds + 10)
    except FileNotFoundError:
        raise ToolError("tcpdump ist nicht installiert.") from None
    data = res.stdout[:max_bytes]
    if not data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1")):
        raise ToolError("Mitschnitt fehlgeschlagen: " + res.stderr.decode(errors="replace")[-300:])
    return data
