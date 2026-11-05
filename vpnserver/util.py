"""Hilfsfunktionen: Pfade, atomares Schreiben, Prozesse, Zufallswerte, Validierung."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile

log = logging.getLogger("vpnserver")

# Alle Systempfade lassen sich fuer Tests unter ein anderes Wurzelverzeichnis legen.
ROOT = os.environ.get("VPNSERVER_ROOT", "")
# Im Dry-Run werden keine Dienste gestartet/gestoppt (Tests, Image-Bau).
DRYRUN = os.environ.get("VPNSERVER_DRYRUN", "") == "1"


def P(path: str) -> str:
    """Pfad unterhalb des (optionalen) Test-Wurzelverzeichnisses."""
    if ROOT:
        return os.path.join(ROOT, path.lstrip("/"))
    return path


ETC = "/etc/vpn-server"
STATE_FILE = ETC + "/state.json"
PKI_DIR = ETC + "/pki"
RUN_DIR = "/run/vpn-server"


def write_file(path: str, content: str | bytes, mode: int = 0o644,
               owner: tuple[int, int] | None = None) -> bool:
    """Schreibt eine Datei atomar. Gibt True zurueck, wenn sich der Inhalt geaendert hat."""
    real = P(path)
    data = content.encode() if isinstance(content, str) else content
    try:
        with open(real, "rb") as fh:
            if fh.read() == data:
                st = os.stat(real)
                if (st.st_mode & 0o7777) != mode:
                    os.chmod(real, mode)
                return False
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(real) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(real) or ".", prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if owner and os.geteuid() == 0 and not ROOT:
            os.chown(tmp, owner[0], owner[1])
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return True


def read_file(path: str, default: str | None = None) -> str | None:
    try:
        with open(P(path), encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return default


def remove_file(path: str) -> bool:
    try:
        os.unlink(P(path))
        return True
    except FileNotFoundError:
        return False


def run(cmd: list[str], check: bool = False, input: str | None = None,
        timeout: int = 60) -> subprocess.CompletedProcess:
    """Fuehrt ein Kommando aus und protokolliert Fehler."""
    log.debug("run: %s", " ".join(cmd))
    try:
        res = subprocess.run(cmd, input=input, capture_output=True, text=True,
                             timeout=timeout)
    except FileNotFoundError:
        res = subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: nicht gefunden")
    except subprocess.TimeoutExpired:
        res = subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: Zeitueberschreitung")
    if res.returncode != 0:
        log.warning("Kommando fehlgeschlagen (%s): %s %s", res.returncode,
                    " ".join(cmd), (res.stderr or "").strip()[:500])
        if check:
            raise RuntimeError(f"{' '.join(cmd)}: {(res.stderr or res.stdout).strip()}")
    return res


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# --------------------------------------------------------------------------
# Zufallswerte
# --------------------------------------------------------------------------

# Ohne leicht verwechselbare Zeichen (0/O, 1/l/I), damit Passwoerter abtippbar sind.
_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def gen_password(length: int = 16) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def gen_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# --------------------------------------------------------------------------
# Validierung
# --------------------------------------------------------------------------

CLIENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
# Zeichen, die in allen Konfigurationsformaten (swanctl, chap-secrets, ocpasswd,
# PowerShell, XML) gefahrlos verwendet werden koennen.
PASSWORD_RE = re.compile(r"^[A-Za-z0-9\-_.:!+=@%^*?,/~]{8,64}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def valid_client_name(name: str) -> bool:
    return bool(CLIENT_NAME_RE.match(name or ""))


def valid_password(pw: str) -> bool:
    return bool(PASSWORD_RE.match(pw or ""))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_host(value: str) -> bool:
    if not value:
        return False
    if is_ip(value):
        return True
    return bool(HOSTNAME_RE.match(value))


def valid_port(value) -> bool:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= v <= 65535


def valid_ipv4_subnet(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return net.version == 4 and 16 <= net.prefixlen <= 28


# --------------------------------------------------------------------------
# Netzwerk-Informationen
# --------------------------------------------------------------------------

def default_route_info() -> dict:
    """Ermittelt Interface, lokale IP und Gateway der Default-Route."""
    info = {"dev": "", "ip": "", "gateway": "", "prefixlen": 24}
    res = run(["ip", "-j", "route", "get", "1.1.1.1"])
    if res.returncode == 0:
        try:
            data = json.loads(res.stdout)[0]
            info["dev"] = data.get("dev", "")
            info["ip"] = data.get("prefsrc", "")
            info["gateway"] = data.get("gateway", "")
        except (ValueError, IndexError, KeyError):
            pass
    if info["dev"]:
        res = run(["ip", "-j", "-4", "addr", "show", "dev", info["dev"]])
        if res.returncode == 0:
            try:
                for addr in json.loads(res.stdout)[0].get("addr_info", []):
                    if addr.get("local") == info["ip"]:
                        info["prefixlen"] = addr.get("prefixlen", 24)
            except (ValueError, IndexError):
                pass
    if not info["ip"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))
            info["ip"] = s.getsockname()[0]
            s.close()
        except OSError:
            pass
    return info


def local_ipv4_addresses() -> list[str]:
    res = run(["ip", "-j", "-4", "addr", "show", "scope", "global"])
    out = []
    if res.returncode == 0:
        try:
            for iface in json.loads(res.stdout):
                name = iface.get("ifname", "")
                if name.startswith(("wg", "ovpn", "vpns", "ppp", "l2tp", "sstp", "pptp")):
                    continue
                for addr in iface.get("addr_info", []):
                    if addr.get("local"):
                        out.append(addr["local"])
        except ValueError:
            pass
    return out


def system_nameservers() -> list[str]:
    """Nameserver aus resolv.conf (ohne lokale Stub-Resolver)."""
    out = []
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        content = read_file(path)
        if not content:
            continue
        for line in content.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                ns = parts[1]
                try:
                    ip = ipaddress.ip_address(ns)
                except ValueError:
                    continue
                if ip.is_loopback or ip.version != 4:
                    continue
                if ns not in out:
                    out.append(ns)
        if out:
            break
    return out


def ipv6_available() -> bool:
    return os.path.exists("/proc/net/if_inet6")


def hostname() -> str:
    return socket.gethostname()
