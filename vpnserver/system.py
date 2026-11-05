"""Systemfunktionen: Konsolen-Banner, oeffentliche IP, DynDNS, Let's Encrypt,
Netzwerkkonfiguration, Sicherung/Wiederherstellung, Neustart, Updates."""

from __future__ import annotations

import base64
import datetime as dt
import io
import ipaddress
import json
import os
import shutil
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

from . import pki, util
from .util import P, log

ISSUE_FILE = "/etc/issue"
UPDATE_LOG = "/var/log/vpn-server-update.log"
LE_LOG = "/var/log/vpn-server-letsencrypt.log"


# --------------------------------------------------------------------------
# Konsolen-Banner (/etc/issue)
# --------------------------------------------------------------------------

def write_issue(state: dict) -> None:
    port = state["server"].get("webui_port", 8443)
    hn = util.hostname() or "vpn-server"
    lines = [
        "",
        "  ==========================================================",
        "   VPN-Server  (\\n)",
        "  ==========================================================",
        "",
        f"   Weboberflaeche:   https://\\4:{port}",
        f"                     https://{hn}.local:{port}",
        "",
    ]
    initial = state["admin"].get("initial_password")
    if initial and state["admin"].get("must_change", True):
        lines += [
            f"   Benutzer:         {state['admin'].get('username', 'admin')}",
            f"   Initialpasswort:  {initial}",
            "",
            "   Das Passwort gilt fuer die Weboberflaeche sowie fuer die",
            "   Konsole/SSH (Benutzer 'vpnadmin') und muss bei der ersten",
            "   Anmeldung geaendert werden.",
            "",
        ]
    lines += [
        "   Passwort vergessen?  Auf der Konsole als vpnadmin anmelden:",
        "                        sudo vpnctl admin-password",
        "",
        "",
    ]
    util.write_file(ISSUE_FILE, "\n".join(lines), mode=0o644)


def set_system_password(user: str, password: str) -> bool:
    if util.DRYRUN:
        return True
    res = util.run(["chpasswd"], input=f"{user}:{password}\n")
    return res.returncode == 0


# --------------------------------------------------------------------------
# Oeffentliche IP / DynDNS
# --------------------------------------------------------------------------

IP_SERVICES = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip",
               "https://v4.ident.me"]


def _http_get(url: str, timeout: int = 8, auth: tuple[str, str] | None = None) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-server/1.0"})
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (feste URLs)
        return resp.read(4096).decode(errors="replace").strip()


def detect_public_ip() -> str:
    for url in IP_SERVICES:
        try:
            value = _http_get(url, timeout=5)
            ip = ipaddress.ip_address(value)
            if ip.version == 4 and ip.is_global:
                return str(ip)
        except (OSError, ValueError, urllib.error.URLError):
            continue
    return ""


DDNS_PROVIDERS = {
    "none": "Kein DynDNS",
    "duckdns": "DuckDNS (duckdns.org)",
    "dynv6": "dynv6 (dynv6.com)",
    "ipv64": "IPv64 (ipv64.net)",
    "noip": "No-IP / DynDNS2-kompatibel",
    "custom": "Eigene Update-URL",
}


def _ddns_url(cfg: dict, ip: str) -> tuple[str, tuple[str, str] | None]:
    q = urllib.parse.quote
    p = cfg.get("provider")
    domain, token = cfg.get("domain", ""), cfg.get("token", "")
    if p == "duckdns":
        sub = domain.replace(".duckdns.org", "")
        return f"https://www.duckdns.org/update?domains={q(sub)}&token={q(token)}&ip={ip}", None
    if p == "dynv6":
        return f"https://dynv6.com/api/update?hostname={q(domain)}&token={q(token)}&ipv4={ip}", None
    if p == "ipv64":
        return f"https://ipv64.net/nic/update?key={q(token)}&domain={q(domain)}&ip={ip}", None
    if p == "noip":
        server = cfg.get("url") or "https://dynupdate.no-ip.com/nic/update"
        return (f"{server}?hostname={q(domain)}&myip={ip}",
                (cfg.get("username", ""), cfg.get("password", "")))
    if p == "custom":
        url = cfg.get("url", "").replace("{ip}", ip).replace("{domain}", q(domain))
        return url.replace("{token}", q(token)), None
    return "", None


def ddns_update(state: dict, force: bool = False) -> str:
    cfg = state["ddns"]
    if cfg.get("provider", "none") == "none":
        return "DynDNS ist deaktiviert."
    ip = detect_public_ip()
    if not ip:
        cfg["last_result"] = "Öffentliche IP konnte nicht ermittelt werden."
        return cfg["last_result"]
    if ip == cfg.get("last_ip") and not force:
        return f"Unverändert ({ip})."
    url, auth = _ddns_url(cfg, ip)
    if not url.startswith("https://") and not url.startswith("http://"):
        cfg["last_result"] = "Ungültige Update-URL."
        return cfg["last_result"]
    try:
        answer = _http_get(url, auth=auth)
        ok = not any(w in answer.lower() for w in ("ko", "badauth", "nohost", "error", "invalid",
                                                    "abuse", "fail"))
        if answer.lower().startswith(("ok", "good", "nochg")) or "updated" in answer.lower():
            ok = True
    except (OSError, urllib.error.URLError) as exc:
        answer, ok = str(exc), False
    now = dt.datetime.now().strftime("%d.%m.%Y %H:%M")
    cfg["last_update"] = now
    cfg["last_result"] = ("OK: " if ok else "Fehler: ") + answer[:200]
    if ok:
        cfg["last_ip"] = ip
    return cfg["last_result"]


# --------------------------------------------------------------------------
# Let's Encrypt
# --------------------------------------------------------------------------

def letsencrypt_request(state: dict) -> tuple[bool, str]:
    host = state["server"].get("public_host", "")
    if not host or util.is_ip(host):
        return False, "Fuer Let's Encrypt wird ein DNS-Name (z. B. DynDNS) als öffentliche Adresse benötigt."
    if not util.have("certbot"):
        return False, "certbot ist nicht installiert."
    cmd = ["certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
           "--preferred-challenges", "http", "--cert-name", "vpn-server", "-d", host,
           "--keep-until-expiring", "--expand",
           "--deploy-hook", "/usr/local/sbin/vpnctl apply --quiet"]
    email = state["letsencrypt"].get("email", "").strip()
    cmd += ["--email", email] if email else ["--register-unsafely-without-email"]
    res = util.run(cmd, timeout=300)
    util.write_file(LE_LOG, (res.stdout or "") + "\n" + (res.stderr or ""), mode=0o600)
    if res.returncode == 0 and pki.le_available():
        return True, "Zertifikat erfolgreich ausgestellt."
    err = (res.stderr or res.stdout or "").strip().splitlines()
    detail = " ".join(err[-6:])[:600]
    return False, ("Let's Encrypt fehlgeschlagen. Ist Port 80/TCP am Router auf diesen Server "
                   "weitergeleitet und zeigt der DNS-Name auf Ihre öffentliche IP? " + detail)


def le_cert_info() -> dict:
    if not pki.le_available():
        return {}
    try:
        from cryptography import x509
        with open(P(pki.LE_LIVE + "/cert.pem"), "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        try:
            na = cert.not_valid_after_utc
        except AttributeError:
            na = cert.not_valid_after
        return {"not_after": na.strftime("%d.%m.%Y")}
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------------
# Netzwerk
# --------------------------------------------------------------------------

INTERFACES = "/etc/network/interfaces"


def network_info() -> dict:
    info = util.default_route_info()
    info["dns"] = util.system_nameservers()
    content = util.read_file(INTERFACES) or ""
    info["manager"] = "ifupdown" if content and util.have("ifup") else (
        "netplan" if os.path.isdir(P("/etc/netplan")) else "unbekannt")
    info["method"] = "dhcp"
    if info["dev"] and f"iface {info['dev']} inet static" in content:
        info["method"] = "static"
    return info


def set_network(dev: str, method: str, address: str = "", prefixlen: int = 24,
                gateway: str = "", dns: list[str] | None = None) -> str:
    """Schreibt /etc/network/interfaces (nur Debian/ifupdown) und startet das
    Interface verzoegert neu."""
    info = network_info()
    if info["manager"] != "ifupdown":
        raise ValueError("Die Netzwerkkonfiguration ist nur unter Debian (ifupdown) möglich. "
                         "Bitte eine DHCP-Reservierung im Router verwenden.")
    if not dev or "/" in dev or " " in dev:
        raise ValueError("Ungültiges Interface.")
    lines = ["# Verwaltet von VPN-Server", "source /etc/network/interfaces.d/*", "",
             "auto lo", "iface lo inet loopback", "", f"auto {dev}"]
    if method == "static":
        ipaddress.ip_interface(f"{address}/{prefixlen}")
        ipaddress.ip_address(gateway)
        lines += [f"iface {dev} inet static", f"    address {address}/{prefixlen}",
                  f"    gateway {gateway}"]
    else:
        lines += [f"iface {dev} inet dhcp"]
    lines += [f"iface {dev} inet6 auto", ""]
    if not util.DRYRUN:
        shutil.copy(P(INTERFACES), P(INTERFACES + ".bak"))
    util.write_file(INTERFACES, "\n".join(lines), mode=0o644)
    if method == "static" and dns:
        for d in dns:
            ipaddress.ip_address(d)
        util.write_file("/etc/resolv.conf", "".join(f"nameserver {d}\n" for d in dns), mode=0o644)
    if not util.DRYRUN:
        util.run(["systemd-run", "--on-active=3", "--unit=vpn-network-restart", "--collect",
                  "/bin/sh", "-c",
                  f"ifdown --force {dev}; ip addr flush dev {dev}; ifup {dev}; "
                  "systemctl restart vpn-webui.service"])
    return address if method == "static" else ""


# --------------------------------------------------------------------------
# Sicherung / Wiederherstellung
# --------------------------------------------------------------------------

def backup_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(P(util.ETC), arcname="vpn-server",
                filter=lambda ti: None if ti.name.endswith("/.lock") else ti)
        meta = json.dumps({"created": dt.datetime.now().isoformat(), "format": 1}).encode()
        ti = tarfile.TarInfo("vpn-server-backup.json")
        ti.size = len(meta)
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(meta))
    return buf.getvalue()


def restore_bytes(data: bytes) -> None:
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise ValueError("Keine gültige Sicherungsdatei.") from exc
    with tar:
        names = tar.getnames()
        if "vpn-server/state.json" not in names:
            raise ValueError("Die Sicherung enthaelt keine vpn-server/state.json.")
        for m in tar.getmembers():
            if not (m.name == "vpn-server-backup.json" or m.name == "vpn-server"
                    or m.name.startswith("vpn-server/")):
                raise ValueError(f"Unerwarteter Eintrag in der Sicherung: {m.name}")
            if m.issym() or m.islnk() or m.isdev():
                raise ValueError("Sicherung enthaelt unzulässige Dateitypen.")
        json.loads(tar.extractfile("vpn-server/state.json").read())
        # Aktuellen Stand sichern
        bdir = P("/var/backups")
        os.makedirs(bdir, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        with open(os.path.join(bdir, f"vpn-server-{stamp}.tar.gz"), "wb") as fh:
            fh.write(backup_bytes())
        tmp = P(util.ETC + ".restore")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        try:
            tar.extractall(tmp, filter="data")
        except TypeError:  # Python < 3.11.4
            tar.extractall(tmp)  # noqa: S202 (Eintraege oben geprueft)
    old = P(util.ETC + ".old")
    shutil.rmtree(old, ignore_errors=True)
    os.rename(P(util.ETC), old)
    os.rename(os.path.join(tmp, "vpn-server"), P(util.ETC))
    shutil.rmtree(tmp, ignore_errors=True)
    os.chmod(P(util.ETC), 0o711)


# --------------------------------------------------------------------------
# Neustart / Updates
# --------------------------------------------------------------------------

def schedule(action: str) -> None:
    if util.DRYRUN:
        return
    if action in ("reboot", "poweroff"):
        util.run(["systemd-run", "--on-active=3", "--unit=vpn-power", "--collect",
                  "systemctl", action])


def start_update() -> None:
    if util.DRYRUN:
        return
    script = ("export DEBIAN_FRONTEND=noninteractive; "
              "echo \"=== Update gestartet: $(date) ===\"; apt-get update && "
              "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
              "full-upgrade && apt-get -y autoremove; "
              "echo \"=== Fertig (Exit $?): $(date) ===\"; "
              "[ -f /var/run/reboot-required ] && echo 'Neustart erforderlich.'")
    util.run(["systemd-run", "--unit=vpn-update", "--collect",
              "--property=StandardOutput=file:" + UPDATE_LOG,
              "--property=StandardError=file:" + UPDATE_LOG, "/bin/bash", "-c", script])


def update_running() -> bool:
    if util.DRYRUN:
        return False
    return util.run(["systemctl", "is-active", "--quiet", "vpn-update.service"]).returncode == 0


def reboot_required() -> bool:
    return os.path.exists(P("/var/run/reboot-required"))


def uptime() -> str:
    try:
        secs = float((util.read_file("/proc/uptime") or "0").split()[0])
    except ValueError:
        return ""
    days, rem = divmod(int(secs), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days} Tage, {hours} Std., {rem // 60} Min." if days else f"{hours} Std., {rem // 60} Min."


def os_name() -> str:
    for line in (util.read_file("/etc/os-release") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')
    return "Linux"


def journal(unit: str, lines: int = 150) -> str:
    if util.DRYRUN:
        return ""
    res = util.run(["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"])
    out = res.stdout or res.stderr
    if unit == "accel-ppp.service":
        log_file = util.read_file("/var/log/accel-ppp/accel-ppp.log") or ""
        out += "\n--- /var/log/accel-ppp/accel-ppp.log ---\n" + "\n".join(log_file.splitlines()[-lines:])
    return out
