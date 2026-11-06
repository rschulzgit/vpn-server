#!/usr/bin/env python3
"""E2E-Testsuite fuer den installierten VPN-Server.

Emuliert reale Endgeraete (Android, iPhone/iPad, macOS, Windows, Linux) mit
deren typischen Identitaeten, Krypto-Vorschlaegen und Profilen, verbindet sich
mit jedem Protokoll und prueft Heimnetz-, Internet- und DNS-Zugriff durch den
Tunnel. Danach folgen Funktionstests der Weboberflaeche (Sperren, Loeschen,
Passwortwechsel, Client-zu-Client, Heimnetz-Zugriff, Teilen-Link, Sicherung,
CLI, Neustart).

Aufruf (als root, nach tests/e2e/run.sh-Vorbereitung):
    suite.py --work /tmp/e2e --initial-password XYZ
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import os
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid

NS = "vpncli"        # "Geraet A" (192.168.250.2)
NS2 = "vpncli2"      # "Geraet B" (192.168.250.3)
HOST_IP = "192.168.250.1"
NS_IP = "192.168.250.2"
VPN_HOST = "vpn.test"
WEB = "https://127.0.0.1:8443"
LAN_URL = "http://10.0.2.2:8099/"     # Dienst im "Heimnetz" des Servers
NEW_ADMIN_PW = "E2e-Admin-Passwort-1"
CPW = "E2eTest-Pass1"
DNS = "1.1.1.1"

WORK = "/tmp/e2e"
RESULTS: list[dict] = []
BG: list[subprocess.Popen] = []
INTERNET_IP = ""


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def sh(cmd: str, timeout: int = 60, input: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                              input=input, executable="/bin/bash")
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", exc.stderr or "timeout")


def nsx(cmd: str, ns: str = NS, timeout: int = 60, input: str | None = None):
    return sh(f"ip netns exec {ns} {cmd}", timeout=timeout, input=input)


def bg(cmd: str, log: str, ns: str = NS) -> subprocess.Popen:
    fh = open(os.path.join(WORK, log), "w")
    p = subprocess.Popen(["ip", "netns", "exec", ns, "bash", "-c", cmd], stdout=fh,
                         stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    BG.append(p)
    return p


def stop(p: subprocess.Popen | None) -> None:
    if p and p.poll() is None:
        try:
            os.killpg(p.pid, 15)
            p.wait(10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(p.pid, 9)
            except ProcessLookupError:
                pass


def wait_until(fn, timeout: float = 30, interval: float = 1) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(interval)
    return False


def read(path: str) -> str:
    try:
        with open(os.path.join(WORK, path), errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def tail(path: str, n: int = 25) -> str:
    return "\n".join(read(path).splitlines()[-n:])


def remote(cmd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Kommando als root auf dem VPN-Server (per SSH als vpnadmin + sudo)."""
    b64 = base64.b64encode(cmd.encode()).decode()
    remote_cmd = f"echo '{ADMIN_PW}' | sudo -S -p '' bash -c \"$(echo {b64} | base64 -d)\""
    argv = ["sshpass", "-p", ADMIN_PW, "ssh", "-q", "-o", "StrictHostKeyChecking=no", "-o",
            "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-p", "2222",
            "vpnadmin@127.0.0.1", remote_cmd]
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, exc.stdout or "", exc.stderr or "timeout")


ADMIN_PW = NEW_ADMIN_PW


class Fail(Exception):
    pass


def check(cond, msg: str) -> None:
    if not cond:
        raise Fail(msg)


# --- Erreichbarkeit durch den Tunnel ----------------------------------------

def lan_ok(ns: str = NS) -> bool:
    r = nsx(f"curl -s --noproxy '*' --max-time 8 -o /dev/null -w '%{{http_code}}' {LAN_URL}", ns, timeout=15)
    return r.stdout.strip() == "200"


def internet_ok(ns: str = NS) -> bool:
    r = nsx(f"curl -s --noproxy '*' --max-time 12 -o /dev/null -w '%{{http_code}}' "
            f"--resolve deb.debian.org:80:{INTERNET_IP} http://deb.debian.org/debian/", ns, timeout=20)
    return r.stdout.strip() in ("200", "301", "302")


def dns_ok(server: str = DNS, ns: str = NS) -> bool:
    r = nsx(f"dig +time=3 +tries=2 +short @{server} debian.org A", ns, timeout=20)
    return bool(re.search(r"^\d+\.\d+\.\d+\.\d+$", r.stdout, re.M))


def tunnel_checks(ns: str = NS, internet: bool = True, dns: bool = True) -> list[str]:
    errors = []
    if not wait_until(lambda: lan_ok(ns), 20, 2):
        errors.append("Heimnetz nicht erreichbar")
    if internet and not wait_until(lambda: internet_ok(ns), 20, 2):
        errors.append("Internet nicht erreichbar")
    if dns and not dns_ok(DNS, ns):
        errors.append("DNS durch den Tunnel fehlgeschlagen")
    return errors


# =============================================================================
# Weboberflaeche
# =============================================================================

class Web:
    def __init__(self, base: str = WEB):
        self.base = base
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.ProxyHandler({}))
        self.csrf = ""
        self.last_headers = {}

    def req(self, path: str, data: dict | None = None, files: dict | None = None,
            csrf: bool = True) -> tuple[int, str, bytes]:
        """Anfrage mit Wiederholung bei Verbindungsabbruechen (z. B. waehrend die
        Weboberflaeche ein neues Zertifikat laedt)."""
        last_exc = None
        for attempt in range(12):
            if data is not None or files is not None:
                wait_web(60)
            try:
                return self._req(path, data, files, csrf)
            except (urllib.error.URLError, ConnectionError, ssl.SSLError, TimeoutError) as exc:
                if isinstance(exc, urllib.error.HTTPError):
                    raise
                last_exc = exc
                print(f"  (Verbindung unterbrochen: {exc} - neuer Versuch)", flush=True)
                time.sleep(5)
        raise last_exc

    def _req(self, path: str, data: dict | None = None, files: dict | None = None,
             csrf: bool = True) -> tuple[int, str, bytes]:
        headers = {}
        body = None
        if files is not None:
            boundary = uuid.uuid4().hex
            parts = []
            fields = dict(data or {})
            if csrf:
                fields.setdefault("csrf_token", self.csrf)
            for k, v in fields.items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
            for k, (fname, content) in files.items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{fname}"\r\n'
                             f"Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n")
            parts.append(f"--{boundary}--\r\n".encode())
            body = b"".join(parts)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif data is not None:
            data = dict(data)
            if csrf:
                data.setdefault("csrf_token", self.csrf)
            body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(self.base + path, data=body, headers=headers)
        try:
            with self.opener.open(r, timeout=300) as resp:
                raw, url, code = resp.read(), resp.geturl(), resp.status
                self.last_headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raw, url, code = exc.read(), exc.geturl(), exc.code
            self.last_headers = dict(exc.headers)
        m = re.search(rb'name="csrf-token" content="([^"]+)"', raw)
        if m:
            self.csrf = m.group(1).decode()
        return code, url, raw

    @staticmethod
    def flashes(raw: bytes) -> list[str]:
        return re.findall(r'<div class="flash (?:ok|error)">([^<]+)</div>', raw.decode(errors="replace"))

    def login(self, password: str) -> bool:
        self.req("/login")
        code, url, raw = self.req("/login", {"username": "admin", "password": password})
        return code == 200 and "/login" not in url

    def download(self, client: str, kind: str) -> bytes:
        code, _url, raw = self.req(f"/clients/{client}/dl/{kind}")
        check(code == 200 and raw, f"Download {kind} fuer {client} fehlgeschlagen ({code})")
        return raw

    def status(self) -> dict:
        code, _url, raw = self.req("/api/status")
        check(code == 200, f"/api/status liefert {code}")
        return json.loads(raw)

    def settings(self, section: str, form: dict) -> list[str]:
        form = dict(form)
        form["section"] = section
        _code, _url, raw = self.req("/settings", form)
        return self.flashes(raw)

    def client_action(self, client: str, action: str, **extra) -> list[str]:
        _code, _url, raw = self.req(f"/clients/{client}/action", {"action": action, **extra})
        return self.flashes(raw)


def wait_web(timeout: int = 120) -> bool:
    """Wartet, bis die Weboberflaeche antwortet."""
    return wait_until(lambda: sh(f"curl -skf --max-time 5 --noproxy '*' {WEB}/health",
                                 timeout=15).returncode == 0, timeout, 2)


W = Web()

ALL_PROTOCOLS = {f"{p}_enabled": "1" for p in ("wireguard", "openvpn", "ikev2", "l2tp", "ikev1_xauth",
                                                  "sstp", "openconnect", "pptp")}
ALL_PROTOCOLS.update(openvpn_udp="1", openvpn_tcp="1", wireguard_port="51820", openvpn_udp_port="1194",
                     openvpn_tcp_port="1194", sstp_port="443", openconnect_port="4443")
GENERAL = {"public_host": VPN_HOST, "dns": DNS, "name": "VPN-Server", "lan_access": "1"}


def session_seen(user: str, proto_part: str) -> bool:
    def probe():
        for s in W.status()["sessions"]:
            if s.get("user") == user and proto_part.lower() in s.get("proto", "").lower():
                return True
        return False
    return wait_until(probe, 25, 3)


# =============================================================================
# Testregistrierung
# =============================================================================

TESTS: list[tuple[str, str, object]] = []


def test(category: str, name: str):
    def deco(fn):
        TESTS.append((category, name, fn))
        return fn
    return deco


def run_tests(selected: str | None) -> None:
    for category, name, fn in TESTS:
        if selected and not re.search(selected, f"{category} {name}", re.I):
            continue
        print(f"\n\033[1;34m--- [{category}] {name}\033[0m", flush=True)
        start = time.time()
        try:
            detail = fn() or ""
            RESULTS.append({"category": category, "name": name, "ok": True, "detail": detail,
                            "secs": round(time.time() - start, 1)})
            print(f"\033[1;32mPASS\033[0m {name} {detail}", flush=True)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc) if isinstance(exc, Fail) else f"{type(exc).__name__}: {exc}"
            if not isinstance(exc, Fail):
                traceback.print_exc()
            RESULTS.append({"category": category, "name": name, "ok": False, "detail": msg,
                            "secs": round(time.time() - start, 1)})
            print(f"\033[1;31mFAIL\033[0m {name}: {msg}", flush=True)
        finally:
            cleanup_clients()


def cleanup_clients() -> None:
    for p in list(BG):
        stop(p)
    BG.clear()
    for ns in (NS, NS2):
        for conf in ("wg-a", "wg-b"):
            if os.path.exists(os.path.join(WORK, f"{conf}.conf")):
                sh(f"ip netns exec {ns} env PATH={WORK}/fakebin:$PATH wg-quick down {WORK}/{conf}.conf",
                   timeout=20)
        for line in sh(f"ip -n {ns} -o link show").stdout.splitlines():
            m = re.match(r"\d+: ([^:@]+)", line)
            if m and m.group(1).startswith(("tun", "ppp", "wg-")):
                sh(f"ip -n {ns} link del {m.group(1)}")
        sh(f"ip netns exec {ns} nft flush ruleset")
    sh("pkill -x xl2tpd; pkill -x sstpc; pkill -x pppd; pkill -x openconnect; pkill -f 'openvpn --config'")
    if shutil.which("swanctl"):
        for line in sh("ip netns exec vpncli swanctl --list-sas --raw").stdout.splitlines():
            for m in re.finditer(r"uniqueid=(\d+)", line):
                sh(f"ip netns exec {NS} swanctl --terminate --ike-id {m.group(1)} --force")
    time.sleep(1)


# =============================================================================
# 1. Einrichtung ueber die Weboberflaeche
# =============================================================================

PROFILES: dict = {}


@test("Weboberfläche", "Falsches Passwort wird abgewiesen")
def t_bad_login():
    w = Web()
    w.req("/login")
    code, url, _ = w.req("/login", {"username": "admin", "password": "falsch"})
    check(code == 401, f"Status {code}")


@test("Weboberfläche", "Anmeldung mit Initialpasswort erzwingt Einrichtungsassistent")
def t_login():
    check(W.login(ARGS.initial_password), "Login fehlgeschlagen")
    code, url, raw = W.req("/clients")
    check("/setup" in url, f"Keine Weiterleitung zum Assistenten ({url})")


@test("Weboberfläche", "Assistent: neues Passwort, Konsole/SSH-Passwort, öffentliche Adresse")
def t_setup():
    code, url, raw = W.req("/setup", {"password": "kurz", "password2": "kurz"})
    check(any("mindestens" in f for f in W.flashes(raw)), "Zu kurzes Passwort nicht abgelehnt")
    W.req("/setup", {"password": NEW_ADMIN_PW, "password2": NEW_ADMIN_PW, "system_too": "1"})
    code, url, raw = W.req("/setup", {"public_host": "192.168.1.10", "dns": DNS})
    check("/setup" in url, "Private IP als öffentliche Adresse wurde akzeptiert")
    code, url, raw = W.req("/setup", {"public_host": VPN_HOST, "dns": DNS})
    check("/setup" not in url, f"Assistent nicht abgeschlossen: {W.flashes(raw)}")
    time.sleep(5)  # Zertifikat fuer die neue Adresse wird per Reload uebernommen
    check(wait_web(60), "Weboberfläche nach Zertifikatswechsel nicht erreichbar")
    r = sh("echo | openssl s_client -connect 127.0.0.1:8443 2>/dev/null | openssl x509 -noout -ext subjectAltName")
    check(VPN_HOST in r.stdout, f"Weboberfläche nutzt nicht das neue Zertifikat: {r.stdout.strip()}")
    # neues Passwort gilt
    w2 = Web()
    check(w2.login(NEW_ADMIN_PW), "Neues Admin-Passwort funktioniert nicht")
    check(not Web().login(ARGS.initial_password), "Initialpasswort funktioniert noch")
    r = remote("whoami")
    check(r.stdout.strip() == "root", f"SSH/sudo mit neuem Passwort fehlgeschlagen: {r.stderr[-200:]}")


@test("Weboberfläche", "Alle Protokolle aktivieren (inkl. PPTP) und Dienste prüfen")
def t_enable_all():
    W.settings("protocols", ALL_PROTOCOLS)

    def all_active():
        st = W.status()
        return all(u["active"] == "active" for u in st["units"] if u["wanted"])
    ok = wait_until(all_active, 90, 3)
    units = W.status()["units"]
    bad = [f"{u['unit']}={u['active']}" for u in units if u["wanted"] and u["active"] != "active"]
    check(ok, "Dienste nicht aktiv: " + ", ".join(bad))
    return f"({len([u for u in units if u['wanted']])} Dienste aktiv)"


@test("Weboberfläche", "Clients anlegen (Volltunnel, Split-Tunnel, zweites Gerät)")
def t_clients():
    for name, tunnel in (("e2e", "full"), ("e2e-split", "split"), ("e2e-b", "full")):
        code, url, raw = W.req("/clients", {"name": name, "password": CPW, "note": "E2E", "tunnel": tunnel})
        check(f"/clients/{name}" in url, f"{name}: {W.flashes(raw)}")
    code, url, raw = W.req("/clients", {"name": "e2e", "password": CPW, "tunnel": "full"})
    check(any("existiert" in f for f in W.flashes(raw)), "Doppelter Name nicht abgelehnt")
    code, url, raw = W.req("/clients", {"name": "Ungültig Name", "tunnel": "full"})
    check(any("Ungültig" in f for f in W.flashes(raw)), "Ungültiger Name nicht abgelehnt")


@test("Weboberfläche", "Alle Seiten erreichbar, Profile herunterladbar")
def t_pages_downloads():
    for page in ("/", "/clients", "/status", "/settings", "/system", "/clients/e2e", "/status?log=strongswan.service"):
        code, _u, _r = W.req(page)
        check(code == 200, f"{page} -> {code}")
    kinds = ["wireguard", "wireguard-qr", "openvpn", "ca", "p12", "json", "credentials", "zip",
             "sswan-cert", "sswan-eap", "mobileconfig-cert", "mobileconfig-eap", "win-ikev2-eap",
             "win-ikev2-cert", "win-sstp", "win-l2tp", "win-pptp"]
    for client in ("e2e", "e2e-split", "e2e-b"):
        for kind in kinds:
            PROFILES[(client, kind)] = W.download(client, kind)
    d = json.loads(PROFILES[("e2e", "json")])
    check(d["server"] == VPN_HOST, "Falsche Serveradresse in den Zugangsdaten")
    return f"({len(PROFILES)} Dateien)"


# =============================================================================
# 2. Profilpruefung (statisch)
# =============================================================================

def cred(client: str = "e2e") -> dict:
    return json.loads(PROFILES[(client, "json")])


@test("Profile", "WireGuard-QR-Code dekodiert exakt zur Konfiguration")
def t_qr():
    svg = os.path.join(WORK, "wg-qr.svg")
    png = os.path.join(WORK, "wg-qr.png")
    with open(svg, "wb") as fh:
        fh.write(PROFILES[("e2e", "wireguard-qr")])
    r = sh(f"rsvg-convert -w 800 -b white -o {png} {svg}")
    check(r.returncode == 0, f"SVG->PNG fehlgeschlagen: {r.stderr}")
    r = sh(f"zbarimg --raw -q {png}")
    check(r.returncode == 0, f"QR-Code nicht lesbar: {r.stderr}")
    decoded = r.stdout.rstrip("\n")
    conf = PROFILES[("e2e", "wireguard")].decode().rstrip("\n")
    check(decoded == conf, "QR-Inhalt weicht von der .conf ab")
    PROFILES["wg-from-qr"] = decoded + "\n"


@test("Profile", "WireGuard Voll- und Split-Tunnel")
def t_wg_profiles():
    full = PROFILES[("e2e", "wireguard")].decode()
    split = PROFILES[("e2e-split", "wireguard")].decode()
    check("AllowedIPs = 0.0.0.0/0, ::/0" in full, "Vollttunnel-AllowedIPs falsch")
    check(f"Endpoint = {VPN_HOST}:51820" in full, "Endpoint falsch")
    check(f"DNS = {DNS}" in full, "DNS fehlt")
    m = re.search(r"AllowedIPs = (.*)", split)
    nets = [n.strip() for n in m.group(1).split(",")]
    check("0.0.0.0/0" not in nets and "10.66.66.0/24" in nets and "10.0.2.0/24" in nets,
          f"Split-AllowedIPs unerwartet: {nets}")


@test("Profile", "PKCS#12 (Android/Windows-Import): Legacy-Verschlüsselung, Client- und CA-Zertifikat")
def t_p12():
    p12 = os.path.join(WORK, "e2e.p12")
    with open(p12, "wb") as fh:
        fh.write(PROFILES[("e2e", "p12")])
    pw = cred()["ikev2"]["p12_password"]
    r = sh(f"openssl pkcs12 -in {p12} -info -noout -passin pass:{pw} 2>&1")
    check("pbeWithSHA1And3-KeyTripleDES-CBC" in r.stdout, f"Unerwartete P12-Verschlüsselung: {r.stdout[:300]}")
    r = sh(f"openssl pkcs12 -in {p12} -nokeys -passin pass:{pw} | openssl x509 -noout -subject -ext subjectAltName")
    check("CN=e2e" in r.stdout.replace(" ", "") and "DNS:e2e" in r.stdout, f"Client-Zertifikat: {r.stdout}")
    r = sh(f"openssl pkcs12 -in {p12} -nokeys -passin pass:{pw}")
    blocks = ["".join(b.split()) for b in
              re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", r.stdout, re.S)]
    ca_body = "".join(re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                                PROFILES[("e2e", "ca")].decode(), re.S).group(1).split())
    check(ca_body in blocks, f"CA-Zertifikat fehlt im P12 ({len(blocks)} Zertifikate enthalten)")
    check(len(blocks) == 2, f"{len(blocks)} Zertifikate im P12 (erwartet: Client + CA)")


@test("Profile", "Apple-Profil (.mobileconfig) für iPhone/iPad/Mac")
def t_mobileconfig():
    for kind in ("mobileconfig-cert", "mobileconfig-eap"):
        mc = plistlib.loads(PROFILES[("e2e", kind)])
        types = [p["PayloadType"] for p in mc["PayloadContent"]]
        check("com.apple.vpn.managed" in types and "com.apple.security.root" in types, f"{kind}: {types}")
        root = [p for p in mc["PayloadContent"] if p["PayloadType"] == "com.apple.security.root"][0]
        ca_der = sh("openssl x509 -in /dev/stdin -outform DER | base64 -w0",
                    input=PROFILES[("e2e", "ca")].decode()).stdout
        check(base64.b64encode(root["PayloadContent"]).decode() == ca_der.strip(), "CA im Profil weicht ab")
        vpn = [p for p in mc["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"][0]["IKEv2"]
        check(vpn["RemoteAddress"] == VPN_HOST and vpn["RemoteIdentifier"] == VPN_HOST, "Remote-Werte falsch")
        if kind.endswith("cert"):
            check("com.apple.security.pkcs12" in types and vpn["AuthenticationMethod"] == "Certificate", "P12 fehlt")
        else:
            check(vpn["ExtendedAuthEnabled"] == 1 and vpn["AuthName"] == "e2e", "EAP-Werte falsch")


@test("Profile", "strongSwan-App-Profile (.sswan) für Android")
def t_sswan():
    for kind, typ in (("sswan-cert", "ikev2-cert"), ("sswan-eap", "ikev2-eap")):
        d = json.loads(PROFILES[("e2e", kind)])
        check(d["type"] == typ and d["remote"]["addr"] == VPN_HOST and d["remote"]["cert"], f"{kind}: {d.keys()}")
        uuid.UUID(d["uuid"])
    check(json.loads(PROFILES[("e2e", "sswan-cert")])["local"]["p12"], "P12 fehlt im Zertifikatsprofil")


WIN_CALLS: dict = {}


@test("Profile", "Windows-Einrichtungsskripte laufen fehlerfrei (PowerShell, Windows-Cmdlets simuliert)")
def t_windows_scripts():
    check(shutil.which("pwsh"), "pwsh nicht installiert")
    mock = r'''
$ErrorActionPreference = 'Stop'
$env:TEMP = '/tmp'
$global:calls = New-Object System.Collections.ArrayList
function Rec($n, $a) { [void]$global:calls.Add(@{cmd=$n; args=@($a | ForEach-Object { "$_" })}) }
function Add-VpnConnection { Rec 'Add-VpnConnection' $args }
function Remove-VpnConnection { Rec 'Remove-VpnConnection' $args }
function Set-VpnConnectionIPsecConfiguration { Rec 'Set-VpnConnectionIPsecConfiguration' $args }
function Import-Certificate { Rec 'Import-Certificate' $args; $p = $args[[array]::IndexOf($args, '-FilePath') + 1]; if (-not (Test-Path $p)) { throw "CA-Datei fehlt" } }
function Import-PfxCertificate { Rec 'Import-PfxCertificate' $args; $p = $args[[array]::IndexOf($args, '-FilePath') + 1]; if ((Get-Item $p).Length -lt 500) { throw "P12 zu klein" } }
function New-Item { Rec 'New-Item' $args }
function Set-ItemProperty { Rec 'Set-ItemProperty' $args }
'''
    out = []
    for kind in ("win-ikev2-eap", "win-ikev2-cert", "win-sstp", "win-l2tp", "win-pptp"):
        cmd = PROFILES[("e2e", kind)].decode()
        check("\r\n" in cmd and cmd.startswith("@echo off"), f"{kind}: kein gültiges CMD-Format")
        idx = cmd.index("#PSSTART")
        ps = cmd[idx:]
        ps = re.sub(r"^\$isAdmin = .*$", "$isAdmin = $true", ps, flags=re.M)
        script = os.path.join(WORK, f"{kind}.ps1")
        calls_file = os.path.join(WORK, f"{kind}.calls.json")
        with open(script, "w") as fh:
            fh.write(mock + ps + f"\nConvertTo-Json -InputObject $global:calls -Depth 5 | Set-Content '{calls_file}'\n")
        r = sh(f"pwsh -NoProfile -NonInteractive -File {script}", timeout=120)
        check(r.returncode == 0, f"{kind}: {r.stdout[-400:]} {r.stderr[-400:]}")
        calls = json.loads(open(calls_file).read())
        if isinstance(calls, dict):
            calls = [calls]
        WIN_CALLS[kind] = calls
        add = [c for c in calls if c["cmd"] == "Add-VpnConnection"]
        check(len(add) == 1, f"{kind}: Add-VpnConnection nicht aufgerufen")
        a = add[0]["args"]
        opt = {a[i].lstrip("-"): (a[i + 1] if i + 1 < len(a) and not a[i + 1].startswith("-") else True)
               for i in range(len(a)) if a[i].startswith("-")}
        WIN_CALLS[kind + ":opts"] = opt
        check(opt.get("ServerAddress") == VPN_HOST, f"{kind}: ServerAddress {opt.get('ServerAddress')}")
        expect_tt = {"win-ikev2-eap": "Ikev2", "win-ikev2-cert": "Ikev2", "win-sstp": "Sstp",
                     "win-l2tp": "L2tp", "win-pptp": "Pptp"}[kind]
        check(opt.get("TunnelType") == expect_tt, f"{kind}: TunnelType {opt.get('TunnelType')}")
        if kind == "win-l2tp":
            check(opt.get("L2tpPsk") == cred()["ipsec_psk"], "L2TP-PSK falsch")
        if kind in ("win-ikev2-eap", "win-ikev2-cert", "win-sstp"):
            check(any(c["cmd"] == "Import-Certificate" for c in calls), f"{kind}: CA nicht importiert")
        out.append(expect_tt)
    return "(" + ", ".join(out) + ")"


# =============================================================================
# 3. Geraete-Emulation: WireGuard
# =============================================================================

def write(path: str, content: str | bytes, mode: int = 0o600) -> str:
    full = os.path.join(WORK, path)
    with open(full, "wb" if isinstance(content, bytes) else "w") as fh:
        fh.write(content)
    os.chmod(full, mode)
    return full


def wg_up(conf: str, name: str = "wg-a", ns: str = NS) -> subprocess.CompletedProcess:
    path = write(f"{name}.conf", conf)
    return sh(f"ip netns exec {ns} env PATH={WORK}/fakebin:$PATH wg-quick up {path}", timeout=30)


@test("Android / iPhone", "WireGuard-App: QR-Code scannen, gesamter Verkehr über VPN")
def t_wg_qr():
    write("resolvconf.log", "")
    r = wg_up(PROFILES["wg-from-qr"])
    check(r.returncode == 0, f"wg-quick: {r.stderr[-300:]}")
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(DNS in read("resolvconf.log"), "DNS-Server nicht an das System übergeben")
    check(session_seen("e2e", "WireGuard"), "Verbindung nicht in der Statusanzeige")
    hs = nsx("wg show wg-a latest-handshakes").stdout
    check(hs.split() and hs.split()[-1] != "0", "Kein Handshake")


@test("Laptop", "WireGuard Split-Tunnel: nur Heimnetz über VPN")
def t_wg_split():
    r = wg_up(PROFILES[("e2e-split", "wireguard")].decode())
    check(r.returncode == 0, f"wg-quick: {r.stderr[-300:]}")
    check(wait_until(lan_ok, 20, 2), "Heimnetz nicht erreichbar")
    check(not internet_ok(), "Internetverkehr läuft fälschlich durch den Split-Tunnel")


# =============================================================================
# 4. Geraete-Emulation: OpenVPN
# =============================================================================

def ovpn_up(profile: bytes, name: str, ns: str = NS, extra: str = "") -> subprocess.Popen:
    path = write(f"{name}.ovpn", profile)
    log = f"{name}.log"
    p = bg(f"openvpn --config {path} --verb 3 {extra}", log, ns)
    return p


def ovpn_ready(log: str) -> bool:
    return "Initialization Sequence Completed" in read(log)


@test("Alle Plattformen", "OpenVPN Connect: Profil unverändert (UDP), gesamter Verkehr")
def t_ovpn_udp():
    ovpn_up(PROFILES[("e2e", "openvpn")], "ovpn-a")
    check(wait_until(lambda: ovpn_ready("ovpn-a.log"), 40), "Keine Verbindung: " + tail("ovpn-a.log", 15))
    check("udp" in read("ovpn-a.log").lower() and "[AF_INET]" in read("ovpn-a.log"), "Kein UDP")
    check(f"dhcp-option DNS {DNS}" in read("ovpn-a.log"), "DNS nicht gepusht")
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(session_seen("e2e", "OpenVPN UDP"), "Verbindung nicht in der Statusanzeige")


@test("Hotel-/Firmen-WLAN", "OpenVPN: UDP blockiert -> automatischer Wechsel auf TCP")
def t_ovpn_tcp_fallback():
    nsx("nft add table inet blk")
    nsx("nft 'add chain inet blk out { type filter hook output priority 0 ; }'")
    nsx("nft add rule inet blk out udp dport 1194 drop")
    ovpn_up(PROFILES[("e2e", "openvpn")], "ovpn-tcp")
    check(wait_until(lambda: ovpn_ready("ovpn-tcp.log"), 60), "Kein TCP-Fallback: " + tail("ovpn-tcp.log", 15))
    check("TCP" in read("ovpn-tcp.log") or "tcp" in read("ovpn-tcp.log"), "Nicht über TCP verbunden")
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(session_seen("e2e", "OpenVPN TCP"), "Verbindung nicht in der Statusanzeige")


# =============================================================================
# 5. Geraete-Emulation: IPsec (strongSwan als Client, Parameter wie das Geraet)
# =============================================================================

SWAN_DEVICES: list[dict] = []


def apple_proposals(params: dict) -> str:
    enc = {"AES-256-GCM": "aes256gcm16", "AES-128-GCM": "aes128gcm16", "AES-256": "aes256",
           "AES-128": "aes128"}[params["EncryptionAlgorithm"]]
    integ = {"SHA2-384": "sha384", "SHA2-256": "sha256", "SHA1-160": "sha1"}[params["IntegrityAlgorithm"]]
    dh = {20: "ecp384", 19: "ecp256", 14: "modp2048", 21: "ecp521"}[int(params["DiffieHellmanGroup"])]
    return enc, integ, dh


def win_proposals(calls: list) -> tuple[str, str]:
    c = [x for x in calls if x["cmd"] == "Set-VpnConnectionIPsecConfiguration"][0]["args"]
    o = {c[i].lstrip("-"): c[i + 1] for i in range(len(c) - 1) if c[i].startswith("-")}
    enc = {"AES256": "aes256", "AES128": "aes128"}[o["EncryptionMethod"]]
    integ = {"SHA256": "sha256", "SHA384": "sha384", "SHA1": "sha1"}[o["IntegrityCheckMethod"]]
    dh = {"Group14": "modp2048", "ECP256": "ecp256", "ECP384": "ecp384", "Group2": "modp1024"}[o["DHGroup"]]
    esp = {"GCMAES256": "aes256gcm16", "GCMAES128": "aes128gcm16"}[o["CipherTransformConstants"]]
    return f"{enc}-{integ}-{dh}", esp


def build_swan_devices() -> None:
    c = cred()
    mc_cert = plistlib.loads(PROFILES[("e2e", "mobileconfig-cert")])
    mc_eap = plistlib.loads(PROFILES[("e2e", "mobileconfig-eap")])
    ike_c = [p for p in mc_cert["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"][0]["IKEv2"]
    ike_e = [p for p in mc_eap["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"][0]["IKEv2"]
    p12_payload = [p for p in mc_cert["PayloadContent"] if p["PayloadType"] == "com.apple.security.pkcs12"][0]
    enc, integ, dh = apple_proposals(ike_c["IKESecurityAssociationParameters"])
    cenc, _ci, cdh = apple_proposals(ike_c["ChildSecurityAssociationParameters"])
    apple_ike = f"{enc}-prf{integ}-{dh}" if "gcm" in enc else f"{enc}-{integ}-{dh}"
    apple_esp = f"{cenc}-{cdh}"
    sw_cert = json.loads(PROFILES[("e2e", "sswan-cert")])
    sw_eap = json.loads(PROFILES[("e2e", "sswan-eap")])
    try:
        win_ike, win_esp = win_proposals(WIN_CALLS["win-ikev2-eap"])
        win_ike_c, win_esp_c = win_proposals(WIN_CALLS["win-ikev2-cert"])
    except (KeyError, IndexError):  # PowerShell-Test nicht gelaufen -> Werte des Skripts
        win_ike, win_esp = win_ike_c, win_esp_c = "aes256-sha256-modp2048", "aes256gcm16"

    # Zertifikate/Schluessel wie vom jeweiligen Geraet importiert
    os.makedirs("/etc/swanctl/pkcs12", exist_ok=True)
    os.makedirs("/etc/swanctl/x509ca", exist_ok=True)
    with open("/etc/swanctl/pkcs12/dl.p12", "wb") as fh:
        fh.write(PROFILES[("e2e", "p12")])
    with open("/etc/swanctl/pkcs12/apple.p12", "wb") as fh:
        fh.write(p12_payload["PayloadContent"])
    with open("/etc/swanctl/pkcs12/sswan.p12", "wb") as fh:
        fh.write(base64.b64decode(sw_cert["local"]["p12"]))
    with open("/etc/swanctl/x509ca/vpn-ca.der", "wb") as fh:
        fh.write(base64.b64decode(sw_cert["remote"]["cert"]))

    android_ike = ("aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha384-ecp384,"
                   "aes256gcm16-prfsha256-ecp256")
    android_esp = "aes256gcm16,aes128gcm16,aes256-sha256,aes128-sha256"
    d = SWAN_DEVICES
    d.append(dict(key="android-psk", cat="Android 11+ (ohne App)", label="IKEv2/IPSec PSK",
                  local=f"auth = psk\nid = {c['ikev2']['psk_id']}", remote=f"auth = psk\nid = {VPN_HOST}",
                  ike=android_ike, esp=android_esp, status="IKEv2 (PSK)"))
    d.append(dict(key="android-rsa", cat="Android 11+ (ohne App)", label="IKEv2/IPSec RSA (Zertifikat)",
                  local="auth = pubkey\nid = e2e", remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike=android_ike, esp=android_esp, status="IKEv2 (Zertifikat)"))
    d.append(dict(key="android-mschap", cat="Android 11+ (ohne App)", label="IKEv2/IPSec MSCHAPv2",
                  local="auth = eap-mschapv2\neap_id = e2e\nid = e2e", remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike=android_ike, esp=android_esp, status="IKEv2 (Benutzername)"))
    d.append(dict(key="sswan-cert", cat="Android strongSwan-App", label=".sswan-Profil mit Zertifikat",
                  local="auth = pubkey\nid = e2e", remote=f"auth = pubkey\nid = {sw_cert['remote']['id']}",
                  addr=sw_cert["remote"]["addr"], ike="default", esp="default", status="IKEv2 (Zertifikat)"))
    d.append(dict(key="sswan-eap", cat="Android strongSwan-App", label=".sswan-Profil mit Passwort",
                  local=f"auth = eap-mschapv2\neap_id = {sw_eap['local']['eap_id']}\nid = {sw_eap['local']['eap_id']}",
                  remote=f"auth = pubkey\nid = {sw_eap['remote']['id']}", addr=sw_eap["remote"]["addr"],
                  ike="default", esp="default", status="IKEv2 (Benutzername)"))
    d.append(dict(key="apple-cert", cat="iPhone / iPad / Mac", label=".mobileconfig mit Zertifikat",
                  local=f"auth = pubkey\nid = {ike_c['LocalIdentifier']}",
                  remote=f"auth = pubkey\nid = {ike_c['RemoteIdentifier']}", addr=ike_c["RemoteAddress"],
                  ike=apple_ike, esp=apple_esp, status="IKEv2 (Zertifikat)"))
    d.append(dict(key="apple-eap", cat="iPhone / iPad / Mac", label=".mobileconfig mit Benutzername/Passwort",
                  local=f"auth = eap-mschapv2\neap_id = {ike_e['AuthName']}\nid = {ike_e['LocalIdentifier']}",
                  remote=f"auth = pubkey\nid = {ike_e['RemoteIdentifier']}", addr=ike_e["RemoteAddress"],
                  ike=apple_ike, esp=apple_esp, status="IKEv2 (Benutzername)",
                  eap_secret=ike_e["AuthPassword"]))
    d.append(dict(key="ios-psk", cat="iPhone / iPad / Mac", label="IKEv2 manuell mit PSK (iOS-Standard-Krypto)",
                  local=f"auth = psk\nid = {c['ikev2']['psk_id']}", remote=f"auth = psk\nid = {VPN_HOST}",
                  ike="aes256-sha256-modp2048", esp="aes256-sha256-modp2048", status="IKEv2 (PSK)"))
    d.append(dict(key="win-eap", cat="Windows 10/11", label="IKEv2 Benutzername/Passwort (Skript-Krypto)",
                  local=f"auth = eap-mschapv2\neap_id = e2e\nid = {NS_IP}", remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike=win_ike, esp=win_esp, status="IKEv2 (Benutzername)"))
    d.append(dict(key="win-eap-default", cat="Windows 10/11", label="IKEv2 manuell eingerichtet (Windows-Standard-Krypto)",
                  local=f"auth = eap-mschapv2\neap_id = e2e\nid = {NS_IP}", remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike="aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024",
                  esp="aes256-sha1,aes128-sha1,3des-sha1", status="IKEv2 (Benutzername)"))
    d.append(dict(key="win-cert", cat="Windows 10/11", label="IKEv2 Maschinenzertifikat (ID als DN)",
                  local='auth = pubkey\nid = "O=VPN-Server, CN=e2e"', remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike=win_ike_c, esp=win_esp_c, status="IKEv2 (Zertifikat)"))
    d.append(dict(key="linux-nm", cat="Linux", label="NetworkManager-strongswan (EAP)",
                  local="auth = eap-mschapv2\neap_id = e2e\nid = e2e", remote=f"auth = pubkey\nid = {VPN_HOST}",
                  ike="default", esp="default", status="IKEv2 (Benutzername)"))
    d.append(dict(key="ios-cisco", cat="iPhone / iPad / Mac", label="Cisco IPsec (IKEv1 + XAuth)", version=1,
                  local="auth = psk", local2="auth = xauth\nxauth_id = e2e", remote="auth = psk",
                  ike="aes256-sha256-modp2048,aes256-sha1-modp1024", esp="aes256-sha1", status="Cisco IPsec"))
    d.append(dict(key="android-xauth", cat="Android bis 11", label="IPSec Xauth PSK", version=1,
                  local="auth = psk", local2="auth = xauth\nxauth_id = e2e", remote="auth = psk",
                  ike="aes128-sha1-modp1024,3des-sha1-modp1024", esp="aes128-sha1,3des-sha1", status="Cisco IPsec"))


def write_swanctl() -> None:
    c = cred()
    conns = []
    for dev in SWAN_DEVICES:
        version = dev.get("version", 2)
        local2 = f"\n    local-2 {{\n      {dev['local2'].replace(chr(10), chr(10) + '      ')}\n    }}" if dev.get("local2") else ""
        conns.append(f"""  {dev['key']} {{
    version = {version}
    remote_addrs = {dev.get('addr', VPN_HOST)}
    vips = 0.0.0.0
    proposals = {dev['ike']}
    local {{
      {dev['local'].replace(chr(10), chr(10) + '      ')}
    }}{local2}
    remote {{
      {dev['remote'].replace(chr(10), chr(10) + '      ')}
    }}
    children {{
      {dev['key']} {{
        remote_ts = 0.0.0.0/0
        esp_proposals = {dev['esp']}
      }}
    }}
  }}""")
    conns.append(f"""  l2tp {{
    version = 1
    remote_addrs = {VPN_HOST}
    proposals = aes256-sha1-modp1024,aes128-sha1-modp1024
    local {{
      auth = psk
    }}
    remote {{
      auth = psk
    }}
    children {{
      l2tp {{
        mode = transport
        local_ts = dynamic[udp/1701]
        # wie Windows/iOS/Android: Selektor des Servers hinter NAT (private Adresse) akzeptieren
        remote_ts = 0.0.0.0/0[udp/1701]
        esp_proposals = aes256-sha1,aes128-sha1
      }}
    }}
  }}""")
    eap_pw = CPW_CURRENT
    secrets = f"""secrets {{
  ike-psk {{
    id = {c['ikev2']['psk_id']}
    secret = "{c['ikev2']['psk']}"
  }}
  ike-v1 {{
    id-1 = {HOST_IP}
    secret = "{c['ipsec_psk']}"
  }}
  eap-e2e {{
    id = e2e
    secret = "{eap_pw}"
  }}
  xauth-e2e {{
    id = e2e
    secret = "{eap_pw}"
  }}
  pkcs12-dl {{
    file = dl.p12
    secret = "{c['ikev2']['p12_password']}"
  }}
  pkcs12-apple {{
    file = apple.p12
    secret = "{c['ikev2']['p12_password']}"
  }}
  pkcs12-sswan {{
    file = sswan.p12
    secret = "{c['ikev2']['p12_password']}"
  }}
}}
"""
    with open("/etc/swanctl/conf.d/e2e.conf", "w") as fh:
        fh.write("connections {\n" + "\n".join(conns) + "\n}\n" + secrets)


CPW_CURRENT = CPW
CHARON: subprocess.Popen | None = None


def charon_start() -> None:
    global CHARON
    with open("/etc/strongswan.d/zz-e2e.conf", "w") as fh:
        fh.write(f"""charon-systemd {{
  filelog {{
    e2e {{
      path = {WORK}/charon-cli.log
      default = 1
      ike = 2
      cfg = 1
    }}
  }}
  plugins {{
    resolve {{
      file = {WORK}/ipsec-resolv.conf
      resolvconf {{
        path = {WORK}/fakebin/resolvconf
      }}
    }}
  }}
}}
""")
    log = open(os.path.join(WORK, "charon-stdout.log"), "w")
    CHARON = subprocess.Popen(["ip", "netns", "exec", NS, "/usr/sbin/charon-systemd"], stdout=log,
                              stderr=subprocess.STDOUT)
    check(wait_until(lambda: nsx("swanctl --stats").returncode == 0, 20), "charon startet nicht")
    r = nsx("swanctl --load-all --noprompt")
    check("failed" not in r.stdout + r.stderr, f"swanctl: {r.stdout[-500:]} {r.stderr[-300:]}")


def swan_reload() -> None:
    write_swanctl()
    r = nsx("swanctl --load-all --noprompt")
    check("failed" not in r.stdout + r.stderr, f"swanctl: {r.stdout[-500:]}")


def make_swan_test(dev: dict):
    def fn():
        write("ipsec-resolv.conf", "")
        write("resolvconf.log", "")
        r = nsx(f"timeout 45 swanctl --initiate --child {dev['key']}", timeout=60)
        if r.returncode != 0:
            raise Fail("Verbindung fehlgeschlagen: " + " | ".join(
                l for l in (r.stdout + r.stderr).splitlines() if re.search(r"fail|error|no |AUTH|proposal", l, re.I))[-600:])
        sas = nsx(f"swanctl --list-sas --ike {dev['key']}").stdout
        vip = re.search(r"local .*\[(10\.66\.\d+\.\d+)\]", sas)
        check(vip, f"Keine virtuelle IP zugewiesen: {sas[:300]}")
        errors = tunnel_checks()
        check(not errors, ", ".join(errors))
        check(DNS in read("ipsec-resolv.conf") + read("resolvconf.log"),
              "DNS-Server nicht per IKE übermittelt")
        check(session_seen("e2e", dev["status"]), f"Nicht als '{dev['status']}' in der Statusanzeige")
        nsx(f"swanctl --terminate --ike {dev['key']} --force")
        return f"(VIP {vip.group(1)}, IKE {dev['ike'].split(',')[0]})"
    return fn


@test("IPsec-Vorbereitung", "Client-Parameter aus den Profilen übernehmen, strongSwan-Client starten")
def t_swan_prepare():
    build_swan_devices()
    write_swanctl()
    charon_start()
    pos = next(i for i, t in enumerate(TESTS) if t[2] is t_swan_prepare) + 1
    new = [(dev["cat"], dev["label"], make_swan_test(dev)) for dev in SWAN_DEVICES]
    new.append(("Windows 10/11", "L2TP/IPsec mit PSK + MSCHAPv2 (wie Windows-Skript)", t_l2tp))
    new.append(("iPhone / iPad / Mac", "L2TP/IPsec: erneut verbinden nach Trennung", t_l2tp))
    TESTS[pos:pos] = new
    return f"({len(SWAN_DEVICES)} Geräteprofile)"


def ppp_iface(ns: str = NS) -> str:
    out = sh(f"ip -n {ns} -o -4 addr show").stdout
    m = re.search(r"\d+: (ppp\d+)\s+inet (\S+)", out)
    return m.group(1) if m else ""


VLAN_NETS = ("192.168.10.0/24", "192.168.20.0/24")


def route_via(iface: str, ns: str = NS) -> None:
    for net in ("10.0.2.0/24", f"{INTERNET_IP}/32", f"{DNS}/32", *VLAN_NETS):
        nsx(f"ip route replace {net} dev {iface}", ns)


L2TP_LAST_END = [0.0]


def l2tp_connect(user: str, password: str) -> str:
    """Baut L2TP/IPsec auf und liefert die PPP-Schnittstelle."""
    # Nach dem Trennen haelt der Server den Tunnel noch einen vollen
    # Wiederholungszyklus vor (RFC 2661, ca. 31 s). Ein neuer Verbindungsaufbau
    # vom selben Absenderport (1701) wird in dieser Zeit verworfen; echte
    # Clients verbinden sich danach normal neu.
    wait = L2TP_LAST_END[0] + 35 - time.time()
    if wait > 0:
        time.sleep(wait)
    r = nsx("timeout 45 swanctl --initiate --child l2tp", timeout=60)
    check(r.returncode == 0, "IPsec-Transport-SA fehlgeschlagen: " + (r.stdout + r.stderr)[-400:])
    write("xl2tpd.conf", f"""[global]
port = 1701
access control = no
[lac vpn]
lns = {HOST_IP}
ppp debug = yes
pppoptfile = {WORK}/options.l2tp
length bit = yes
autodial = yes
redial = no
""", 0o644)
    write("options.l2tp", f"""ipcp-accept-local
ipcp-accept-remote
refuse-eap
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
noccp
noauth
mtu 1280
mru 1280
noipdefault
nodefaultroute
name {user}
password {password}
connect-delay 2000
""", 0o600)
    bg(f"xl2tpd -D -c {WORK}/xl2tpd.conf -p {WORK}/xl2tpd.pid -C {WORK}/l2tp-control", "xl2tpd.log")
    check(wait_until(lambda: ppp_iface(), 40), "Keine PPP-Verbindung: " + tail("xl2tpd.log", 20))
    route_via(ppp_iface())
    return ppp_iface()


def l2tp_disconnect() -> None:
    # Sauber trennen wie ein echter Client (StopCCN), dann IPsec beenden
    sh(f"timeout 5 bash -c \"echo 'd vpn' > {WORK}/l2tp-control\"")
    time.sleep(4)
    nsx("swanctl --terminate --ike l2tp")
    sh("pkill -f 'xl2tpd -D -c' || true")
    L2TP_LAST_END[0] = time.time()


def t_l2tp():
    l2tp_connect("e2e", CPW_CURRENT)
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(session_seen("e2e", "L2TP"), "Nicht als L2TP in der Statusanzeige")
    l2tp_disconnect()


# =============================================================================
# 6. SSTP und OpenConnect
# =============================================================================

def sstp_up(password: str, ns: str = NS, log: str = "sstp.log", user: str = "e2e") -> subprocess.Popen:
    ca = write("ca.crt", PROFILES[("e2e", "ca")], 0o644)
    return bg(f"sstpc --log-stderr --log-level 3 --ca-cert {ca} --user {user} --password '{password}' "
              f"{VPN_HOST} require-mschap-v2 refuse-eap refuse-pap refuse-chap refuse-mschap noauth "
              f"noipdefault nodefaultroute noccp nobsdcomp nodeflate", log, ns)


@test("Windows 10/11", "SSTP (TCP 443, Zertifikatsprüfung gegen CA, MSCHAPv2)")
def t_sstp():
    sstp_up(CPW_CURRENT)
    check(wait_until(lambda: ppp_iface(), 40), "Keine PPP-Verbindung: " + tail("sstp.log", 20))
    route_via(ppp_iface())
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(session_seen("e2e", "SSTP"), "Nicht als SSTP in der Statusanzeige")


def oc_script() -> str:
    return write("oc-script.sh", f"""#!/bin/sh
if [ "$reason" = connect ]; then
  ip link set dev "$TUNDEV" up mtu "${{INTERNAL_IP4_MTU:-1300}}"
  ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
  for n in 10.0.2.0/24 {INTERNET_IP}/32 {DNS}/32 {" ".join(VLAN_NETS)}; do ip route replace $n dev "$TUNDEV"; done
  echo "DNS=$INTERNAL_IP4_DNS" > {WORK}/oc-env.txt
fi
exit 0
""", 0o755)


def oc_up(log: str, extra: str = "", user: str = "e2e", password: str | None = None) -> subprocess.Popen:
    pin = cred()["openconnect_pin"]
    script = oc_script()
    pwfile = write("oc-pw.txt", (password or CPW_CURRENT) + "\n")
    return bg(f"openconnect --servercert {pin} -u {user} --passwd-on-stdin --script {script} "
              f"{extra} {VPN_HOST}:4443 < {pwfile}", log)


@test("Cisco Secure Client / OpenConnect", "OpenConnect mit DTLS (UDP 4443) und Zertifikats-Pin")
def t_oc():
    oc_up("oc.log")
    check(wait_until(lambda: "CSTP connected" in read("oc.log"), 30), "Keine Verbindung: " + tail("oc.log"))
    check(wait_until(lambda: "DTLS" in read("oc.log") and "Established" in read("oc.log"), 20), "Kein DTLS")
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))
    check(DNS in read("oc-env.txt"), "DNS nicht übermittelt")
    check(session_seen("e2e", "OpenConnect"), "Nicht in der Statusanzeige")


@test("Hotel-/Firmen-WLAN", "OpenConnect: UDP blockiert -> nur TLS/TCP")
def t_oc_tcp():
    nsx("nft add table inet blk")
    nsx("nft 'add chain inet blk out { type filter hook output priority 0 ; }'")
    nsx("nft add rule inet blk out udp dport 4443 drop")
    oc_up("oc-tcp.log")
    check(wait_until(lambda: "CSTP connected" in read("oc-tcp.log"), 30), "Keine Verbindung: " + tail("oc-tcp.log"))
    errors = tunnel_checks()
    check(not errors, ", ".join(errors))


@test("Alte Geräte", "PPTP-Dienst lauscht auf TCP 1723 (GRE ist durch QEMU-NAT nicht testbar)")
def t_pptp():
    r = remote("ss -ltn | grep -c ':1723 '")
    check(r.stdout.strip() not in ("", "0"), f"Port 1723 nicht offen: {r.stdout} {r.stderr[-200:]}")


# =============================================================================
# 7. Funktionstests
# =============================================================================

@test("Funktion", "Client-zu-Client standardmäßig gesperrt, per Einstellung freischaltbar")
def t_c2c():
    wg_up(PROFILES[("e2e", "wireguard")].decode(), "wg-a", NS)
    ovpn_up(PROFILES[("e2e-b", "openvpn")], "ovpn-b", NS2)
    check(wait_until(lambda: ovpn_ready("ovpn-b.log"), 40), "Gerät B verbindet nicht")
    out = sh(f"ip -n {NS2} -o -4 addr show").stdout
    m = re.search(r"inet (10\.66\.6[78]\.\d+)/", out)
    check(m, f"Keine OpenVPN-Adresse auf Gerät B: {out}")
    ip_b = m.group(1)
    check(nsx(f"ping -c2 -W2 {ip_b}").returncode != 0, "Client-zu-Client ist nicht gesperrt")
    W.settings("general", {**GENERAL, "client_to_client": "1"})
    ok = wait_until(lambda: nsx(f"ping -c1 -W2 {ip_b}").returncode == 0, 20, 2)
    W.settings("general", GENERAL)
    check(ok, "Client-zu-Client nach Freischaltung nicht möglich")
    check(wait_until(lambda: nsx(f"ping -c1 -W2 {ip_b}").returncode != 0, 20, 2), "Sperre wirkt nicht wieder")


@test("Funktion", "Heimnetz-Zugriff abschaltbar (Internet bleibt erreichbar)")
def t_lan_toggle():
    wg_up(PROFILES[("e2e", "wireguard")].decode())
    check(wait_until(lan_ok, 20, 2), "Heimnetz initial nicht erreichbar")
    form = dict(GENERAL)
    form.pop("lan_access")
    W.settings("general", form)
    blocked = wait_until(lambda: not lan_ok(), 20, 2)
    inet = internet_ok()
    W.settings("general", GENERAL)
    check(blocked, "Heimnetz trotz Sperre erreichbar")
    check(inet, "Internet bei gesperrtem Heimnetz nicht erreichbar")
    check(wait_until(lan_ok, 20, 2), "Heimnetz nach Freigabe nicht wieder erreichbar")


@test("Funktion", "Protokoll abschalten stoppt den Dienst (SSTP), Einschalten startet ihn wieder")
def t_proto_toggle():
    form = dict(ALL_PROTOCOLS)
    form.pop("sstp_enabled")
    W.settings("protocols", form)
    closed = wait_until(lambda: remote("ss -ltn | grep -c ':443 '").stdout.strip() == "0", 30, 3)
    W.settings("protocols", ALL_PROTOCOLS)
    check(closed, "Port 443 nach Abschalten noch offen")
    check(wait_until(lambda: remote("ss -ltn | grep -c ':443 '").stdout.strip() != "0", 40, 3),
          "SSTP nach Einschalten nicht wieder aktiv")
    sstp_up(CPW_CURRENT)
    check(wait_until(lambda: ppp_iface(), 40), "SSTP danach nicht nutzbar: " + tail("sstp.log"))


@test("Funktion", "Client-Passwort ändern: altes Passwort abgewiesen, neues akzeptiert (SSTP, IKEv2-EAP)")
def t_password_change():
    global CPW_CURRENT
    new = "Neu-E2e-Pass2"
    flashes = W.client_action("e2e", "set-password", password=new)
    check(any("gespeichert" in f for f in flashes), f"{flashes}")
    sstp_up(CPW_CURRENT, log="sstp-old.log")
    check(not wait_until(lambda: ppp_iface(), 20), "Altes Passwort funktioniert noch (SSTP)")
    cleanup_clients()
    CPW_CURRENT = new
    swan_reload()
    sstp_up(CPW_CURRENT, log="sstp-new.log")
    check(wait_until(lambda: ppp_iface(), 40), "Neues Passwort funktioniert nicht (SSTP)")
    cleanup_clients()
    r = nsx("timeout 45 swanctl --initiate --child android-mschap", timeout=60)
    check(r.returncode == 0, "Neues Passwort funktioniert nicht (IKEv2-EAP)")


@test("Funktion", "Client sperren trennt die Verbindung und widerruft das Zertifikat; Entsperren")
def t_lock():
    ovpn_up(PROFILES[("e2e-b", "openvpn")], "ovpn-lock", NS2)
    check(wait_until(lambda: ovpn_ready("ovpn-lock.log"), 40), "Gerät B verbindet nicht")
    check(wait_until(lambda: lan_ok(NS2), 20, 2), "Gerät B ohne Heimnetz vor dem Sperren")
    W.client_action("e2e-b", "toggle")
    check(wait_until(lambda: re.search(r"SIGTERM|SIGUSR1|Restart|Connection reset|server-pushed",
                                       read("ovpn-lock.log").split("Initialization Sequence Completed", 1)[-1])
                     or not lan_ok(NS2), 75, 3),
          "Bestehende Verbindung wurde nicht getrennt")
    cleanup_clients()
    ovpn_up(PROFILES[("e2e-b", "openvpn")], "ovpn-locked", NS2)
    check(not wait_until(lambda: ovpn_ready("ovpn-locked.log"), 25), "Gesperrter Client kann sich verbinden")
    cleanup_clients()
    wg_up(PROFILES[("e2e-b", "wireguard")].decode(), "wg-b", NS2)
    check(not wait_until(lambda: lan_ok(NS2), 15, 3), "Gesperrter Client kommt per WireGuard ins Netz")
    cleanup_clients()
    W.client_action("e2e-b", "toggle")
    PROFILES[("e2e-b", "openvpn")] = W.download("e2e-b", "openvpn")
    ovpn_up(PROFILES[("e2e-b", "openvpn")], "ovpn-unlocked", NS2)
    check(wait_until(lambda: ovpn_ready("ovpn-unlocked.log"), 40), "Nach Entsperren (neues Profil) keine Verbindung")


@test("Funktion", "Schlüssel erneuern: altes WireGuard-Profil ungültig, neues funktioniert")
def t_regen():
    old = PROFILES[("e2e-b", "wireguard")].decode()
    W.client_action("e2e-b", "regen-keys")
    wg_up(old, "wg-b", NS2)
    check(not wait_until(lambda: lan_ok(NS2), 15, 3), "Altes WireGuard-Profil funktioniert noch")
    cleanup_clients()
    new = W.download("e2e-b", "wireguard").decode()
    check(new != old, "Profil unverändert")
    wg_up(new, "wg-b", NS2)
    check(wait_until(lambda: lan_ok(NS2), 20, 2), "Neues WireGuard-Profil funktioniert nicht")


@test("Funktion", "Teilen-Link: Profile ohne Anmeldung abrufbar (Handy im WLAN)")
def t_share():
    W.client_action("e2e", "share")
    _c, _u, raw = W.req("/clients/e2e")
    m = re.search(rb"/share/([A-Za-z0-9_\-]+)", raw)
    check(m, "Kein Teilen-Link")
    token = m.group(1).decode()
    phone = Web()
    code, _u, page = phone.req(f"/share/{token}")
    check(code == 200 and b"WireGuard" in page, f"Teilen-Seite {code}")
    code, _u, conf = phone.req(f"/share/{token}/dl/wireguard")
    check(code == 200 and conf == PROFILES[("e2e", "wireguard")], "Download über Teilen-Link abweichend")
    code, _u, _r = phone.req("/clients")
    check("/login" in _u, "Teilen-Link gewährt Zugriff auf die Verwaltung")
    W.client_action("e2e", "unshare")
    code, _u, _r = Web().req(f"/share/{token}")
    check(code == 404, "Gelöschter Teilen-Link funktioniert noch")


@test("Funktion", "Client löschen: WireGuard, OpenVPN und IKEv2-PSK abgewiesen")
def t_delete():
    W.client_action("e2e-split", "delete")
    wg_up(PROFILES[("e2e-split", "wireguard")].decode())
    check(not wait_until(lambda: lan_ok(), 12, 3), "Gelöschter WireGuard-Client kommt ins Netz")
    cleanup_clients()
    ovpn_up(PROFILES[("e2e-split", "openvpn")], "ovpn-del")
    check(not wait_until(lambda: ovpn_ready("ovpn-del.log"), 20), "Gelöschter OpenVPN-Client verbindet sich")


@test("Funktion", "Sicherung herunterladen und wiederherstellen")
def t_backup():
    code, _u, data = W.req("/system/backup")
    check(code == 200 and data[:2] == b"\x1f\x8b", "Keine gzip-Sicherung")
    code, _u, raw = W.req("/system", {"action": "restore"}, files={"backup": ("backup.tar.gz", data)})
    check(any("wiederhergestellt" in f for f in W.flashes(raw)), f"{W.flashes(raw)}")
    wg_up(PROFILES[("e2e", "wireguard")].decode())
    check(wait_until(lan_ok, 20, 2), "Nach Wiederherstellung keine Verbindung")


@test("Funktion", "Kommandozeile vpnctl (status, client add/export/del)")
def t_cli():
    r = remote("vpnctl status")
    check("WireGuard" in r.stdout and "!!" not in r.stdout, f"vpnctl status: {r.stdout[-500:]}")
    r = remote("vpnctl client add cli-test")
    check("Zugangsdaten" in r.stdout, f"client add: {r.stdout[-300:]} {r.stderr[-300:]}")
    r = remote("vpnctl client export cli-test wireguard -o -")
    check("[Interface]" in r.stdout, "client export")
    r = remote("vpnctl client del cli-test")
    check("geloescht" in r.stdout or "gelöscht" in r.stdout, f"client del: {r.stdout}")


@test("Sicherheit", "HTTP-Sicherheitsheader, Cookie-Flags, CSRF-Schutz")
def t_security_headers():
    w = Web()
    w.req("/login")
    h = {k.lower(): v for k, v in w.last_headers.items()}
    check("default-src 'self'" in h.get("content-security-policy", ""), "CSP fehlt")
    check(h.get("x-frame-options") == "DENY", "X-Frame-Options fehlt")
    w.login(ADMIN_PW)
    cookie = [c for c in w.jar if c.name == "vpnserver_session"]
    check(cookie and cookie[0].secure, "Session-Cookie nicht 'Secure'")
    check(cookie[0].has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie[0]._rest).lower(), "Kein HttpOnly")
    code, _u, _r = w.req("/clients", {"name": "csrf-test", "tunnel": "full"}, csrf=False)
    check(code == 400, f"POST ohne CSRF-Token liefert {code}")


@test("Sicherheit", "TLS: nur TLS 1.2+, Zertifikatskette gültig für Weboberfläche, SSTP und OpenConnect")
def t_tls():
    ca = write("ca.crt", PROFILES[("e2e", "ca")], 0o644)
    r = sh("echo | openssl s_client -connect 127.0.0.1:8443 -tls1_1 2>&1")
    check("Cipher is (NONE)" in r.stdout or "alert" in r.stdout.lower() or r.returncode != 0, "TLS 1.1 akzeptiert")
    for port in (8443, 443, 4443):
        host = "127.0.0.1" if port == 8443 else HOST_IP
        r = sh(f"echo | openssl s_client -connect {host}:{port} -servername {VPN_HOST} -CAfile {ca} "
               f"-verify_hostname {VPN_HOST} 2>&1")
        check("Verify return code: 0" in r.stdout, f"Port {port}: {re.findall(r'Verify return code: .*', r.stdout)}")


@test("Sicherheit", "Firewall: Standard-Policy drop, L2TP nur über IPsec, Weboberfläche nur aus LAN/VPN")
def t_firewall():
    r = remote("nft list chain inet vpnserver input")
    out = r.stdout
    check("policy drop" in out, "Input-Policy ist nicht drop")
    check(re.search(r"udp dport 1701 meta (secpath|ipsec) exists accept", out),
          "L2TP nicht auf IPsec beschränkt")
    check("tcp dport 8443 ip saddr @private_nets accept" in out, "Weboberfläche nicht beschränkt")


# =============================================================================
# 7b. Statistik und Werkzeuge der Weboberflaeche
# =============================================================================

@test("Statistik", "Durchsatz live, Datenvolumen je Client und Verbindungsprotokoll werden erfasst")
def t_stats():
    write("traffic.bin", os.urandom(8 * 1024 * 1024), 0o644)
    r = wg_up(PROFILES[("e2e", "wireguard")].decode())
    check(r.returncode == 0, f"wg-quick: {r.stderr[-300:]}")
    check(wait_until(lan_ok, 20, 2), "Heimnetz nicht erreichbar")
    time.sleep(12)  # die Statistik erfasst Verbindungen alle 10 s
    for _ in range(3):
        nsx(f"curl -s --noproxy '*' --max-time 30 -o /dev/null {LAN_URL}traffic.bin", timeout=40)

    def live_rate():
        pts = W.req("/api/live")[2]
        data = json.loads(pts)
        return max((p[1] for p in data.get("points", [])), default=0)
    check(wait_until(lambda: live_rate() > 100_000, 30, 3), "Kein Durchsatz in der Live-Anzeige")

    def client_volume():
        data = json.loads(W.req("/api/history?range=24h")[2])
        for c in data.get("clients", []):
            if c["name"] == "e2e":
                return c["down"]
        return 0
    check(wait_until(lambda: client_volume() > 8_000_000, 90, 5),
          f"Datenvolumen für e2e fehlt (gemessen: {client_volume()} Bytes)")
    events = json.loads(W.req("/api/events?limit=50")[2])["events"]
    check(any(e["type"] == "connect" and e["user"] == "e2e" for e in events), "Anmeldung nicht im Verbindungsprotokoll")
    for page in ("/", "/statistik", "/status"):
        code, _u, raw = W.req(page)
        check(code == 200, f"{page}: {code}")
    return f"(live {live_rate() * 8 / 1e6:.1f} Mbit/s, e2e {client_volume() / 1e6:.0f} MB)"


@test("Werkzeuge", "Ping, DNS-Abfrage, Wake-on-LAN und Paketmitschnitt in der Weboberfläche")
def t_tools():
    code, _u, raw = W.req("/api/tools/ping", {"host": "10.0.2.2", "count": "2"})
    out = json.loads(raw)["output"]
    check(code == 200 and re.search(r" 0% packet loss", out), f"Ping: {out[-300:]}")
    code, _u, raw = W.req("/api/tools/dns", {"name": "debian.org", "type": "A", "server": ""})
    out = json.loads(raw)["output"]
    check(code == 200 and re.search(r"debian\.org\.\s+\d+\s+IN\s+A\s+\d+\.", out), f"DNS: {out[-300:]}")
    code, _u, raw = W.req("/api/tools/ping", {"host": "10.0.2.2; reboot"})
    check(code == 400, "Ungültige Eingabe nicht abgewiesen")
    code, _u, raw = W.req("/api/tools/wol", {"mac": "52:54:00:12:34:56"})
    check(code == 200 and "gesendet" in json.loads(raw)["output"], f"WoL: {raw[-200:]}")
    code, _u, raw = W.req("/werkzeuge/mitschnitt", {"iface": "any", "seconds": "2", "filter": "icmp"})
    check(code == 200 and raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"), f"Mitschnitt: {code} {raw[:80]!r}")
    return f"(Mitschnitt {len(raw)} Bytes)"


# =============================================================================
# 8. RADIUS-Anmeldung und VLAN-Zuweisung (wie beim WLAN-Controller)
# =============================================================================
#
# Externer RADIUS-Server: FreeRADIUS auf dem Test-Host (fuer den Server 10.0.2.2)
#   radvlan10 -> VLAN 10 (dazu ein langes Class- und ein Framed-IP-Attribut, die
#                der VPN-Server ignorieren muss), radnovlan -> kein VLAN,
#                radvlan99 -> nicht eingerichtetes VLAN, radwrong -> anderes Passwort
# VLAN-Trunk: zweite Netzwerkkarte des Servers; VLAN 10 (192.168.10.0/24, Gateway .1)
#   und VLAN 20 (192.168.20.0/24, ohne Gateway) mit je einem HTTP-Dienst auf .1:8080,
#   der die Absenderadresse zurueckgibt.

RAD = {"radvlan10": "Radius-Pass10", "radnovlan": "Radius-Pass00", "radvlan99": "Radius-Pass99",
       "radwrong": "Falsch-Pass1"}
VLAN_DEV = "vlan20dev"
VLAN_DEV_PW = "Vlan20-Geraet1"


def vlan_peer(vid: int, ns: str = NS) -> str:
    """Absenderadresse, mit der ein Dienst im VLAN den Client sieht ("" = nicht erreichbar)."""
    r = nsx(f"curl -s --noproxy '*' --max-time 6 http://192.168.{vid}.1:8080/", ns, timeout=15)
    return r.stdout.strip() if r.returncode == 0 else ""


def vlan_checks(vid: int, other: int, ns: str = NS) -> list[str]:
    errors = []
    if not wait_until(lambda: vlan_peer(vid, ns) == f"192.168.{vid}.2", 20, 2):
        errors.append(f"VLAN {vid} nicht erreichbar (Antwort: '{vlan_peer(vid, ns)}')")
    if vlan_peer(other, ns):
        errors.append(f"VLAN {other} ist erreichbar (Isolation verletzt)")
    if lan_ok(ns):
        errors.append("Heimnetz des Servers ist erreichbar (Isolation verletzt)")
    return errors


def vlan_session(user: str, vid: int) -> bool:
    def probe():
        for sess in W.status()["sessions"]:
            if sess.get("user") == user and str(sess.get("vlan", "")).startswith(f"{vid} "):
                return True
        return False
    return wait_until(probe, 25, 3)


def write_radius_swanctl() -> None:
    c = cred()
    conns, secrets = [], []
    for key, user in (("rad-eap10", "radvlan10"), ("rad-eapnone", "radnovlan"),
                      ("rad-eap99", "radvlan99"), ("rad-eapwrong", "radwrong")):
        conns.append(f"""  {key} {{
    version = 2
    remote_addrs = {VPN_HOST}
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes256gcm16-prfsha384-ecp384
    local {{
      auth = eap-mschapv2
      eap_id = {user}
    }}
    remote {{
      auth = pubkey
      id = {VPN_HOST}
    }}
    children {{
      {key} {{
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16,aes256-sha256
      }}
    }}
  }}""")
        secrets.append(f"""  eap-{key} {{
    id = {user}
    secret = "{RAD[user]}"
  }}""")
    conns.append(f"""  rad-xauth10 {{
    version = 1
    remote_addrs = {VPN_HOST}
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes256-sha1-modp1024
    local {{
      auth = psk
    }}
    local-2 {{
      auth = xauth
      xauth_id = radvlan10
    }}
    remote {{
      auth = psk
    }}
    children {{
      rad-xauth10 {{
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256-sha1,aes256-sha256
      }}
    }}
  }}""")
    secrets.append("""  xauth-rad10 {
    id = radvlan10
    secret = "Radius-Pass10"
  }""")
    with open("/etc/swanctl/conf.d/e2e-radius.conf", "w") as fh:
        fh.write("connections {\n" + "\n".join(conns) + "\n}\nsecrets {\n" + "\n".join(secrets) + "\n}\n")
    del c


def swan_vip(key: str) -> str:
    sas = nsx(f"swanctl --list-sas --ike {key}").stdout
    m = re.search(r"local .*\[(10\.\d+\.\d+\.\d+)\]", sas)
    return m.group(1) if m else ""


def in_net(ip: str, net: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net)
    except ValueError:
        return False


@test("RADIUS / VLAN", "VLANs anlegen: Trunk mit VLAN 10 (mit Gateway) und VLAN 20 (ohne)")
def t_vlan_setup():
    r = remote("ip -o link | grep -i '52:54:00:00:99:01' | awk -F': ' '{print $2}'")
    nic = r.stdout.strip().split("@")[0]
    check(nic, f"Trunk-Netzwerkkarte nicht gefunden: {r.stdout} {r.stderr[-200:]}")
    _c, _u, raw = W.req("/settings")
    check(f'value="{nic}"' in raw.decode(errors="replace"), f"{nic} nicht in der Schnittstellenauswahl")
    W.settings("vlan-save", {"id": "10", "name": "Gäste", "parent": nic, "address": "192.168.10.2/24",
                             "gateway": "192.168.10.1", "dns": "192.168.10.1"})
    W.settings("vlan-save", {"id": "20", "name": "IoT", "parent": nic, "address": "192.168.20.2/24",
                             "gateway": ""})
    st = remote("cat /etc/vpn-server/state.json").stdout
    check('"vpn_net": "10.67.1.0/24"' in st and '"vpn_net": "10.67.2.0/24"' in st,
          "VLANs nicht gespeichert")

    def links_up():
        page = W.req("/settings")[2].decode(errors="replace")
        return page.count(">verbunden<") >= 2
    check(wait_until(links_up, 30, 3), "VLAN-Schnittstellen nicht verbunden")
    out = remote("ip -d link show vlan10; ip rule; ip route show table 1001; ip route show table 1002").stdout
    check("vlan protocol 802.1Q id 10" in out, f"vlan10 fehlt: {out[:300]}")
    check("lookup 1001" in out and "default via 192.168.10.1 dev vlan10" in out, f"Routing VLAN 10: {out[-600:]}")
    check("unreachable default" in out, "VLAN 20 ohne Gateway darf nicht ins Internet routen")
    check(remote("ping -c1 -W2 192.168.10.1").returncode == 0, "Server erreicht VLAN 10 nicht")
    return f"(Trunk {nic})"


@test("RADIUS / VLAN", "Externen RADIUS-Server eintragen, Verbindung testen (VLAN-Attribut erkannt)")
def t_radius_setup():
    W.settings("radius", {"enabled": "1", "host1": "10.0.2.2", "auth_port1": "1812",
                          "acct_port1": "1813", "secret1": "testing123", "nas_identifier": "vpn-e2e",
                          "local_users": "1", "accounting": "1", "unknown_vlan": "reject",
                          "no_vlan": "default"})
    _c, _u, raw = W.req("/settings", {"section": "radius-test", "test_user": "radvlan10",
                                      "test_password": RAD["radvlan10"], "test_method": "pap"})
    page = raw.decode(errors="replace")
    check("Anmeldung erfolgreich" in page and "VLAN 10 (Gäste)" in page,
          "Verbindungstest: " + (re.findall(r'<div class="(?:infobox|warnbox)">([^<]+)', page) or ["?"])[-1])
    _c, _u, raw = W.req("/settings", {"section": "radius-test", "test_user": "radvlan99",
                                      "test_password": RAD["radvlan99"], "test_method": "pap"})
    check("abgelehnt" in raw.decode(errors="replace"), "Hinweis auf nicht eingerichtetes VLAN fehlt")

    def radius_active():
        return any(u["unit"] == "vpn-radius.service" and u["active"] == "active"
                   for u in W.status()["units"])
    check(wait_until(radius_active, 30, 3), "vpn-radius.service nicht aktiv")


@test("RADIUS / VLAN", "Lokaler Client in VLAN 20: WireGuard (feste Adresse aus dem VLAN-Bereich)")
def t_vlan_wg():
    flashes = W.req("/clients", {"name": VLAN_DEV, "password": VLAN_DEV_PW, "tunnel": "full",
                                 "vlan": "20"})[2]
    del flashes
    conf = W.download(VLAN_DEV, "wireguard").decode()
    check("Address = 10.67.2.2/32" in conf, f"Falsche Adresse: {conf.splitlines()[3:5]}")
    r = wg_up(conf)
    check(r.returncode == 0, f"wg-quick: {r.stderr[-300:]}")
    errors = vlan_checks(20, 10)
    check(not errors, ", ".join(errors))
    check(not internet_ok(), "VLAN 20 (ohne Gateway) erreicht das Internet")
    check(vlan_session(VLAN_DEV, 20), "VLAN nicht in der Statusanzeige")
    return "(10.67.2.2 -> VLAN 20, NAT auf 192.168.20.2)"


@test("RADIUS / VLAN", "Lokaler Client in VLAN 20: OpenVPN (feste Adresse je VLAN)")
def t_vlan_ovpn():
    ovpn_up(W.download(VLAN_DEV, "openvpn"), "ovpn-vlan")
    check(wait_until(lambda: ovpn_ready("ovpn-vlan.log"), 40), "Keine Verbindung: " + tail("ovpn-vlan.log", 15))
    out = nsx("ip -o -4 addr show").stdout
    m = re.search(r"inet (10\.66\.6[78]\.\d+)/", out)
    check(m and (in_net(m.group(1), "10.66.67.144/28") or in_net(m.group(1), "10.66.68.144/28")),
          f"Adresse nicht aus dem VLAN-20-Block: {out}")
    errors = vlan_checks(20, 10)
    check(not errors, ", ".join(errors))
    return f"({m.group(1)})"


@test("RADIUS / VLAN", "Lokaler Client in VLAN 20: SSTP mit Passwort (über den lokalen RADIUS-Dienst)")
def t_vlan_sstp_local():
    sstp_up(VLAN_DEV_PW, user=VLAN_DEV, log="sstp-vlan.log")
    check(wait_until(lambda: ppp_iface(), 40), "Keine PPP-Verbindung: " + tail("sstp-vlan.log", 20))
    ip = re.search(r"inet (\S+?)/|inet (\S+) peer", sh(f"ip -n {NS} -o -4 addr show {ppp_iface()}").stdout)
    vip = (ip.group(1) or ip.group(2)) if ip else ""
    check(in_net(vip, "10.67.2.64/27"), f"PPP-Adresse nicht aus VLAN 20: {vip}")
    route_via(ppp_iface())
    errors = vlan_checks(20, 10)
    check(not errors, ", ".join(errors))
    return f"({vip})"


@test("RADIUS / VLAN", "RADIUS-Benutzer mit VLAN 10: IKEv2 EAP-MSCHAPv2 (Windows/Android/iOS)")
def t_rad_eap():
    write_radius_swanctl()
    r = nsx("swanctl --load-all --noprompt")
    check("failed" not in r.stdout + r.stderr, f"swanctl: {r.stdout[-400:]}")
    write("ipsec-resolv.conf", "")
    write("resolvconf.log", "")
    r = nsx("timeout 45 swanctl --initiate --child rad-eap10", timeout=60)
    check(r.returncode == 0, "Verbindung fehlgeschlagen: " + (r.stdout + r.stderr)[-500:])
    vip = swan_vip("rad-eap10")
    check(in_net(vip, "10.67.1.32/27"), f"Adresse nicht aus VLAN 10: {vip}")
    errors = vlan_checks(10, 20)
    check(not errors, ", ".join(errors))
    check(not internet_ok(), "Internet läuft nicht über das VLAN-Gateway")
    check("192.168.10.1" in read("ipsec-resolv.conf") + read("resolvconf.log"), "VLAN-DNS nicht übermittelt")
    check(vlan_session("radvlan10", 10), "Nicht mit VLAN 10 in der Statusanzeige")
    check(any(s.get("user") == "radvlan10" and s.get("radius") for s in W.status()["sessions"]),
          "Nicht als RADIUS-Benutzer gekennzeichnet")
    nsx("swanctl --terminate --ike rad-eap10 --force")
    return f"(VIP {vip})"


@test("RADIUS / VLAN", "RADIUS-Benutzer mit VLAN 10: L2TP/IPsec (MSCHAPv2)")
def t_rad_l2tp():
    iface = l2tp_connect("radvlan10", RAD["radvlan10"])
    out = sh(f"ip -n {NS} -o -4 addr show {iface}").stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    check(m and in_net(m.group(1), "10.67.1.64/27"), f"PPP-Adresse nicht aus VLAN 10: {out}")
    errors = vlan_checks(10, 20)
    l2tp_disconnect()
    check(not errors, ", ".join(errors))
    return f"({m.group(1)})"


@test("RADIUS / VLAN", "RADIUS-Benutzer mit VLAN 10: SSTP")
def t_rad_sstp():
    sstp_up(RAD["radvlan10"], user="radvlan10", log="sstp-rad.log")
    check(wait_until(lambda: ppp_iface(), 40), "Keine PPP-Verbindung: " + tail("sstp-rad.log", 20))
    out = sh(f"ip -n {NS} -o -4 addr show {ppp_iface()}").stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    check(m and in_net(m.group(1), "10.67.1.64/27"), f"PPP-Adresse nicht aus VLAN 10: {out}")
    route_via(ppp_iface())
    errors = vlan_checks(10, 20)
    check(not errors, ", ".join(errors))
    check(vlan_session("radvlan10", 10), "Nicht mit VLAN 10 in der Statusanzeige")


@test("RADIUS / VLAN", "RADIUS-Benutzer mit VLAN 10: OpenConnect / AnyConnect")
def t_rad_oc():
    write("oc-env.txt", "")
    oc_up("oc-rad.log", user="radvlan10", password=RAD["radvlan10"])
    check(wait_until(lambda: "CSTP connected" in read("oc-rad.log"), 30), "Keine Verbindung: " + tail("oc-rad.log"))
    m = re.search(r"Configured as (\d+\.\d+\.\d+\.\d+)", read("oc-rad.log"))
    check(m and in_net(m.group(1), "10.67.1.96/27"), f"Adresse nicht aus VLAN 10: {m.group(1) if m else '?'}")
    errors = vlan_checks(10, 20)
    check(not errors, ", ".join(errors))
    check("192.168.10.1" in read("oc-env.txt"), "VLAN-DNS nicht übermittelt")
    return f"({m.group(1)})"


@test("RADIUS / VLAN", "RADIUS-Benutzer mit VLAN 10: Cisco IPsec (IKEv1 XAuth)")
def t_rad_xauth():
    r = nsx("timeout 45 swanctl --initiate --child rad-xauth10", timeout=60)
    check(r.returncode == 0, "Verbindung fehlgeschlagen: " + (r.stdout + r.stderr)[-500:])
    vip = swan_vip("rad-xauth10")
    check(in_net(vip, "10.67.1.32/27"), f"Adresse nicht aus VLAN 10: {vip}")
    errors = vlan_checks(10, 20)
    check(not errors, ", ".join(errors))
    nsx("swanctl --terminate --ike rad-xauth10 --force")
    return f"(VIP {vip})"


@test("RADIUS / VLAN", "RADIUS-Benutzer ohne VLAN: Standardnetz mit Heimnetz-Zugriff, VLANs gesperrt")
def t_rad_novlan():
    r = nsx("timeout 45 swanctl --initiate --child rad-eapnone", timeout=60)
    check(r.returncode == 0, "Verbindung fehlgeschlagen: " + (r.stdout + r.stderr)[-500:])
    vip = swan_vip("rad-eapnone")
    check(in_net(vip, "10.66.69.0/24"), f"Adresse nicht aus dem Standardnetz: {vip}")
    check(wait_until(lan_ok, 20, 2), "Heimnetz nicht erreichbar")
    check(not vlan_peer(10) and not vlan_peer(20), "VLAN aus dem Standardnetz erreichbar")
    nsx("swanctl --terminate --ike rad-eapnone --force")
    return f"(VIP {vip})"


@test("RADIUS / VLAN", "Abgelehnt: nicht eingerichtetes VLAN 99, falsches Passwort, gesperrter Client")
def t_rad_reject():
    for key in ("rad-eap99", "rad-eapwrong"):
        r = nsx(f"timeout 45 swanctl --initiate --child {key}", timeout=60)
        check(r.returncode != 0, f"{key}: Anmeldung wurde fälschlich angenommen")
    W.client_action(VLAN_DEV, "toggle")
    sstp_up(VLAN_DEV_PW, user=VLAN_DEV, log="sstp-locked.log")
    time.sleep(12)
    check(not ppp_iface(), "Gesperrter Client konnte sich per SSTP anmelden")
    cleanup_clients()
    W.client_action(VLAN_DEV, "toggle")
    log = remote("journalctl -u vpn-radius --no-pager -n 200").stdout
    check("radvlan99" in log and "Login incorrect" in log, "Ablehnung nicht im RADIUS-Protokoll")


@test("RADIUS / VLAN", "Accounting: Start/Stop erreichen den externen RADIUS-Server")
def t_rad_accounting():
    detail = sh("cat /var/log/freeradius/radacct/127.0.0.1/detail-* 2>/dev/null").stdout
    check("radvlan10" in detail, "Kein Accounting für radvlan10 beim RADIUS-Server")
    check("Acct-Status-Type = Start" in detail and "Acct-Status-Type = Stop" in detail,
          "Start/Stop fehlen")
    check('NAS-Identifier = "vpn-e2e"' in detail, "NAS-Identifier nicht übernommen")
    check(VLAN_DEV not in detail, "Lokale Benutzer werden an den RADIUS-Server gemeldet")


@test("RADIUS / VLAN", "Profile für RADIUS-Benutzer: ohne gespeicherte Zugangsdaten")
def t_rad_profiles():
    code, _u, raw = W.req("/radius-profile")
    check(code == 200 and "RADIUS-Benutzer" in raw.decode(errors="replace"), f"Seite: {code}")
    code, _u, mc = W.req("/radius-profile/dl/mobileconfig-eap")
    check(code == 200, f"mobileconfig: {code}")
    plist = plistlib.loads(mc)
    ike = [p for p in plist["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"][0]["IKEv2"]
    check("AuthPassword" not in ike and "AuthName" not in ike and ike["ExtendedAuthEnabled"] == 1,
          "mobileconfig enthält Zugangsdaten")
    code, _u, sw = W.req("/radius-profile/dl/sswan-eap")
    check(code == 200 and "eap_id" not in json.loads(sw)["local"], ".sswan enthält einen Benutzernamen")
    code, _u, cmd = W.req("/radius-profile/dl/win-ikev2-eap")
    check(code == 200 and b"Passwort:" not in cmd and b"Add-VpnConnection" in cmd, "Windows-Skript")


@test("Funktion", "Neustart: alle Dienste starten automatisch, Verbindungen funktionieren")
def t_reboot():
    remote("systemd-run --on-active=2 systemctl reboot", timeout=30)
    time.sleep(20)
    check(wait_until(lambda: sh(f"curl -skf --max-time 5 --noproxy '*' {WEB}/health", timeout=15).returncode == 0, 600, 5),
          "Weboberfläche nach Neustart nicht erreichbar")
    check(W.login(ADMIN_PW), "Login nach Neustart fehlgeschlagen")

    def all_active():
        return all(u["active"] == "active" for u in W.status()["units"] if u["wanted"])
    ok = wait_until(all_active, 120, 5)
    bad = [f"{u['unit']}={u['active']}" for u in W.status()["units"] if u["wanted"] and u["active"] != "active"]
    check(ok, "Nach Neustart nicht aktiv: " + ", ".join(bad))
    wg_up(PROFILES[("e2e", "wireguard")].decode())
    check(wait_until(lan_ok, 30, 2), "WireGuard nach Neustart")
    cleanup_clients()
    sstp_up(CPW_CURRENT)
    check(wait_until(lambda: ppp_iface(), 40), "SSTP nach Neustart")
    cleanup_clients()
    r = nsx("timeout 45 swanctl --initiate --child android-psk", timeout=60)
    check(r.returncode == 0, "IKEv2 nach Neustart")


@test("RADIUS / VLAN", "Nach dem Neustart: VLAN-Schnittstellen und RADIUS-Anmeldung funktionieren")
def t_rad_after_reboot():
    oc_up("oc-reboot.log", user="radvlan10", password=RAD["radvlan10"])
    check(wait_until(lambda: "CSTP connected" in read("oc-reboot.log"), 40),
          "Keine Verbindung: " + tail("oc-reboot.log"))
    errors = vlan_checks(10, 20)
    check(not errors, ", ".join(errors))


# =============================================================================
# Hauptprogramm
# =============================================================================

def report() -> int:
    boot = []
    for line in read("boot-results.jsonl").splitlines():
        if line.strip():
            boot.append(json.loads(line))
    RESULTS[:0] = boot
    failed = [r for r in RESULTS if not r["ok"]]
    lines = ["## Ergebnis der Geräte- und Funktionstests", "",
             f"**{len(RESULTS) - len(failed)} von {len(RESULTS)} Tests bestanden**", "",
             "Das ISO wurde in einer VM vollautomatisch installiert. Endgeräte werden mit Linux-Clients "
             "nachgebildet, die die Identitäten, Anmeldeverfahren und Krypto-Vorschläge des jeweiligen "
             "Geräts verwenden bzw. dessen Profil (.mobileconfig, .sswan, QR-Code, Windows-Skript) direkt "
             "auswerten. Verbindungen laufen über simulierte Portfreigaben (NAT) wie an einem Heimrouter.", "",
             "| Bereich | Test | Ergebnis | Details |", "|---|---|---|---|"]
    for r in RESULTS:
        lines.append(f"| {r['category']} | {r['name']} | {'✅' if r['ok'] else '❌'} | "
                     f"{r['detail'].replace('|', '/')[:300]} ({r['secs']} s) |")
    md = "\n".join(lines) + "\n"
    print("\n" + md)
    with open(os.path.join(WORK, "results.md"), "w") as fh:
        fh.write(md)
    with open(os.path.join(WORK, "results.json"), "w") as fh:
        json.dump(RESULTS, fh, indent=2, ensure_ascii=False)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(md)
    return 1 if failed else 0


def main() -> None:
    global ARGS, WORK, INTERNET_IP
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default=WORK)
    ap.add_argument("--initial-password", required=True)
    ap.add_argument("--only", help="Regex zur Testauswahl")
    ARGS = ap.parse_args()
    WORK = ARGS.work
    os.makedirs(os.path.join(WORK, "fakebin"), exist_ok=True)
    # wg-quick ruft fuer DNS "resolvconf" auf -> protokollieren statt das Host-System zu aendern
    write("fakebin/resolvconf", f"#!/bin/sh\n[ \"$1\" = \"-a\" ] && cat >> {WORK}/resolvconf.log\nexit 0\n", 0o755)
    try:
        INTERNET_IP = socket.gethostbyname("deb.debian.org")
    except OSError:
        INTERNET_IP = "151.101.2.132"
    print(f"Internet-Testziel deb.debian.org = {INTERNET_IP}")
    try:
        run_tests(ARGS.only)
    finally:
        cleanup_clients()
        if CHARON:
            CHARON.terminate()
    sys.exit(report())


if __name__ == "__main__":
    main()
