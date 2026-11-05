#!/usr/bin/env python3
"""E2E-Hilfe: Weboberflaeche wie ein Benutzer bedienen (Login, Assistent,
Client anlegen, Profile herunterladen). Nur Standardbibliothek."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request


class Web:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.ProxyHandler({}))
        self.csrf = ""

    def req(self, path: str, data: dict | None = None) -> tuple[int, str, bytes]:
        body = None
        if data is not None:
            data = dict(data)
            data.setdefault("csrf_token", self.csrf)
            body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(self.base + path, data=body)
        try:
            with self.opener.open(r, timeout=180) as resp:
                raw = resp.read()
                url = resp.geturl()
                code = resp.status
        except urllib.error.HTTPError as exc:
            raw, url, code = exc.read(), exc.geturl(), exc.code
        text = raw.decode(errors="replace")
        m = re.search(r'name="csrf-token" content="([^"]+)"', text)
        if m:
            self.csrf = m.group(1)
        return code, url, raw

    def flashes(self, raw: bytes) -> list[str]:
        return re.findall(r'<div class="flash (?:ok|error)">([^<]+)</div>', raw.decode(errors="replace"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--password", required=True, help="Initialpasswort")
    ap.add_argument("--new-password", required=True)
    ap.add_argument("--host", required=True, help="oeffentliche Adresse")
    ap.add_argument("--client", default="e2e")
    ap.add_argument("--client-password", default="E2eTest-Pass1")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    w = Web(args.url)
    w.req("/login")
    code, url, raw = w.req("/login", {"username": "admin", "password": args.password})
    if "/setup" not in url:
        sys.exit(f"Login fehlgeschlagen ({code} {url}): {w.flashes(raw)}")
    print("Login OK")
    code, url, raw = w.req("/setup", {"password": args.new_password, "password2": args.new_password,
                                      "system_too": "1"})
    print("Passwort gesetzt:", w.flashes(raw))
    # Private Adressen lehnt der Assistent ab -> Testname "vpn.test" (per /etc/hosts aufgeloest)
    code, url, raw = w.req("/setup", {"public_host": args.host, "dns": "1.1.1.1"})
    if "/setup" in url:
        sys.exit(f"Einrichtung fehlgeschlagen: {w.flashes(raw)}")
    print("Einrichtung abgeschlossen:", w.flashes(raw))

    # Alle Protokolle aktivieren (auch PPTP, um die Konfiguration mitzutesten)
    form = {"section": "protocols"}
    for p in ("wireguard", "openvpn", "ikev2", "l2tp", "ikev1_xauth", "sstp", "openconnect", "pptp"):
        form[f"{p}_enabled"] = "1"
    form.update(openvpn_udp="1", openvpn_tcp="1", wireguard_port="51820", openvpn_udp_port="1194",
                openvpn_tcp_port="1194", sstp_port="443", openconnect_port="4443")
    code, url, raw = w.req("/settings", form)
    print("Protokolle:", w.flashes(raw))

    code, url, raw = w.req("/clients", {"name": args.client, "password": args.client_password,
                                        "note": "E2E", "tunnel": "full"})
    if f"/clients/{args.client}" not in url:
        sys.exit(f"Client anlegen fehlgeschlagen: {w.flashes(raw)}")
    print("Client angelegt")

    kinds = ["wireguard", "openvpn", "ca", "p12", "json", "credentials", "zip", "sswan-cert",
             "mobileconfig-cert", "win-ikev2-eap", "win-sstp", "win-l2tp", "win-pptp"]
    for kind in kinds:
        code, url, raw = w.req(f"/clients/{args.client}/dl/{kind}")
        if code != 200 or not raw:
            sys.exit(f"Download {kind} fehlgeschlagen: {code}")
        ext = {"wireguard": "conf", "openvpn": "ovpn", "ca": "crt", "p12": "p12", "json": "json",
               "credentials": "txt", "zip": "zip", "sswan-cert": "sswan",
               "mobileconfig-cert": "mobileconfig"}.get(kind, "cmd")
        with open(os.path.join(args.out, f"{kind}.{ext}"), "wb") as fh:
            fh.write(raw)
        print(f"  {kind}: {len(raw)} Bytes")

    for page in ("/", "/clients", "/status", "/settings", "/system", f"/clients/{args.client}"):
        code, url, raw = w.req(page)
        if code != 200:
            sys.exit(f"Seite {page} liefert {code}")
    for _ in range(30):
        code, url, raw = w.req("/api/status")
        units = json.loads(raw)["units"]
        bad = [u for u in units if u["wanted"] and u["active"] != "active"]
        if not bad:
            break
        time.sleep(3)
    for u in units:
        print(f"  Dienst {u['unit']}: {u['active']} (soll {'an' if u['wanted'] else 'aus'})")
    with open(os.path.join(args.out, "cookies.txt"), "w") as fh:
        fh.write(w.csrf)
    if bad:
        sys.exit("Nicht laufende Dienste: " + ", ".join(u["unit"] for u in bad))
    print("Weboberflaeche OK")


if __name__ == "__main__":
    main()
