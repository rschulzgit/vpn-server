import re

import pytest

from vpnserver import apply, state as st, util


@pytest.fixture()
def client():
    import shutil, os
    shutil.rmtree(util.ROOT, ignore_errors=True)
    os.makedirs(util.ROOT)
    s = st.default_state()
    s["admin"]["password_hash"] = st.hash_password("Start12345")
    s["admin"]["initial_password"] = "Start12345"
    apply.apply(s)
    st.save(s)
    from vpnserver.web import create_app
    app = create_app()
    app.config["SESSION_COOKIE_SECURE"] = False
    return app.test_client()


def token(resp):
    return re.search(r'name="csrf-token" content="([^"]+)"', resp.text).group(1)


def login_and_setup(c):
    tok = token(c.get("/login"))
    r = c.post("/login", data={"username": "admin", "password": "Start12345", "csrf_token": tok})
    assert r.headers["Location"].endswith("/")
    tok = token(c.get("/setup"))
    c.post("/setup", data={"password": "NeuesPasswort1", "password2": "NeuesPasswort1", "csrf_token": tok})
    r = c.post("/setup", data={"public_host": "vpn.example.org", "dns": "1.1.1.1", "csrf_token": tok})
    assert r.status_code == 302 and "/setup" not in r.headers["Location"]
    return tok


def test_login_required(client):
    assert client.get("/clients").status_code == 302
    assert client.get("/api/status").status_code == 401
    assert client.get("/ca.crt").status_code == 200


def test_bad_login(client):
    tok = token(client.get("/login"))
    r = client.post("/login", data={"username": "admin", "password": "x", "csrf_token": tok})
    assert r.status_code == 401


def test_full_flow(client):
    tok = login_and_setup(client)
    for page in ("/", "/clients", "/clients/neu", "/status", "/status/protokoll", "/statistik", "/werkzeuge", "/settings/allgemein", "/settings/protokolle", "/settings/radius", "/settings/vlans", "/settings/ipsec", "/settings/dyndns", "/settings/zertifikate", "/system", "/system/netzwerk", "/system/updates", "/system/sicherung", "/system/dienste"):
        assert client.get(page).status_code == 200, page
    # Alte Adressen leiten weiter
    assert client.get("/settings").headers["Location"].endswith("/settings/allgemein")
    assert client.get("/status?log=ocserv.service").headers["Location"].endswith(
        "/system/dienste?log=ocserv.service")
    assert client.get("/settings/gibtsnicht").status_code == 404
    assert client.get("/system/gibtsnicht").status_code == 404
    r = client.post("/clients", data={"name": "test-handy", "tunnel": "full", "csrf_token": tok})
    assert r.headers["Location"].endswith("/clients/test-handy")
    page = client.get("/clients/test-handy")
    assert page.status_code == 200 and "<svg" in page.text
    for kind in ("wireguard", "openvpn", "p12", "mobileconfig-cert", "sswan-eap", "win-sstp", "zip"):
        assert client.get(f"/clients/test-handy/dl/{kind}").status_code == 200, kind
    assert client.get("/clients/test-handy/dl/win-pptp").status_code == 404
    # CSRF
    assert client.post("/clients/test-handy/action", data={"action": "toggle"}).status_code == 400
    # Teilen-Link
    client.post("/clients/test-handy/action", data={"action": "share", "csrf_token": tok})
    m = re.search(r"/share/([A-Za-z0-9_\-]+)", client.get("/clients/test-handy").text)
    assert m
    assert client.get(f"/share/{m.group(1)}").status_code == 200
    assert client.get(f"/share/{m.group(1)}", environ_base={"REMOTE_ADDR": "8.8.8.8"}).status_code == 404
    # Loeschen
    client.post("/clients/test-handy/action", data={"action": "delete", "csrf_token": tok})
    assert "test-handy" not in st.load()["clients"]


def test_port_conflict(client):
    tok = login_and_setup(client)
    client.post("/settings", data={"section": "protocols", "csrf_token": tok, "sstp_enabled": "1",
                                   "sstp_port": "4443", "openconnect_enabled": "1",
                                   "openconnect_port": "4443"})
    assert "berschneiden" in client.get("/settings/protokolle").text


def test_radius_vlan_flow(client):
    tok = login_and_setup(client)
    # VLAN anlegen (Fehler: Gateway ausserhalb, dann korrekt)
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "name": "Gäste", "address": "192.168.10.2/24",
                                   "gateway": "192.168.11.1"})
    assert "Gateway muss im VLAN-Netz" in client.get("/settings/vlans").text
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "name": "Gäste", "address": "192.168.10.2/24",
                                   "gateway": "192.168.10.1", "dns": "192.168.10.1"})
    s = st.load()
    assert s["vlans"]["10"]["vpn_net"] == "10.67.1.0/24"
    # Doppelte ID
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "address": "192.168.12.2/24"})
    assert "bereits eingerichtet" in client.get("/settings/vlans").text
    # Client im VLAN anlegen
    client.post("/clients", data={"name": "gast", "tunnel": "full", "vlan": "10", "csrf_token": tok})
    s = st.load()
    assert s["clients"]["gast"]["vlan"] == "10"
    assert s["clients"]["gast"]["wg"]["ip"] == "10.67.1.2"
    page = client.get("/clients/gast")
    assert "VLAN 10" in page.text
    wg = client.get("/clients/gast/dl/wireguard").text
    assert "Address = 10.67.1.2/32" in wg and "DNS = 192.168.10.1" in wg
    # VLAN wechseln -> Standardnetz
    client.post("/clients/gast/action", data={"action": "update", "tunnel": "full", "vlan": "",
                                              "csrf_token": tok})
    s = st.load()
    assert s["clients"]["gast"]["vlan"] == "" and s["clients"]["gast"]["wg"]["ip"].startswith("10.66.66.")
    client.post("/clients/gast/action", data={"action": "update", "tunnel": "split", "vlan": "10",
                                              "csrf_token": tok})
    wg = client.get("/clients/gast/dl/wireguard").text
    assert "AllowedIPs = 192.168.10.0/24" in wg
    # RADIUS-Server
    client.post("/settings", data={"section": "radius", "csrf_token": tok, "enabled": "1",
                                   "host1": "192.168.1.10", "auth_port1": "1812",
                                   "acct_port1": "1813", "secret1": "geheim'", "local_users": "1"})
    assert "Anführungszeichen" in client.get("/settings/radius").text
    client.post("/settings", data={"section": "radius", "csrf_token": tok, "enabled": "1",
                                   "host1": "192.168.1.10", "auth_port1": "1812",
                                   "acct_port1": "1813", "secret1": "Geheim123!", "local_users": "1",
                                   "accounting": "1", "unknown_vlan": "reject"})
    s = st.load()
    assert s["radius"]["enabled"] and s["radius"]["servers"][0]["secret"] == "Geheim123!"
    # Geheimnis bleibt erhalten, wenn das Feld leer ist
    client.post("/settings", data={"section": "radius", "csrf_token": tok, "enabled": "1",
                                   "host1": "192.168.1.10", "local_users": "1"})
    assert st.load()["radius"]["servers"][0]["secret"] == "Geheim123!"
    for page in ("/settings/radius", "/settings/vlans", "/settings/vlans?vlan=10", "/radius-profile", "/status"):
        assert client.get(page).status_code == 200, page
    assert "VLAN 10 bearbeiten" in client.get("/settings/vlans?vlan=10").text
    assert client.get("/settings?vlan=10").headers["Location"].endswith("/settings/vlans?vlan=10")
    for kind in ("mobileconfig-eap", "sswan-eap", "win-ikev2-eap", "win-sstp", "ca"):
        r = client.get(f"/radius-profile/dl/{kind}")
        assert r.status_code == 200, kind
    assert b"AuthPassword" not in client.get("/radius-profile/dl/mobileconfig-eap").data
    assert client.get("/radius-profile/dl/openvpn").status_code == 404
    # VLAN loeschen -> Client ins Standardnetz
    client.post("/settings", data={"section": "vlan-delete", "csrf_token": tok, "id": "10"})
    s = st.load()
    assert not s["vlans"] and s["clients"]["gast"]["vlan"] == ""


def test_dashboard_stats_tools(client):
    import json as _json
    tok = login_and_setup(client)
    client.post("/clients", data={"name": "csp-test", "tunnel": "full", "csrf_token": tok})
    for page in ("/", "/clients", "/clients/neu", "/status", "/status/protokoll", "/statistik", "/werkzeuge", "/settings/allgemein", "/settings/protokolle", "/settings/radius", "/settings/vlans", "/settings/ipsec", "/settings/dyndns", "/settings/zertifikate", "/system", "/system/netzwerk", "/system/updates", "/system/sicherung", "/system/dienste", "/clients/csp-test", "/radius-profile"):
        r = client.get(page)
        assert r.status_code == 200, page
        assert 'style="' not in r.text, f"Inline-Style (CSP) auf {page}"
    live = client.get("/api/live").get_json()
    assert "points" in live and "system" in live and "today" in live
    hist = client.get("/api/history?range=30d").get_json()
    assert len(hist["series"]) == 30
    assert client.get("/api/history?range=quatsch").get_json()["range"] == "24h"
    assert "events" in client.get("/api/events?limit=5").get_json()
    r = client.post("/api/tools/ping", data={"host": "1.2.3.4;id", "csrf_token": tok})
    assert r.status_code == 400 and "Ungültige" in r.get_json()["output"]
    assert client.post("/api/tools/ping", data={"host": "x"}).status_code == 400  # ohne CSRF
    r = client.post("/werkzeuge/wol", data={"action": "add", "name": "Büro-PC", "mac": "00:11:22:33:44:55",
                                            "csrf_token": tok})
    assert st.load()["tools"]["wol"][0]["mac"] == "00:11:22:33:44:55"
    assert "Büro-PC" in client.get("/werkzeuge").text
    client.post("/werkzeuge/wol", data={"action": "delete", "mac": "00:11:22:33:44:55", "csrf_token": tok})
    assert st.load()["tools"]["wol"] == []
    r = client.post("/werkzeuge/mitschnitt", data={"iface": "gibtsnicht", "seconds": "1", "csrf_token": tok})
    assert r.status_code == 302
    r = client.post("/status/trennen", data={"user": "test", "csrf_token": tok})
    assert r.status_code == 302
    del _json


def test_software_update_settings(client):
    tok = login_and_setup(client)
    page = client.get("/system/updates").text
    assert "Software-Update" in page and "rschulzgit/vpn-server" in page
    assert 'name="channel" value="release" checked' in page  # Standard: Releases ohne Token
    client.post("/system", data={"action": "app-update-settings", "repo": "kaputt", "channel": "branch",
                                 "branch": "main", "csrf_token": tok})
    assert "Ungültiges Repository" in client.get("/system/updates").text
    client.post("/system", data={"action": "app-update-settings", "repo": "rschulzgit/vpn-server",
                                 "channel": "branch", "branch": "claude/vpn-server-iso",
                                 "token": "github_pat_" + "A" * 40, "auto": "1", "csrf_token": tok})
    u = st.load()["update"]
    assert u["branch"] == "claude/vpn-server-iso" and u["auto"] and u["token"].startswith("github_pat_")
    assert "gespeichert" in client.get("/system/updates").text
    client.post("/system", data={"action": "app-update-settings", "repo": "rschulzgit/vpn-server",
                                 "channel": "release", "branch": "", "token_clear": "1", "csrf_token": tok})
    u = st.load()["update"]
    assert u["token"] == "" and u["channel"] == "release" and not u["auto"]
    assert client.get("/api/update/status").get_json()["state"] == "idle"


def test_sponsor_link_only_on_system_page(client):
    from vpnserver import __sponsor_url__
    tok = login_and_setup(client)
    assert __sponsor_url__ == "https://github.com/sponsors/rschulzgit"
    page = client.get("/system").text
    assert f'href="{__sponsor_url__}"' in page and "Projekt unterstützen" in page
    assert 'rel="noopener noreferrer"' in page and "GPL-3.0-or-later" in page
    client.post("/clients", data={"name": "sp-test", "tunnel": "full", "csrf_token": tok})
    for other in ("/", "/clients", "/clients/neu", "/status", "/status/protokoll", "/statistik", "/werkzeuge", "/settings/allgemein", "/settings/protokolle", "/settings/radius", "/settings/vlans", "/settings/ipsec", "/settings/dyndns", "/settings/zertifikate", "/system", "/system/netzwerk", "/system/updates", "/system/sicherung", "/system/dienste", "/clients/sp-test", "/radius-profile"):
        if other == "/system":
            continue
        text = client.get(other).text
        assert __sponsor_url__ not in text and "Projekt unterstützen" not in text, other


def test_navigation_and_add_client(client):
    """Seitenleiste mit Gruppen, Client-Anlage ueber eigene Seite, Netzwerkplan mit Links."""
    import json as _json
    tok = login_and_setup(client)
    page = client.get("/settings/radius").text
    # Gruppe der aktuellen Seite ist aufgeklappt, der Unterpunkt markiert
    assert re.search(r'<details class="nav-group" data-group="einstellungen" open>', page)
    assert re.search(r'<details class="nav-group" data-group="system" >', page)
    assert re.search(r'class="active" href="/settings/radius">RADIUS<', page)
    for href in ("/status", "/status/protokoll", "/settings/vlans", "/system/dienste", "/system/updates"):
        assert f'href="{href}"' in page, href
    # Dienste stehen unter System, nicht mehr bei den Verbindungen
    assert "systemd-Unit" in client.get("/system/dienste").text
    assert "systemd-Unit" not in client.get("/status").text
    assert "Verbindungsprotokoll" in client.get("/status/protokoll").text
    # Clients: Button statt Formular unter der Liste
    clients = client.get("/clients").text
    assert 'href="/clients/neu"' in clients and 'name="password"' not in clients
    form = client.get("/clients/neu").text
    assert 'action="/clients"' in form and 'name="name"' in form
    r = client.post("/clients", data={"name": "neu", "tunnel": "full", "csrf_token": tok})
    assert r.headers["Location"].endswith("/clients/neu")
    assert "reserviert" in client.get("/clients/neu").text and "neu" not in st.load()["clients"]
    r = client.post("/clients", data={"name": "nav-test", "tunnel": "full", "csrf_token": tok})
    assert r.headers["Location"].endswith("/clients/nav-test")
    # Netzwerkplan: Daten fuer anklickbare Geraete
    dash = client.get("/").text
    data = _json.loads(re.search(r'<script id="dash-data" type="application/json">(.*?)</script>', dash, re.S).group(1))
    assert "nav-test" in data["clients"] and data["client_url"] == "/clients/__NAME__"
    assert data["sessions_url"] == "/status"
