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
    for page in ("/", "/clients", "/status", "/settings", "/system"):
        assert client.get(page).status_code == 200, page
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
    assert "berschneiden" in client.get("/settings").text


def test_radius_vlan_flow(client):
    tok = login_and_setup(client)
    # VLAN anlegen (Fehler: Gateway ausserhalb, dann korrekt)
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "name": "Gäste", "address": "192.168.10.2/24",
                                   "gateway": "192.168.11.1"})
    assert "Gateway muss im VLAN-Netz" in client.get("/settings").text
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "name": "Gäste", "address": "192.168.10.2/24",
                                   "gateway": "192.168.10.1", "dns": "192.168.10.1"})
    s = st.load()
    assert s["vlans"]["10"]["vpn_net"] == "10.67.1.0/24"
    # Doppelte ID
    client.post("/settings", data={"section": "vlan-save", "csrf_token": tok, "id": "10",
                                   "address": "192.168.12.2/24"})
    assert "bereits eingerichtet" in client.get("/settings").text
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
    assert "Anführungszeichen" in client.get("/settings").text
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
    for page in ("/settings", "/settings?vlan=10", "/radius-profile", "/status"):
        assert client.get(page).status_code == 200, page
    for kind in ("mobileconfig-eap", "sswan-eap", "win-ikev2-eap", "win-sstp", "ca"):
        r = client.get(f"/radius-profile/dl/{kind}")
        assert r.status_code == 200, kind
    assert b"AuthPassword" not in client.get("/radius-profile/dl/mobileconfig-eap").data
    assert client.get("/radius-profile/dl/openvpn").status_code == 404
    # VLAN loeschen -> Client ins Standardnetz
    client.post("/settings", data={"section": "vlan-delete", "csrf_token": tok, "id": "10"})
    s = st.load()
    assert not s["vlans"] and s["clients"]["gast"]["vlan"] == ""
