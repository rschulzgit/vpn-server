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
