import ipaddress
import json
import os
import plistlib
import re
import shutil
import subprocess
import zipfile
import io

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from vpnserver import apply, pki, profiles, render, state as st, util


@pytest.fixture(scope="module")
def srv():
    shutil.rmtree(util.ROOT, ignore_errors=True)
    os.makedirs(util.ROOT)
    s = st.default_state()
    s["server"]["public_host"] = "vpn.example.org"
    s["server"]["dns"] = ["192.168.178.1"]
    s["proto"]["pptp"]["enabled"] = True
    st.new_client(s, "handy")
    st.new_client(s, "laptop", full_tunnel=False, password="Mein-Passwort1")
    apply.apply(s)
    st.save(s)
    return s


def read(path):
    return util.read_file(path)


def test_client_validation(srv):
    with pytest.raises(ValueError):
        st.new_client(srv, "Bad Name")
    with pytest.raises(ValueError):
        st.new_client(srv, "handy")
    with pytest.raises(ValueError):
        st.new_client(srv, "neu", password='a"b c')


def test_wireguard_ips_unique(srv):
    ips = [c["wg"]["ip"] for c in srv["clients"].values()]
    assert len(set(ips)) == len(ips)
    assert "10.66.66.1" not in ips
    for ip in ips:
        assert ipaddress.ip_address(ip) in ipaddress.ip_network("10.66.66.0/24")


def test_password_hash():
    h = st.hash_password("geheim123")
    assert st.verify_password("geheim123", h)
    assert not st.verify_password("falsch", h)


def test_server_cert(srv):
    cert = x509.load_pem_x509_certificate(read(pki.SERVER_CRT).encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "vpn.example.org" in san.get_values_for_type(x509.DNSName)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    oids = {e.dotted_string for e in eku}
    assert "1.3.6.1.5.5.7.3.1" in oids and "1.3.6.1.5.5.8.2.2" in oids
    # Keine CRL-/AIA-Erweiterungen (Windows-SSTP wuerde sonst online pruefen)
    names = {e.oid.dotted_string for e in cert.extensions}
    assert "2.5.29.31" not in names and "1.3.6.1.5.5.7.1.1" not in names
    assert not pki.server_cert_needs_renewal(render.server_cert_names(srv))


def test_client_p12_and_revocation(srv):
    c = srv["clients"]["handy"]
    data = profiles.client_p12(srv, c)
    key, cert, extra = pkcs12.load_key_and_certificates(data, c["p12_password"].encode())
    assert cert.subject.rfc4514_string().endswith("CN=handy") or "CN=handy" in cert.subject.rfc4514_string()
    assert extra and len(extra) == 1
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["handy"]
    # Sperren
    serial = pki.issue_client_cert("wegdamit")
    pki.revoke_client("wegdamit")
    crl = x509.load_pem_x509_crl(read(pki.CRL).encode())
    assert crl.get_revoked_certificate_by_serial_number(int(serial, 16)) is not None
    assert not pki.client_cert_exists("wegdamit")


def test_render_strongswan(srv):
    conf = read(render.SWANCTL_CONF)
    for name in ("ikev2-cert", "ikev2-eap", "ikev2-psk-handy", "ikev2-psk-laptop", "ikev1-xauth", "l2tp-psk"):
        assert re.search(rf"^\s+{name} \{{", conf, re.M), name
    assert "id = vpn.example.org" in conf
    assert 'secret = "Mein-Passwort1"' in conf
    assert "local_ts = dynamic[udp/1701]" in conf and "remote_ts = dynamic[udp]" in conf
    assert ";" not in conf  # swanctl kennt kein Semikolon als Trenner


def test_render_disabled_protocols(srv):
    s = json.loads(json.dumps(srv))
    s["proto"]["l2tp"]["enabled"] = False
    s["proto"]["ikev1_xauth"]["enabled"] = False
    files = render.render_strongswan(s)
    conf = files[render.SWANCTL_CONF][0]
    assert "l2tp-psk" not in conf and "ikev1-xauth" not in conf and "ike-ikev1-shared" not in conf
    acc = render.render_accel(s)[render.ACCEL_CONF][0]
    assert "\nl2tp\n" not in acc and "[l2tp]" not in acc and "[sstp]" in acc


def test_render_accel_and_ocserv(srv):
    acc = read(render.ACCEL_CONF)
    assert "[sstp]" in acc and "[pptp]" in acc and "[l2tp]" in acc
    assert "10.66.70.10-254,name=vpn-ppp" in acc
    assert "[client-ip-range]\n" in acc and "0.0.0.0/0" in acc
    chap = read(render.CHAP_SECRETS)
    assert '"laptop" * "Mein-Passwort1" *' in chap
    oc = read(render.OCPASSWD)
    assert re.search(r"^handy:\*:\$6\$", oc, re.M)
    assert "tcp-port = 4443" in read(render.OCSERV_CONF)


def test_render_firewall(srv):
    nft = read(render.NFT_CONF)
    assert "udp dport 51820 accept" in nft
    assert "udp dport 1701 meta secpath exists accept" in nft
    assert "tcp dport 443 accept" in nft and "tcp dport 1723 accept" in nft
    assert "masquerade" in nft
    # DNS im Heimnetz bleibt auch ohne LAN-Zugriff erreichbar
    assert "ip daddr 192.168.178.1 udp dport 53 accept" in nft


@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("nft"), reason="nft -c benoetigt root")
def test_nft_syntax(srv, tmp_path):
    nft = read(render.NFT_CONF)
    for f in ("nftables-local-input.nft", "nftables-local-forward.nft"):
        (tmp_path / f).write_text("# leer\n")
        nft = nft.replace(f"/etc/vpn-server/{f}", str(tmp_path / f))
    (tmp_path / "t.nft").write_text(nft)
    res = subprocess.run(["nft", "-c", "-f", str(tmp_path / "t.nft")], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def test_profiles(srv):
    c = srv["clients"]["handy"]
    wg = profiles.wireguard_conf(srv, c)
    assert "Endpoint = vpn.example.org:51820" in wg and "AllowedIPs = 0.0.0.0/0, ::/0" in wg
    wg2 = profiles.wireguard_conf(srv, srv["clients"]["laptop"])
    assert "0.0.0.0/0" not in wg2 and "10.66.66.0/24" in wg2
    ovpn = profiles.openvpn_ovpn(srv, c)
    for tag in ("<ca>", "<cert>", "<key>", "<tls-crypt>"):
        assert tag in ovpn
    assert "remote vpn.example.org 1194 udp" in ovpn and "remote vpn.example.org 1194 tcp" in ovpn
    mc = plistlib.loads(profiles.mobileconfig(srv, c, "cert"))
    vpn = [p for p in mc["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed"][0]
    assert vpn["IKEv2"]["RemoteIdentifier"] == "vpn.example.org"
    assert vpn["IKEv2"]["LocalIdentifier"] == "handy"
    sw = json.loads(profiles.sswan(srv, c, "cert"))
    assert sw["type"] == "ikev2-cert" and sw["local"]["p12"]
    cmd = profiles.windows_cmd(srv, c, "l2tp")
    assert "\r\n" in cmd and "AssumeUDPEncapsulationContextOnSendRule" in cmd
    assert "<svg" in profiles.qr_svg(wg)
    z = zipfile.ZipFile(io.BytesIO(profiles.zip_all(srv, c)))
    names = z.namelist()
    assert "handy.ovpn" in names and "handy-wireguard.conf" in names and "handy-windows-pptp.cmd" in names
    data = json.loads(profiles.credentials_json(srv, c))
    assert data["ikev2"]["psk_id"] == "handy" and data["openconnect_pin"].startswith("pin-sha256:")


def test_backup_roundtrip(srv):
    from vpnserver import system
    data = system.backup_bytes()
    system.restore_bytes(data)
    s2 = st.load()
    assert set(s2["clients"]) == set(srv["clients"])
    with pytest.raises(ValueError):
        system.restore_bytes(b"kein tar")


def test_radius_vlan_render():
    import ipaddress
    from vpnserver import render, vlan
    s = st.default_state()
    s["server"]["public_host"] = "vpn.example.org"
    st.ensure_server_keys(s)
    s["vlans"]["10"] = vlan.validate(s, {"id": "10", "name": "Gäste", "address": "192.168.10.2/24",
                                         "gateway": "192.168.10.1", "dns": "192.168.10.1"})
    s["vlans"]["20"] = vlan.validate(s, {"id": "20", "name": "IoT", "address": "192.168.20.2/24"})
    st.new_client(s, "alice", password="alicepass123", vlan="10")
    st.new_client(s, "bob", password="bobpass12345")
    st.new_client(s, "carol", password="carolpass123")["enabled"] = False
    assert vlan.radius_mode(s)
    files = render.render_all(s)
    swan = files[render.SWANCTL_CONF][0]
    # Gruppenbasierte Zuordnung fuer EAP/XAuth, Zertifikat je Client
    assert "groups = vlan0" in swan and "groups = vlan10" in swan and "auth = eap-radius" in swan
    assert "auth = xauth-radius" in swan and "ikev2-cert-alice" in swan and "eap-alice" not in swan
    # Zertifikats-Bindung je Client: das Client-Zertifikat, niemals der Schluessel
    certs = re.findall(r"^\s*certs = (\S+)", swan, re.M)
    assert "/etc/vpn-server/pki/clients/alice.crt" in certs
    assert not [c for c in certs if c.endswith(".key")]
    assert "vlan10-ipsec {\n        addrs = 10.67.1.34-10.67.1.62\n        dns = 192.168.10.1" in swan
    assert "class_group = yes" in files[render.STRONGSWAN_CONF][0]
    accel = files[render.ACCEL_CONF][0]
    assert "\nradius\n" in accel and "10.67.1.66-94,name=vlan10" in accel and "chap-secrets=" not in accel
    oc = files[render.OCSERV_CONF][0]
    assert 'auth = "radius[' in oc and "config-per-group" in oc
    assert files[f"{render.OCSERV_GROUP_DIR}/vlan10"][0].startswith("# VLAN 10")
    users = files[render.RADIUS_USERS][0]
    assert "\"alice\" Cleartext-Password := 'alicepass123'" in users
    assert 'Tunnel-Private-Group-Id := "10"' in users and '"carol" Auth-Type := Reject' in users
    rconf = files[render.RADIUSD_CONF][0]
    assert 'case "10"' in rconf and 'case "20"' in rconf and "proxy_requests = no" in rconf
    ccd = files[f"{render.ccd_dir('udp')}/alice"][0]
    ip = ccd.split("ifconfig-push ")[1].split()[0]
    assert ipaddress.ip_address(ip) in ipaddress.ip_network("10.66.67.128/28")
    assert "nopool" in files[f"{render.OVPN_DIR}/udp.conf"][0]
    nft = files[render.NFT_CONF][0]
    assert 'oifname "vlan10" accept' in nft and "set vlan20_src" in nft
    assert s["clients"]["alice"]["wg"]["ip"] == "10.67.1.2"
    # Externer RADIUS-Server
    s["radius"].update(enabled=True, servers=[{"host": "192.168.1.10", "auth_port": 1812,
                                               "acct_port": 1813, "secret": "Geheim123!"}])
    rconf = render.render_radius(s)[render.RADIUSD_CONF][0]
    assert "proxy_requests = yes" in rconf and "secret = 'Geheim123!'" in rconf
    assert "Replicate-To-Realm" in rconf and "/^(alice|bob)$/" in rconf
    # Unbekannte VLAN-ID: Standardnetz statt Ablehnung
    s["radius"]["unknown_vlan"] = "default"
    assert "nicht eingerichtet" not in render.render_radius(s)[render.RADIUSD_CONF][0]
    # Ohne VLANs und RADIUS bleibt alles wie bisher
    s2 = st.default_state()
    st.ensure_server_keys(s2)
    st.new_client(s2, "dave", password="davepass1234")
    f2 = render.render_all(s2)
    assert "auth = eap-mschapv2" in f2[render.SWANCTL_CONF][0]
    assert "chap-secrets=" in f2[render.ACCEL_CONF][0] and "eap-radius" not in f2[render.STRONGSWAN_CONF][0]


def test_wg_routes_for_vlan_blocks(monkeypatch):
    """Peers mit VLAN-Adresse kommen per "wg syncconf" hinzu - die Route muss apply setzen."""
    from vpnserver import vlan
    s = st.default_state()
    s["vlans"]["20"] = vlan.validate(s, {"id": "20", "name": "IoT", "address": "192.168.20.2/24"})
    calls = []

    def fake_run(cmd, **_kw):
        calls.append(cmd)
        out = '[{"dst":"10.67.9.0/27","dev":"wg0","protocol":"static"}]' if "show" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(util, "DRYRUN", False)
    monkeypatch.setattr(util, "run", fake_run)
    vlan.sync_wg_routes(s)
    assert ["ip", "route", "replace", "10.67.1.0/27", "dev", "wg0", "proto", "static"] in calls
    assert ["ip", "route", "del", "10.67.9.0/27", "dev", "wg0", "proto", "static"] in calls


def test_vlan_validation():
    from vpnserver import vlan
    s = st.default_state()
    with pytest.raises(ValueError):
        vlan.validate(s, {"id": "5000", "address": "192.168.10.2/24"})
    with pytest.raises(ValueError):
        vlan.validate(s, {"id": "10", "address": "192.168.10.0/24"})
    with pytest.raises(ValueError):
        vlan.validate(s, {"id": "10", "address": "10.66.66.5/24"})  # VPN-Bereich
    with pytest.raises(ValueError):
        vlan.validate(s, {"id": "10", "address": "192.168.10.2/24", "vpn_net": "8.8.8.0/24"})
    for i in range(1, vlan.MAX_VLANS + 1):
        s["vlans"][str(i)] = vlan.validate(s, {"id": str(i), "address": f"192.168.{100 + i}.2/24"})
    with pytest.raises(ValueError):
        vlan.validate(s, {"id": "99", "address": "192.168.99.2/24"})
    assert vlan.ovpn_slice("10.66.67.0/24", 8) == __import__("ipaddress").ip_network("10.66.67.240/28")


def test_stats_collector_and_history(monkeypatch):
    import time as _t
    from vpnserver import stats, util as u
    u.remove_file(stats.HIST_FILE)
    u.remove_file(stats.EVENTS_FILE)
    col = stats.Collector()
    counters = iter([{"vpn_down": 1000, "vpn_up": 100, "vlan10_down": 0, "vlan10_up": 0},
                     {"vpn_down": 5000, "vpn_up": 600, "vlan10_down": 300, "vlan10_up": 30},
                     {"vpn_down": 200, "vpn_up": 50, "vlan10_down": 10, "vlan10_up": 1}])  # Firewall neu geladen
    monkeypatch.setattr(stats, "nft_counters", lambda: next(counters))
    col.tick_live()
    col.tick_live()
    col.tick_live()
    b = col.hist["buckets"][-1]
    assert b["down"] == 4000 + 200 and b["up"] == 500 + 50
    assert b["vlan"]["10"] == [310, 31]
    assert len(col.points) == 2 and col.points[0][1] > 0
    # Verbindungen: Zuwachs je Benutzer, Ereignisse
    from vpnserver import status
    sess = [{"user": "anna", "proto": "SSTP", "vip": "10.66.70.10", "sid": "ppp:1", "rx_bytes": 100, "tx_bytes": 1000}]
    monkeypatch.setattr(status, "all_sessions", lambda state: [dict(x) for x in sess])
    s = st.default_state()
    st.save(s)
    col.tick_sessions()
    sess[0].update(rx_bytes=300, tx_bytes=4000)
    col.tick_sessions()
    assert col.hist["buckets"][-1]["c"]["anna"] == [4000, 300]
    sess.clear()
    col.tick_sessions()
    ev = stats.events()
    assert ev[0]["type"] == "disconnect" and ev[0]["user"] == "anna" and ev[1]["type"] == "connect"
    col.flush()
    h = stats.history("24h")
    assert len(h["series"]) == 24 and h["series"][-1]["down"] == 4200
    assert h["clients"][0]["name"] == "anna" and h["vlans"]["10"]["down"] == 310
    d7 = stats.history("7d")
    assert len(d7["series"]) == 7 and d7["total"]["down"] == 4200
    assert stats.today_volume()["down"] == 4200
    del _t


def test_tools_validation():
    from vpnserver import tools
    for bad in ("", "a b", "1.2.3.4; rm -rf /", "$(id)", "-c1 x", "x" * 300):
        with pytest.raises(tools.ToolError):
            tools.ping(bad)
    assert tools.normalize_mac("00-11-22-AA-bb-CC") == "00:11:22:aa:bb:cc"
    assert tools.normalize_mac("001122aabbcc") == "00:11:22:aa:bb:cc"
    with pytest.raises(tools.ToolError):
        tools.normalize_mac("00:11:22:33:44")
    with pytest.raises(tools.ToolError):
        tools.capture("any", 1, "host 1.2.3.4 && reboot")
    with pytest.raises(tools.ToolError):
        tools.capture("eth99-gibts-nicht", 1, "")
    with pytest.raises(tools.ToolError):
        tools.dns("example.org", "PTR")


def test_updater_with_fake_github(tmp_path):
    import importlib.util
    from vpnserver import updater
    spec = importlib.util.spec_from_file_location(
        "fake_github", os.path.join(os.path.dirname(__file__), "e2e", "fake_github.py"))
    fg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fg)
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fake = fg.FakeGitHub(repo_dir, "9.9.9", token="testtoken_0123456789abcdef", release=True)
    srv = fake.serve(0, background=True)
    port = srv.server_address[1]
    s = st.default_state()
    u = updater.settings(s)
    u.update(api=f"http://127.0.0.1:{port}", repo="test/vpn-server", channel="branch", branch="main")
    # Privates Repository ohne Token
    with pytest.raises(updater.UpdateError, match="Token"):
        updater.check(s)
    u["token"] = "testtoken_0123456789abcdef"
    avail = updater.check(s)
    assert avail["version"] == "9.9.9" and avail["sha"] == fake.sha and avail["newer"]
    assert s["update"]["available"]["sha"] == fake.sha
    # Release-Kanal: Version vergleichen
    u["channel"] = "release"
    avail = updater.check(s)
    assert avail["ref"] == "v9.9.9" and avail["newer"]
    # Herunterladen, entpacken, pruefen
    root = updater._download(u, fake.sha, str(tmp_path / "new"))
    assert os.path.isfile(os.path.join(root, "installer", "install.sh"))
    updater._verify(root)
    with open(os.path.join(root, "vpnserver", "__init__.py")) as fh:
        assert '"9.9.9"' in fh.read()
    # Kaputter Stand wird abgelehnt
    with open(os.path.join(root, "vpnserver", "cli.py"), "a") as fh:
        fh.write("\ndef kaputt(:\n")
    with pytest.raises(updater.UpdateError, match="Syntax"):
        updater._verify(root)
    with pytest.raises(updater.UpdateError):
        updater.validate_settings("kein repo", "branch", "main")
    with pytest.raises(updater.UpdateError):
        updater.validate_settings("a/b", "branch", "main; rm -rf /")
    srv.shutdown()
