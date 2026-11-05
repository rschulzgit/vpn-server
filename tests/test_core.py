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
    tmp = st.default_state()
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
    assert "dynamic[udp]" in conf
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
