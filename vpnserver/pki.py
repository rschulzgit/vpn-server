"""Eigene Zertifizierungsstelle: CA, Server- und Client-Zertifikate, CRL, PKCS#12."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from . import util
from .util import P, PKI_DIR

IKE_INTERMEDIATE = ObjectIdentifier("1.3.6.1.5.5.8.2.2")

CA_KEY = PKI_DIR + "/ca.key"
CA_CRT = PKI_DIR + "/ca.crt"
SERVER_KEY = PKI_DIR + "/server.key"
SERVER_CRT = PKI_DIR + "/server.crt"
CRL = PKI_DIR + "/crl.pem"
CRL_DER = PKI_DIR + "/crl.der"
INDEX = PKI_DIR + "/index.json"
TLS_CRYPT = PKI_DIR + "/openvpn-tls-crypt.key"
CLIENT_DIR = PKI_DIR + "/clients"

SERVER_DAYS = 825          # Apple-Grenze fuer TLS-Serverzertifikate
SERVER_RENEW_DAYS = 60
CLIENT_DAYS = 3650
CA_DAYS = 7300


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _load_key(path: str):
    with open(P(path), "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _load_cert(path: str) -> x509.Certificate:
    with open(P(path), "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _new_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _not_after(cert: x509.Certificate) -> dt.datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------
# Index (Seriennummern, Sperrungen)
# --------------------------------------------------------------------------

def _load_index() -> dict:
    content = util.read_file(INDEX)
    if content:
        return json.loads(content)
    return {"issued": {}, "revoked": []}


def _save_index(idx: dict) -> None:
    util.write_file(INDEX, json.dumps(idx, indent=2) + "\n", mode=0o600)


# --------------------------------------------------------------------------
# CA
# --------------------------------------------------------------------------

def ca_exists() -> bool:
    return os.path.exists(P(CA_CRT)) and os.path.exists(P(CA_KEY))


def init_ca(common_name: str = "VPN-Server CA") -> None:
    if ca_exists():
        return
    os.makedirs(P(PKI_DIR), exist_ok=True)
    os.chmod(P(PKI_DIR), 0o711)
    key = _new_key(3072)
    # Eindeutiger Name je Installation, damit mehrere Server unterscheidbar sind.
    suffix = os.urandom(3).hex().upper()
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPN-Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name} {suffix}"),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    util.write_file(CA_KEY, _key_pem(key), mode=0o600)
    util.write_file(CA_CRT, _cert_pem(cert), mode=0o644)
    _save_index({"issued": {}, "revoked": []})


def ca_cert() -> x509.Certificate:
    return _load_cert(CA_CRT)


def ca_pem() -> str:
    return util.read_file(CA_CRT) or ""


def ca_der() -> bytes:
    return ca_cert().public_bytes(serialization.Encoding.DER)


def ca_common_name() -> str:
    return ca_cert().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _sign(builder: x509.CertificateBuilder) -> x509.Certificate:
    ca_key = _load_key(CA_KEY)
    ca = ca_cert()
    builder = builder.issuer_name(ca.subject).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


# --------------------------------------------------------------------------
# Serverzertifikat (IKEv2, OpenVPN, SSTP, OpenConnect, Weboberflaeche)
# --------------------------------------------------------------------------

def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    seen = set()
    for n in names:
        n = (n or "").strip()
        if not n or n.lower() in seen:
            continue
        seen.add(n.lower())
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def server_cert_names() -> list[str]:
    try:
        cert = _load_cert(SERVER_CRT)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (FileNotFoundError, x509.ExtensionNotFound):
        return []
    names = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    names += san.get_values_for_type(x509.DNSName)
    return names


def server_cert_needs_renewal(names: list[str]) -> bool:
    try:
        cert = _load_cert(SERVER_CRT)
    except FileNotFoundError:
        return True
    if _not_after(cert) - _now() < dt.timedelta(days=SERVER_RENEW_DAYS):
        return True
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn or cn[0].value != names[0][:64]:
        return True
    want = {_norm_name(n) for n in names if n and n.strip()}
    have = {_norm_name(h) for h in server_cert_names()}
    return want != have


def _norm_name(name: str) -> str:
    name = name.strip()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name.lower()


def issue_server_cert(names: list[str]) -> None:
    """Stellt das Serverzertifikat aus. Der Schluessel bleibt erhalten, damit
    Zertifikats-Pins (OpenConnect) gueltig bleiben."""
    if os.path.exists(P(SERVER_KEY)):
        key = _load_key(SERVER_KEY)
    else:
        key = _new_key(2048)
        util.write_file(SERVER_KEY, _key_pem(key), mode=0o600)
    cn = names[0][:64]
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPN-Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                              IKE_INTERMEDIATE]), critical=False)
        .add_extension(x509.SubjectAlternativeName(_san_entries(names)), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = _sign(builder)
    util.write_file(SERVER_CRT, _cert_pem(cert), mode=0o644)


def server_pin_sha256() -> str:
    """pin-sha256 fuer openconnect --servercert."""
    cert = _load_cert(SERVER_CRT)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return "pin-sha256:" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


def server_cert_info() -> dict:
    try:
        cert = _load_cert(SERVER_CRT)
    except FileNotFoundError:
        return {}
    return {
        "names": server_cert_names(),
        "not_after": _not_after(cert).strftime("%d.%m.%Y"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


# --------------------------------------------------------------------------
# Client-Zertifikate
# --------------------------------------------------------------------------

def client_paths(name: str) -> tuple[str, str]:
    return f"{CLIENT_DIR}/{name}.key", f"{CLIENT_DIR}/{name}.crt"


def issue_client_cert(name: str) -> str:
    key_path, crt_path = client_paths(name)
    key = _new_key(2048)
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPN-Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=CLIENT_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        # strongSwan gleicht die IKE-Identitaet (FQDN-Typ) mit dem SAN ab.
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    )
    cert = _sign(builder)
    os.makedirs(P(CLIENT_DIR), exist_ok=True)
    os.chmod(P(CLIENT_DIR), 0o700)
    util.write_file(key_path, _key_pem(key), mode=0o600)
    util.write_file(crt_path, _cert_pem(cert), mode=0o600)
    serial = format(cert.serial_number, "x")
    idx = _load_index()
    idx["issued"][serial] = {"name": name, "issued": now.isoformat(timespec="seconds")}
    _save_index(idx)
    return serial


def client_cert_exists(name: str) -> bool:
    key_path, crt_path = client_paths(name)
    return os.path.exists(P(key_path)) and os.path.exists(P(crt_path))


def revoke_client(name: str) -> None:
    """Sperrt alle Zertifikate eines Clients und loescht die Dateien."""
    idx = _load_index()
    now = _now().isoformat(timespec="seconds")
    revoked = {r["serial"] for r in idx["revoked"]}
    for serial, meta in idx["issued"].items():
        if meta.get("name") == name and serial not in revoked:
            idx["revoked"].append({"serial": serial, "date": now, "name": name})
    _save_index(idx)
    for path in client_paths(name):
        util.remove_file(path)
    write_crl()


def client_cert_pem(name: str) -> str:
    return util.read_file(client_paths(name)[1]) or ""


def client_key_pem(name: str) -> str:
    return util.read_file(client_paths(name)[0]) or ""


def client_p12(name: str, password: str, friendly: str | None = None) -> bytes:
    """PKCS#12 mit Legacy-Verschluesselung (3DES/SHA1), damit Android, iOS,
    macOS und Windows den Import zuverlaessig akzeptieren."""
    key_path, crt_path = client_paths(name)
    key = _load_key(key_path)
    cert = _load_cert(crt_path)
    try:
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
               .kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
               .hmac_hash(hashes.SHA1())
               .build(password.encode()))
    except AttributeError:  # sehr alte cryptography-Versionen
        enc = serialization.BestAvailableEncryption(password.encode())
    return pkcs12.serialize_key_and_certificates(
        (friendly or name).encode(), key, cert, [ca_cert()], enc)


# --------------------------------------------------------------------------
# CRL
# --------------------------------------------------------------------------

def write_crl() -> None:
    idx = _load_index()
    ca_key = _load_key(CA_KEY)
    ca = ca_cert()
    now = _now()
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca.subject)
               .last_update(now - dt.timedelta(minutes=5))
               .next_update(now + dt.timedelta(days=3650)))
    for entry in idx.get("revoked", []):
        try:
            revoked = (x509.RevokedCertificateBuilder()
                       .serial_number(int(entry["serial"], 16))
                       .revocation_date(dt.datetime.fromisoformat(entry["date"]))
                       .build())
        except (ValueError, KeyError):
            continue
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(ca_key, hashes.SHA256())
    util.write_file(CRL, crl.public_bytes(serialization.Encoding.PEM), mode=0o644)
    util.write_file(CRL_DER, crl.public_bytes(serialization.Encoding.DER), mode=0o644)


# --------------------------------------------------------------------------
# OpenVPN tls-crypt
# --------------------------------------------------------------------------

def ensure_tls_crypt() -> None:
    if os.path.exists(P(TLS_CRYPT)):
        return
    data = os.urandom(256).hex()
    lines = [data[i:i + 32] for i in range(0, len(data), 32)]
    content = ("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n"
               + "\n".join(lines) + "\n-----END OpenVPN Static key V1-----\n")
    util.write_file(TLS_CRYPT, content, mode=0o600)


def tls_crypt_key() -> str:
    return util.read_file(TLS_CRYPT) or ""


# --------------------------------------------------------------------------
# Externe (Let's Encrypt) Zertifikate fuer TLS-Dienste
# --------------------------------------------------------------------------

LE_LIVE = "/etc/letsencrypt/live/vpn-server"


def le_available() -> bool:
    return os.path.exists(P(LE_LIVE + "/fullchain.pem")) and os.path.exists(P(LE_LIVE + "/privkey.pem"))


def tls_cert_paths(state: dict) -> tuple[str, str]:
    """Zertifikat/Schluessel fuer TLS-Dienste (SSTP, OpenConnect, Weboberflaeche)."""
    if state.get("letsencrypt", {}).get("enabled") and le_available():
        return LE_LIVE + "/fullchain.pem", LE_LIVE + "/privkey.pem"
    return PKI_DIR + "/server-fullchain.pem", SERVER_KEY


def write_fullchain() -> None:
    chain = (util.read_file(SERVER_CRT) or "") + ca_pem()
    util.write_file(PKI_DIR + "/server-fullchain.pem", chain, mode=0o644)
