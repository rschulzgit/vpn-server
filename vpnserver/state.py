"""Persistenter Zustand (Einstellungen + Clients) in /etc/vpn-server/state.json."""

from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import util
from .util import P

SCHEMA = 1

PROTOCOLS = ["wireguard", "openvpn", "ikev2", "ikev1_xauth", "l2tp", "sstp",
             "openconnect", "pptp"]

PROTOCOL_LABELS = {
    "wireguard": "WireGuard",
    "openvpn": "OpenVPN",
    "ikev2": "IKEv2/IPsec",
    "ikev1_xauth": "Cisco IPsec (IKEv1 XAuth)",
    "l2tp": "L2TP/IPsec",
    "sstp": "SSTP",
    "openconnect": "OpenConnect / Cisco AnyConnect",
    "pptp": "PPTP (unsicher)",
}


def default_state() -> dict:
    return {
        "schema": SCHEMA,
        "admin": {
            "username": "admin",
            "password_hash": "",
            "initial_password": "",
            "must_change": True,
        },
        "secret_key": secrets.token_hex(32),
        "server": {
            "public_host": "",
            "dns": [],
            "lan_access": True,
            "client_to_client": False,
            "webui_port": 8443,
            "webui_public": False,
            "ssh_public": False,
            "setup_done": False,
            "name": "VPN-Server",
        },
        "ddns": {
            "provider": "none",
            "url": "",
            "domain": "",
            "token": "",
            "username": "",
            "password": "",
            "last_ip": "",
            "last_update": "",
            "last_result": "",
        },
        "letsencrypt": {
            "enabled": False,
            "email": "",
            "status": "",
        },
        "proto": {
            "wireguard": {"enabled": True, "port": 51820, "subnet": "10.66.66.0/24",
                          "privkey": "", "pubkey": "", "keepalive": 25, "mtu": 0},
            "openvpn": {"enabled": True, "udp": True, "tcp": True,
                        "udp_port": 1194, "tcp_port": 1194,
                        "udp_subnet": "10.66.67.0/24", "tcp_subnet": "10.66.68.0/24"},
            "ikev2": {"enabled": True, "subnet": "10.66.69.0/24"},
            "ikev1_xauth": {"enabled": True},
            "l2tp": {"enabled": True},
            "ipsec_psk": util.gen_password(24),
            "sstp": {"enabled": True, "port": 443},
            "pptp": {"enabled": False},
            "ppp": {"subnet": "10.66.70.0/24"},
            "openconnect": {"enabled": True, "port": 4443, "subnet": "10.66.71.0/24"},
        },
        "clients": {},
        "shares": {},
    }


def _merge_defaults(state: dict, defaults: dict) -> dict:
    """Ergaenzt fehlende Schlüssel (z. B. nach einem Update) rekursiv."""
    for key, value in defaults.items():
        if key not in state:
            state[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(state[key], dict) and key not in ("clients", "shares"):
            _merge_defaults(state[key], value)
    return state


# --------------------------------------------------------------------------
# Laden / Speichern mit Sperre
# --------------------------------------------------------------------------

_thread_lock = threading.RLock()


@contextlib.contextmanager
def locked():
    """Exklusive Sperre für Lese-Änderungs-Schreib-Zyklen (Threads + Prozesse)."""
    with _thread_lock:
        lockfile = P(util.ETC + "/.lock")
        os.makedirs(os.path.dirname(lockfile), exist_ok=True)
        with open(lockfile, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)


def exists() -> bool:
    return os.path.exists(P(util.STATE_FILE))


def load() -> dict:
    content = util.read_file(util.STATE_FILE)
    if content is None:
        raise FileNotFoundError(util.STATE_FILE)
    state = json.loads(content)
    return _merge_defaults(state, default_state())


def save(state: dict) -> None:
    util.write_file(util.STATE_FILE, json.dumps(state, indent=2, sort_keys=False) + "\n",
                    mode=0o600)


# --------------------------------------------------------------------------
# Admin-Passwort
# --------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    n, r, p = 2 ** 14, 8, 1
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n, r, p, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                              n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# WireGuard-Schluessel
# --------------------------------------------------------------------------

def wg_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def wg_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def ensure_server_keys(state: dict) -> None:
    wg = state["proto"]["wireguard"]
    if not wg.get("privkey"):
        wg["privkey"], wg["pubkey"] = wg_keypair()
    if not state["proto"].get("ipsec_psk"):
        state["proto"]["ipsec_psk"] = util.gen_password(24)


# --------------------------------------------------------------------------
# Clients
# --------------------------------------------------------------------------

def _wg_allocate_ip(state: dict) -> str:
    net = ipaddress.ip_network(state["proto"]["wireguard"]["subnet"])
    used = {c["wg"]["ip"] for c in state["clients"].values() if c.get("wg", {}).get("ip")}
    hosts = list(net.hosts())
    for host in hosts[1:]:  # .1 ist der Server
        if str(host) not in used:
            return str(host)
    raise ValueError("Keine freie WireGuard-Adresse mehr im Subnetz.")


def wg_server_ip(state: dict) -> str:
    net = ipaddress.ip_network(state["proto"]["wireguard"]["subnet"])
    return str(next(net.hosts()))


def renumber_wireguard(state: dict) -> None:
    """Vergibt alle WireGuard-Adressen neu (nach Änderung des Subnetzes)."""
    for client in state["clients"].values():
        client["wg"]["ip"] = ""
    for client in state["clients"].values():
        client["wg"]["ip"] = _wg_allocate_ip(state)


def new_client(state: dict, name: str, password: str | None = None, note: str = "",
               full_tunnel: bool = True) -> dict:
    if not util.valid_client_name(name):
        raise ValueError("Ungültiger Name: erlaubt sind a-z, 0-9 und '-' (max. 31 Zeichen), "
                         "beginnend mit Buchstabe oder Ziffer.")
    if name in state["clients"]:
        raise ValueError(f"Ein Client mit dem Namen '{name}' existiert bereits.")
    if password is not None and password != "" and not util.valid_password(password):
        raise ValueError("Ungültiges Passwort (8-64 Zeichen; erlaubt: A-Z a-z 0-9 - _ . : ! + = @ % ^ * ? , / ~).")
    priv, pub = wg_keypair()
    client = {
        "name": name,
        "note": note,
        "enabled": True,
        "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "password": password or util.gen_password(16),
        "full_tunnel": bool(full_tunnel),
        "wg": {"privkey": priv, "pubkey": pub, "psk": wg_psk(), "ip": ""},
        "psk_id": name,
        "psk": util.gen_password(24),
        "p12_password": util.gen_password(12),
        "cert_serial": "",
    }
    state["clients"][name] = client
    client["wg"]["ip"] = _wg_allocate_ip(state)
    return client


def active_clients(state: dict) -> list[dict]:
    return [c for c in state["clients"].values() if c.get("enabled", True)]


def enabled(state: dict, proto: str) -> bool:
    return bool(state["proto"].get(proto, {}).get("enabled"))


def any_ipsec(state: dict) -> bool:
    return any(enabled(state, p) for p in ("ikev2", "ikev1_xauth", "l2tp"))


def any_ppp(state: dict) -> bool:
    return any(enabled(state, p) for p in ("l2tp", "sstp", "pptp"))


def public_host(state: dict) -> str:
    """Öffentliche Adresse für Client-Profile (Fallback: LAN-IP)."""
    host = state["server"].get("public_host", "").strip()
    if host:
        return host
    return util.default_route_info().get("ip") or "127.0.0.1"


def vpn_subnets(state: dict) -> list[str]:
    pr = state["proto"]
    return [pr["wireguard"]["subnet"], pr["openvpn"]["udp_subnet"],
            pr["openvpn"]["tcp_subnet"], pr["ikev2"]["subnet"], pr["ppp"]["subnet"],
            pr["openconnect"]["subnet"]]


def dns_servers(state: dict) -> list[str]:
    dns = [d for d in state["server"].get("dns", []) if d]
    if dns:
        return dns
    return ["1.1.1.1", "9.9.9.9"]
