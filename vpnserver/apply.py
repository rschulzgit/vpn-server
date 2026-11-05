"""Wendet den Zustand an: PKI pflegen, Dateien schreiben, Dienste (neu) starten."""

from __future__ import annotations

import hashlib
import os
import socket
import time

from . import pki, render, state as st, util
from .util import P, log

WEBUI_UNIT = "vpn-webui.service"


def _hash_files(paths: list[str]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update((util.read_file(p) or "").encode())
    return h.hexdigest()


def ensure_pki(state: dict) -> None:
    """CA, Serverzertifikat, Client-Zertifikate und CRL sicherstellen."""
    pki.init_ca()
    names = render.server_cert_names(state)
    if pki.server_cert_needs_renewal(names):
        log.info("Stelle Serverzertifikat aus fuer: %s", ", ".join(names))
        pki.issue_server_cert(names)
    pki.write_fullchain()
    pki.ensure_tls_crypt()
    for client in st.active_clients(state):
        if not pki.client_cert_exists(client["name"]):
            client["cert_serial"] = pki.issue_client_cert(client["name"])
    if not os.path.exists(P(pki.CRL)):
        pki.write_crl()


# --------------------------------------------------------------------------
# systemd-Hilfen
# --------------------------------------------------------------------------

def systemctl(*args: str) -> bool:
    if util.DRYRUN:
        return True
    return util.run(["systemctl", *args], timeout=90).returncode == 0


def is_active(unit: str) -> bool:
    if util.DRYRUN:
        return False
    return util.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


# Waehrend des Bootvorgangs (Erststart-Dienst) nicht auf Start-Jobs warten,
# sonst drohen Verklemmungen mit der systemd-Boot-Transaktion.
NO_BLOCK = os.environ.get("VPNSERVER_NO_BLOCK", "") == "1"


def ensure_unit(unit: str, want: bool, restart: bool = False, reload: bool = False) -> None:
    nb = ["--no-block"] if NO_BLOCK else []
    if want:
        if not is_active(unit):
            systemctl("enable", unit)
            systemctl(*nb, "restart", unit)
        elif restart:
            systemctl(*nb, "restart", unit)
        elif reload:
            systemctl(*nb, "reload", unit)
        systemctl("enable", unit)
    else:
        if is_active(unit):
            systemctl("stop", unit)
        systemctl("disable", unit)


def _swanctl_load() -> None:
    for _ in range(20):
        if util.run(["swanctl", "--load-all", "--clear"]).returncode == 0:
            return
        time.sleep(0.5)
    log.error("swanctl --load-all fehlgeschlagen")


# --------------------------------------------------------------------------
# Anwenden
# --------------------------------------------------------------------------

def apply(state: dict, restart_webui: bool = True) -> list[str]:
    """Schreibt alle Konfigurationen und gleicht die Dienste ab.
    Der Aufrufer muss den Zustand danach speichern (Seriennummern etc.)."""
    st.ensure_server_keys(state)
    tls_before = _hash_files(list(pki.tls_cert_paths(state)))
    srv_before = _hash_files([pki.SERVER_CRT, pki.SERVER_KEY])
    ensure_pki(state)
    tls_changed = _hash_files(list(pki.tls_cert_paths(state))) != tls_before
    srv_changed = _hash_files([pki.SERVER_CRT, pki.SERVER_KEY]) != srv_before

    files = render.render_all(state)
    changed = set()
    for path, (content, mode) in files.items():
        if util.write_file(path, content, mode):
            changed.add(path)
    messages = [f"geaendert: {p}" for p in sorted(changed)]
    if util.DRYRUN:
        return messages

    # System (Module vor sysctl, z. B. tcp_bbr)
    if render.MODULES_CONF in changed:
        for line in (util.read_file(render.MODULES_CONF) or "").splitlines():
            mod = line.strip()
            if mod and not mod.startswith("#"):
                util.run(["modprobe", mod])
    if render.SYSCTL_CONF in changed:
        util.run(["sysctl", "-p", render.SYSCTL_CONF])

    # Firewall
    if render.NFT_CONF in changed or not is_active("nftables.service"):
        if util.run(["nft", "-f", render.NFT_CONF]).returncode != 0:
            messages.append("FEHLER: Firewall-Regeln konnten nicht geladen werden")
        systemctl("enable", "nftables.service")
        if not is_active("nftables.service"):
            systemctl("start", "nftables.service")

    # WireGuard
    wg_on = st.enabled(state, "wireguard")
    unit = "wg-quick@wg0.service"
    if wg_on:
        iface = (util.read_file(render.WG_CONF) or "").split("[Peer]")[0]
        iface_hash = hashlib.sha256(iface.encode()).hexdigest()
        hash_file = util.RUN_DIR + "/wg-iface.hash"
        old_hash = util.read_file(hash_file)
        if not is_active(unit) or (old_hash is not None and old_hash != iface_hash):
            ensure_unit(unit, True, restart=True)
        elif render.WG_CONF in changed:
            res = util.run(["bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)"])
            if res.returncode != 0:
                ensure_unit(unit, True, restart=True)
        util.write_file(hash_file, iface_hash, mode=0o600)
    else:
        ensure_unit(unit, False)

    # OpenVPN
    ov = state["proto"]["openvpn"]
    for name in ("udp", "tcp"):
        want = st.enabled(state, "openvpn") and ov[name]
        conf_changed = f"{render.OVPN_DIR}/{name}.conf" in changed
        ensure_unit(f"openvpn-server@{name}.service", want, restart=conf_changed or srv_changed)

    # strongSwan
    if st.any_ipsec(state):
        ensure_unit("strongswan.service", True)
        if not NO_BLOCK:  # sonst laedt strongswan.service die Konfiguration selbst
            _swanctl_load()
    else:
        ensure_unit("strongswan.service", False)

    # accel-ppp (L2TP, SSTP, PPTP)
    if st.any_ppp(state):
        ensure_unit("accel-ppp.service", True,
                    restart=render.ACCEL_CONF in changed or tls_changed,
                    reload=render.CHAP_SECRETS in changed)
    else:
        ensure_unit("accel-ppp.service", False)

    # OpenConnect (ocpasswd wird bei jeder Anmeldung neu gelesen)
    ensure_unit("ocserv.service", st.enabled(state, "openconnect"),
                restart=render.OCSERV_CONF in changed or tls_changed)

    # Weboberflaeche neu laden, wenn sich das TLS-Zertifikat geaendert hat
    if tls_changed and restart_webui:
        util.run(["systemd-run", "--on-active=2", "--unit=vpn-webui-reload",
                  "--collect", "systemctl", "restart", WEBUI_UNIT])
    return messages


# --------------------------------------------------------------------------
# Sitzungen eines Clients trennen (nach Sperren/Loeschen)
# --------------------------------------------------------------------------

def _openvpn_mgmt(name: str, command: str) -> str:
    path = f"/run/openvpn-server/mgmt-{name}.sock"
    if not os.path.exists(path):
        return ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(path)
            s.recv(4096)
            s.sendall((command + "\nquit\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode(errors="replace")
    except OSError:
        return ""


def disconnect_client(name: str) -> None:
    if util.DRYRUN:
        return
    for inst in ("udp", "tcp"):
        _openvpn_mgmt(inst, f"kill {name}")
    util.run(["accel-cmd", "terminate", "username", name, "hard"])
    util.run(["occtl", "disconnect", "user", name])
    util.run(["swanctl", "--terminate", "--ike", f"ikev2-psk-{name}", "--force"])
    from .status import ipsec_sessions
    for sa in ipsec_sessions():
        if sa.get("user") == name and sa.get("id"):
            util.run(["swanctl", "--terminate", "--ike-id", str(sa["id"]), "--force"])
