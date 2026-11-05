"""Status der Dienste und verbundenen Clients aller Protokolle."""

from __future__ import annotations

import json
import re
import time

from . import state as st, util

UNITS = [
    ("wireguard", "WireGuard", "wg-quick@wg0.service"),
    ("openvpn", "OpenVPN UDP", "openvpn-server@udp.service"),
    ("openvpn", "OpenVPN TCP", "openvpn-server@tcp.service"),
    ("ipsec", "strongSwan (IKEv2, IKEv1, L2TP-IPsec)", "strongswan.service"),
    ("ppp", "accel-ppp (L2TP, SSTP, PPTP)", "accel-ppp.service"),
    ("openconnect", "OpenConnect (ocserv)", "ocserv.service"),
    ("firewall", "Firewall (nftables)", "nftables.service"),
]


def _fmt_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n or "")
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def _ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"
    return f"{seconds // 86400} d {seconds % 86400 // 3600} h"


def unit_states(state: dict) -> list[dict]:
    want = {
        "wireguard": st.enabled(state, "wireguard"),
        "ipsec": st.any_ipsec(state),
        "ppp": st.any_ppp(state),
        "openconnect": st.enabled(state, "openconnect"),
        "firewall": True,
    }
    ov = state["proto"]["openvpn"]
    out = []
    for key, label, unit in UNITS:
        if key == "openvpn":
            wanted = st.enabled(state, "openvpn") and ov["udp" if "udp" in unit else "tcp"]
        else:
            wanted = want.get(key, False)
        if util.DRYRUN:
            active = "unbekannt"
        else:
            res = util.run(["systemctl", "is-active", unit])
            active = (res.stdout or "").strip() or "unbekannt"
        out.append({"label": label, "unit": unit, "wanted": wanted, "active": active,
                    "ok": (active == "active") == wanted})
    return out


# --------------------------------------------------------------------------
# Sitzungen je Protokoll
# --------------------------------------------------------------------------

def wireguard_sessions(state: dict) -> list[dict]:
    res = util.run(["wg", "show", "wg0", "dump"])
    if res.returncode != 0:
        return []
    by_key = {c["wg"]["pubkey"]: c["name"] for c in state["clients"].values()}
    now = time.time()
    out = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, _psk, endpoint, allowed, hs, rx, tx = parts[:7]
        hs = int(hs or 0)
        if not hs or now - hs > 180:
            continue
        out.append({"proto": "WireGuard", "user": by_key.get(pub, pub[:10] + "..."),
                    "remote": endpoint, "vip": allowed.split("/")[0],
                    "rx": _fmt_bytes(rx), "tx": _fmt_bytes(tx),
                    "since": f"Handshake vor {_ago(now - hs)}"})
    return out


def openvpn_sessions() -> list[dict]:
    out = []
    for inst in ("udp", "tcp"):
        content = util.read_file(f"/run/openvpn-server/status-{inst}.log")
        if not content:
            continue
        header = []
        for line in content.splitlines():
            parts = line.split(",")
            if parts[0] == "HEADER" and len(parts) > 1 and parts[1] == "CLIENT_LIST":
                header = parts[2:]
            elif parts[0] == "CLIENT_LIST" and header:
                row = dict(zip(header, parts[1:]))
                since = row.get("Connected Since (time_t)", "")
                out.append({"proto": f"OpenVPN {inst.upper()}",
                            "user": row.get("Common Name", ""),
                            "remote": row.get("Real Address", ""),
                            "vip": row.get("Virtual Address", ""),
                            "rx": _fmt_bytes(row.get("Bytes Received")),
                            "tx": _fmt_bytes(row.get("Bytes Sent")),
                            "since": _ago(time.time() - int(since)) if since.isdigit() else ""})
    return out


_SA_HEAD = re.compile(r"^(\S+): #(\d+), (\w+), (IKEv\d)")
_SA_REMOTE = re.compile(r"^\s+remote\s+'([^']*)' @ ([^\[\s]+)\[(\d+)\]"
                        r"(?: (?:EAP|XAuth): '([^']*)')?(?: \[([^\]]+)\])?")
_SA_BYTES = re.compile(r"^\s+(in|out)\s+\S+,\s+(\d+) bytes")
_SA_EST = re.compile(r"^\s+established (\d+)s ago")


def ipsec_sessions() -> list[dict]:
    res = util.run(["swanctl", "--list-sas"])
    if res.returncode != 0:
        return []
    out = []
    cur = None
    for line in res.stdout.splitlines():
        m = _SA_HEAD.match(line)
        if m:
            cur = {"conn": m.group(1), "id": int(m.group(2)), "state": m.group(3),
                   "version": m.group(4), "user": "", "remote": "", "vip": "",
                   "rx": 0, "tx": 0, "since": ""}
            out.append(cur)
            continue
        if cur is None:
            continue
        m = _SA_REMOTE.match(line)
        if m:
            remote_id, addr, port, aaa, vip = m.groups()
            cur["remote"] = f"{addr}:{port}"
            cur["vip"] = vip or ""
            user = aaa or remote_id
            cn = re.search(r"CN=([^,]+)", user)
            cur["user"] = cn.group(1) if cn else user
            if cur["conn"].startswith("ikev2-psk-"):
                cur["user"] = cur["conn"][len("ikev2-psk-"):]
            continue
        m = _SA_BYTES.match(line)
        if m:
            cur["rx" if m.group(1) == "in" else "tx"] += int(m.group(2))
            continue
        m = _SA_EST.match(line)
        if m:
            cur["since"] = _ago(int(m.group(1)))
    return out


_CONN_LABEL = {
    "ikev2-cert": "IKEv2 (Zertifikat)",
    "ikev2-eap": "IKEv2 (Benutzername)",
    "ikev1-xauth": "Cisco IPsec (XAuth)",
    "l2tp-psk": "L2TP-IPsec-Transport",
}


def ipsec_display(sessions: list[dict]) -> list[dict]:
    out = []
    for sa in sessions:
        if sa["conn"] == "l2tp-psk":
            continue  # wird ueber accel-ppp als L2TP-Sitzung angezeigt
        label = _CONN_LABEL.get(sa["conn"], "IKEv2 (PSK)" if sa["conn"].startswith("ikev2-psk-")
                                else sa["conn"])
        out.append({"proto": label, "user": sa["user"], "remote": sa["remote"],
                    "vip": sa["vip"], "rx": _fmt_bytes(sa["rx"]), "tx": _fmt_bytes(sa["tx"]),
                    "since": sa["since"]})
    return out


def ppp_sessions() -> list[dict]:
    cols = "ifname,username,ip,type,state,uptime,rx-bytes,tx-bytes,calling-sid"
    res = util.run(["accel-cmd", "show", "sessions", cols])
    if res.returncode != 0:
        return []
    out = []
    lines = [l for l in res.stdout.splitlines() if "|" in l]
    if not lines:
        return []
    header = [h.strip() for h in lines[0].split("|")]
    for line in lines[1:]:
        row = dict(zip(header, [v.strip() for v in line.split("|")]))
        ifname = row.get("ifname", "")
        proto = row.get("type", "") or re.sub(r"\d+$", "", ifname)
        out.append({"proto": proto.upper() or "PPP", "user": row.get("username", ""),
                    "remote": row.get("calling-sid", ""), "vip": row.get("ip", ""),
                    "rx": row.get("rx-bytes", ""), "tx": row.get("tx-bytes", ""),
                    "since": row.get("uptime", "")})
    return out


def openconnect_sessions() -> list[dict]:
    res = util.run(["occtl", "--json", "show", "users"])
    if res.returncode != 0 or not res.stdout.strip():
        return []
    try:
        users = json.loads(res.stdout)
    except ValueError:
        return []
    out = []
    for u in users:
        out.append({"proto": "OpenConnect", "user": u.get("Username", ""),
                    "remote": u.get("Remote IP", ""), "vip": u.get("IPv4", ""),
                    "rx": u.get("RX", ""), "tx": u.get("TX", ""),
                    "since": u.get("_Connected at", u.get("Connected at", ""))})
    return out


def all_sessions(state: dict) -> list[dict]:
    if util.DRYRUN:
        return []
    sessions = []
    sessions += wireguard_sessions(state)
    sessions += openvpn_sessions()
    sessions += ipsec_display(ipsec_sessions())
    sessions += ppp_sessions()
    sessions += openconnect_sessions()
    return sessions
