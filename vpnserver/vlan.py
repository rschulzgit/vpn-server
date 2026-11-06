"""VLANs und RADIUS: Adressplan, VLAN-Schnittstellen und Policy-Routing.

Jedes VLAN erhaelt einen eigenen VPN-Adressbereich (Standard 10.67.<slot>.0/24),
der pro Protokoll in /27-Bloecke aufgeteilt wird:

    .0/27   WireGuard (feste Adressen je Geraet)
    .32/27  IPsec (IKEv2, Cisco IPsec)
    .64/27  PPP (L2TP, SSTP, PPTP)
    .96/27  OpenConnect

OpenVPN (topology subnet) verlangt Adressen aus dem eigenen Tunnelnetz: dort
dient die untere Haelfte als dynamischer Standardbereich, die obere Haelfte
wird in 8 Bloecke (je VLAN-Slot einer) aufgeteilt.

Verkehr aus den Bereichen eines VLANs wird per Policy-Routing ueber die
VLAN-Schnittstelle (802.1Q) geleitet und dort maskiert (NAT). Die Firewall
laesst ihn nur dorthin.
"""

from __future__ import annotations

import ipaddress
import json
import re

from . import util
from .util import log

MAX_VLANS = 8
IFALIAS = "vpn-server"
RULE_PRIO_MAIN = 9000      # "to <VPN-Netze> lookup main"
RULE_PRIO_BASE = 9010      # 9010 + slot: "from <VLAN-Quellen> lookup <Tabelle>"
TABLE_BASE = 1000          # Routing-Tabelle 1000 + slot

PROTO_SLICE = {"wireguard": 0, "ipsec": 1, "ppp": 2, "openconnect": 3}

NAME_RE = re.compile(r"^[\w .()+-]{1,32}$", re.UNICODE)


# --------------------------------------------------------------------------
# Zustand
# --------------------------------------------------------------------------

def vlans(state: dict) -> list[dict]:
    return sorted(state.get("vlans", {}).values(), key=lambda v: v["slot"])


def get(state: dict, vid) -> dict | None:
    if vid in (None, "", 0, "0"):
        return None
    return state.get("vlans", {}).get(str(vid))


def radius_mode(state: dict) -> bool:
    """Anmeldung mit Benutzername/Passwort ueber den lokalen RADIUS-Dienst
    (noetig fuer einen externen RADIUS-Server und fuer die VLAN-Zuordnung)."""
    return bool(state.get("radius", {}).get("enabled") or state.get("vlans"))


def client_vlan(state: dict, client: dict) -> dict | None:
    return get(state, client.get("vlan", ""))


def ifname(v: dict) -> str:
    return f"vlan{v['id']}"


def table(v: dict) -> int:
    return TABLE_BASE + int(v["slot"])


def free_slot(state: dict) -> int:
    used = {int(v["slot"]) for v in state.get("vlans", {}).values()}
    for slot in range(1, MAX_VLANS + 1):
        if slot not in used:
            return slot
    raise ValueError(f"Es sind höchstens {MAX_VLANS} VLANs möglich.")


def default_vpn_net(slot: int) -> str:
    return f"10.67.{slot}.0/24"


# --------------------------------------------------------------------------
# Adressplan
# --------------------------------------------------------------------------

def vpn_net(v: dict) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(v["vpn_net"])


def proto_net(v: dict, proto: str) -> ipaddress.IPv4Network:
    net = vpn_net(v)
    return list(net.subnets(new_prefix=net.prefixlen + 3))[PROTO_SLICE[proto]]


def proto_range(v: dict, proto: str) -> tuple[str, str]:
    """Erste/letzte Clientadresse eines Protokollblocks (erste Adresse bleibt frei)."""
    hosts = list(proto_net(v, proto).hosts())
    return str(hosts[1]), str(hosts[-1])


def ovpn_default_pool(subnet: str) -> tuple[str, str]:
    net = ipaddress.ip_network(subnet)
    lower = list(net.subnets(new_prefix=net.prefixlen + 1))[0]
    hosts = list(lower.hosts())
    return str(hosts[1]), str(hosts[-1])  # .1 = Server


def ovpn_slice(subnet: str, slot: int) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(subnet)
    upper = list(net.subnets(new_prefix=net.prefixlen + 1))[1]
    return list(upper.subnets(new_prefix=net.prefixlen + 4))[slot - 1]


def sources(state: dict, v: dict) -> list[str]:
    """Alle VPN-Adressbereiche, deren Verkehr in dieses VLAN gehoert."""
    ov = state["proto"]["openvpn"]
    return [str(vpn_net(v)), str(ovpn_slice(ov["udp_subnet"], v["slot"])),
            str(ovpn_slice(ov["tcp_subnet"], v["slot"]))]


def all_vpn_nets(state: dict) -> list[str]:
    from .state import vpn_subnets
    return list(vpn_subnets(state)) + [str(vpn_net(v)) for v in vlans(state)]


def vlan_dns(state: dict, v: dict | None) -> list[str]:
    from .state import dns_servers
    if v and v.get("dns"):
        return list(v["dns"])
    return dns_servers(state)


def vlan_clients(state: dict, v: dict) -> list[dict]:
    from .state import active_clients
    return sorted((c for c in active_clients(state) if str(c.get("vlan", "")) == str(v["id"])),
                  key=lambda c: c["name"])


def ovpn_client_ips(state: dict, inst: str) -> dict[str, str]:
    """Feste OpenVPN-Adressen fuer Clients in VLANs (Name -> IP)."""
    subnet = state["proto"]["openvpn"][f"{inst}_subnet"]
    out = {}
    for v in vlans(state):
        hosts = list(ovpn_slice(subnet, v["slot"]).hosts())
        for c, ip in zip(vlan_clients(state, v), hosts):
            out[c["name"]] = str(ip)
    return out


def ovpn_capacity(state: dict) -> int:
    subnet = state["proto"]["openvpn"]["udp_subnet"]
    return len(list(ovpn_slice(subnet, 1).hosts()))


def wg_capacity(v: dict) -> int:
    return len(list(proto_net(v, "wireguard").hosts())) - 1


def vlan_of_ip(state: dict, ip: str) -> dict | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for v in vlans(state):
        if any(addr in ipaddress.ip_network(n) for n in sources(state, v)):
            return v
    return None


# --------------------------------------------------------------------------
# Pruefung
# --------------------------------------------------------------------------

def validate(state: dict, data: dict, old_id: str | None = None) -> dict:
    """Prueft und normalisiert eine VLAN-Definition aus dem Formular."""
    try:
        vid = int(str(data.get("id", "")).strip())
    except ValueError:
        raise ValueError("Die VLAN-ID muss eine Zahl zwischen 1 und 4094 sein.") from None
    if not 1 <= vid <= 4094:
        raise ValueError("Die VLAN-ID muss zwischen 1 und 4094 liegen.")
    if str(vid) != str(old_id or "") and str(vid) in state.get("vlans", {}):
        raise ValueError(f"VLAN {vid} ist bereits eingerichtet.")
    name = str(data.get("name", "")).strip() or f"VLAN {vid}"
    if not NAME_RE.match(name):
        raise ValueError("Ungültiger Name (max. 32 Zeichen: Buchstaben, Ziffern, Leerzeichen, . ( ) + - _).")
    parent = str(data.get("parent", "")).strip()
    if parent and not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", parent):
        raise ValueError("Ungültiger Schnittstellenname.")
    try:
        iface = ipaddress.ip_interface(str(data.get("address", "")).strip())
    except ValueError:
        raise ValueError("Ungültige Server-Adresse im VLAN (Format 192.168.10.2/24).") from None
    if iface.version != 4 or iface.network.prefixlen > 30 or iface.network.prefixlen < 8 \
            or iface.ip in (iface.network.network_address, iface.network.broadcast_address):
        raise ValueError("Ungültige Server-Adresse im VLAN (IPv4 mit Präfix, z. B. 192.168.10.2/24).")
    gateway = str(data.get("gateway", "")).strip()
    if gateway:
        try:
            gw = ipaddress.ip_address(gateway)
        except ValueError:
            raise ValueError("Ungültiges Gateway.") from None
        if gw not in iface.network or gw == iface.ip:
            raise ValueError("Das Gateway muss im VLAN-Netz liegen.")
    dns = [d.strip() for d in str(data.get("dns", "")).replace(";", ",").split(",") if d.strip()]
    for d in dns:
        if not util.is_ip(d):
            raise ValueError(f"Ungültiger DNS-Server: {d}")
    old = state.get("vlans", {}).get(str(old_id)) if old_id else None
    slot = old["slot"] if old else free_slot(state)
    vnet = str(data.get("vpn_net", "")).strip() or (old["vpn_net"] if old else default_vpn_net(slot))
    try:
        net = ipaddress.ip_network(vnet)
    except ValueError:
        raise ValueError(f"Ungültiger VPN-Adressbereich: {vnet}") from None
    if net.version != 4 or not 16 <= net.prefixlen <= 24 or not net.is_private:
        raise ValueError("Der VPN-Adressbereich muss ein privates IPv4-Netz von /16 bis /24 sein.")
    v = {"id": vid, "name": name, "parent": parent, "address": str(iface), "gateway": gateway,
         "dns": dns, "slot": slot, "vpn_net": str(net)}
    # Ueberschneidungen pruefen
    from .state import vpn_subnets
    others = [ipaddress.ip_network(n) for n in vpn_subnets(state)]
    others += [vpn_net(o) for o in vlans(state) if str(o["id"]) != str(old_id or "")]
    for o in others:
        if net.overlaps(o):
            raise ValueError(f"Der VPN-Adressbereich {net} überschneidet sich mit {o}.")
        if iface.network.overlaps(o):
            raise ValueError(f"Das VLAN-Netz {iface.network} überschneidet sich mit dem VPN-Bereich {o}.")
    for o in vlans(state):
        if str(o["id"]) == str(old_id or ""):
            continue
        if ipaddress.ip_interface(o["address"]).network.overlaps(iface.network):
            raise ValueError(f"Das VLAN-Netz {iface.network} überschneidet sich mit VLAN {o['id']}.")
    lan = util.default_route_info()
    if lan.get("ip") and lan.get("prefixlen"):
        lan_net = ipaddress.ip_interface(f"{lan['ip']}/{lan['prefixlen']}").network
        if lan_net.overlaps(iface.network) and (parent or lan.get("dev")) == lan.get("dev"):
            raise ValueError(f"Das VLAN-Netz {iface.network} überschneidet sich mit dem Heimnetz {lan_net}.")
    return v


# --------------------------------------------------------------------------
# Netzwerk anwenden (802.1Q-Schnittstellen, Routing-Tabellen, Regeln)
# --------------------------------------------------------------------------

def physical_interfaces() -> list[str]:
    res = util.run(["ip", "-j", "link", "show"])
    try:
        links = json.loads(res.stdout or "[]")
    except ValueError:
        return []
    out = []
    for link in links:
        name = link.get("ifname", "")
        if link.get("link_type") != "ether" or "@" in name:
            continue
        if re.match(r"^(lo|wg|ovpn|vpns|ppp|l2tp|sstp|pptp|vlan|docker|veth|br-|virbr|tun|tap)", name):
            continue
        out.append(name)
    return out


def parent_of(v: dict) -> str:
    return v.get("parent") or util.default_route_info().get("dev") or "eth0"


def _our_links() -> dict[str, dict]:
    res = util.run(["ip", "-d", "-j", "link", "show", "type", "vlan"])
    try:
        links = json.loads(res.stdout or "[]")
    except ValueError:
        return {}
    out = {}
    for link in links:
        if link.get("ifalias") != IFALIAS:
            continue
        data = (link.get("linkinfo") or {}).get("info_data") or {}
        out[link["ifname"]] = {"parent": link.get("link", ""), "id": data.get("id")}
    return out


def _ip(*args: str) -> bool:
    res = util.run(["ip", *args])
    if res.returncode != 0:
        log.warning("ip %s: %s", " ".join(args), (res.stderr or "").strip())
    return res.returncode == 0


def apply_network(state: dict) -> list[str]:
    """Gleicht VLAN-Schnittstellen, Routing-Tabellen und Regeln ab (idempotent)."""
    if util.DRYRUN:
        return []
    msgs = []
    want = {ifname(v): v for v in vlans(state)}
    have = _our_links()
    for name in set(have) - set(want):
        _ip("link", "del", name)
        msgs.append(f"VLAN-Schnittstelle {name} entfernt")
    for name, v in want.items():
        parent = parent_of(v)
        cur = have.get(name)
        if cur and (cur["parent"] != parent or str(cur["id"]) != str(v["id"])):
            _ip("link", "del", name)
            cur = None
        if not cur:
            util.run(["ip", "link", "del", name])  # fremde Reste
            if not _ip("link", "add", "link", parent, "name", name, "type", "vlan", "id", str(v["id"])):
                msgs.append(f"FEHLER: VLAN {v['id']} auf {parent} konnte nicht angelegt werden")
                continue
            _ip("link", "set", name, "alias", IFALIAS)
            msgs.append(f"VLAN-Schnittstelle {name} auf {parent} angelegt")
        util.run(["sysctl", "-q", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"])
        _ip("link", "set", parent, "up")
        res = util.run(["ip", "-j", "-4", "addr", "show", "dev", name])
        try:
            addrs = {f"{a['local']}/{a['prefixlen']}" for i in json.loads(res.stdout or "[]")
                     for a in i.get("addr_info", [])}
        except (ValueError, KeyError):
            addrs = set()
        if addrs != {v["address"]}:
            _ip("addr", "flush", "dev", name)
            _ip("addr", "add", v["address"], "dev", name)
        _ip("link", "set", name, "up")
        iface = ipaddress.ip_interface(v["address"])
        t = str(table(v))
        _ip("route", "flush", "table", t)
        _ip("route", "add", str(iface.network), "dev", name, "src", str(iface.ip), "table", t)
        if v.get("gateway"):
            _ip("route", "add", "default", "via", v["gateway"], "dev", name, "table", t)
        else:
            # Ohne Gateway nur das VLAN-Netz: alles andere verwerfen statt ueber die
            # Hauptroute ins Heimnetz/Internet zu gelangen
            _ip("route", "add", "unreachable", "default", "table", t)
    # Regeln neu setzen
    res = util.run(["ip", "-j", "-4", "rule", "show"])
    try:
        rules = json.loads(res.stdout or "[]")
    except ValueError:
        rules = []
    for r in rules:
        prio = r.get("priority", 0)
        if RULE_PRIO_MAIN <= prio < RULE_PRIO_BASE + 100:
            util.run(["ip", "rule", "del", "priority", str(prio)])
    if want:
        for net in all_vpn_nets(state):
            _ip("rule", "add", "to", net, "lookup", "main", "priority", str(RULE_PRIO_MAIN))
        for v in want.values():
            for src in sources(state, v):
                _ip("rule", "add", "from", src, "lookup", str(table(v)),
                    "priority", str(RULE_PRIO_BASE + int(v["slot"])))
    # Nicht mehr benoetigte Tabellen leeren
    used = {table(v) for v in want.values()}
    for slot in range(1, MAX_VLANS + 1):
        if TABLE_BASE + slot not in used:
            util.run(["ip", "route", "flush", "table", str(TABLE_BASE + slot)])
    return msgs


def sync_wg_routes(state: dict, dev: str = "wg0") -> None:
    """Routen der WireGuard-Bloecke je VLAN ueber wg0.

    wg-quick legt Routen nur beim Start an; Peers, die spaeter per "wg syncconf"
    hinzukommen und eine Adresse ausserhalb des wg0-Netzes haben (VLAN-Bereich),
    braeuchten sonst einen Neustart der Schnittstelle."""
    if util.DRYRUN:
        return
    want = {str(proto_net(v, "wireguard")) for v in vlans(state)}
    res = util.run(["ip", "-j", "-4", "route", "show", "dev", dev, "proto", "static"])
    try:
        have = {r.get("dst", "") for r in json.loads(res.stdout or "[]")}
    except ValueError:
        have = set()
    for dst in have - want:
        if dst:
            util.run(["ip", "route", "del", dst, "dev", dev, "proto", "static"])
    for dst in sorted(want):
        _ip("route", "replace", dst, "dev", dev, "proto", "static")


def link_state(v: dict) -> dict:
    """Zustand einer VLAN-Schnittstelle fuer die Statusanzeige."""
    res = util.run(["ip", "-j", "-4", "addr", "show", "dev", ifname(v)])
    try:
        info = json.loads(res.stdout or "[]")
    except ValueError:
        info = []
    if not info:
        return {"up": False, "text": "fehlt"}
    i = info[0]
    up = "UP" in i.get("flags", []) and "LOWER_UP" in i.get("flags", [])
    return {"up": up, "text": "verbunden" if up else "kein Link"}
