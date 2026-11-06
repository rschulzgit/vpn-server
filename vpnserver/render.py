"""Erzeugt die Konfigurationsdateien aller Dienste aus dem Zustand."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os

import jinja2

from . import pki, util, vlan
from .state import (active_clients, any_ipsec, dns_servers, enabled,
                    wg_server_ip)
from .util import PKI_DIR

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates", "conf")),
    trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
    undefined=jinja2.StrictUndefined, autoescape=False)

IKE2_PROPOSALS = ", ".join([
    "aes256gcm16-prfsha384-ecp384", "aes256gcm16-prfsha256-ecp256", "aes128gcm16-prfsha256-ecp256",
    "aes256-sha384-ecp384", "aes256-sha256-ecp256", "aes256-sha256-modp2048",
    "aes128-sha256-modp2048", "aes256-sha256-modp1024", "aes256-sha1-modp2048",
    "aes256-sha1-modp1024", "aes128-sha1-modp1024", "3des-sha1-modp1024", "default",
])
ESP2_PROPOSALS = ", ".join([
    "aes256gcm16-ecp384", "aes256gcm16-ecp256", "aes256gcm16-modp2048", "aes256gcm16",
    "aes128gcm16", "chacha20poly1305", "aes256-sha256", "aes128-sha256", "aes256-sha1",
    "aes128-sha1", "3des-sha1", "default",
])
IKE1_PROPOSALS = ", ".join([
    "aes256-sha256-modp2048", "aes256-sha1-modp2048", "aes128-sha1-modp2048",
    "aes256-sha256-modp1024", "aes256-sha1-modp1024", "aes128-sha1-modp1024",
    "3des-sha1-modp1024", "aes256-sha1-ecp256",
])
ESP1_PROPOSALS = ", ".join([
    "aes256-sha1", "aes128-sha1", "aes256-sha256", "aes128-sha256", "aes256gcm16",
    "3des-sha1",
])

# Pfade
WG_CONF = "/etc/wireguard/wg0.conf"
OVPN_DIR = "/etc/openvpn/server"
SWANCTL_CONF = "/etc/swanctl/conf.d/vpn-server.conf"
SWANCTL_CA = "/etc/swanctl/x509ca/vpn-server-ca.crt"
SWANCTL_CRT = "/etc/swanctl/x509/vpn-server.crt"
SWANCTL_KEY = "/etc/swanctl/private/vpn-server.key"
SWANCTL_CRL = "/etc/swanctl/x509crl/vpn-server.crl"
STRONGSWAN_CONF = "/etc/strongswan.d/vpn-server.conf"
ACCEL_CONF = "/etc/accel-ppp.conf"
CHAP_SECRETS = util.ETC + "/chap-secrets"
OCSERV_CONF = "/etc/ocserv/ocserv.conf"
OCPASSWD = util.ETC + "/ocpasswd"
OCSERV_GROUP_DIR = "/etc/ocserv/config-per-group"
RADIUS_DIR = util.ETC + "/radius"
RADIUSD_CONF = RADIUS_DIR + "/radiusd.conf"
RADIUS_USERS = RADIUS_DIR + "/users"
RADCLI_CONF = util.ETC + "/radcli/radiusclient.conf"
RADCLI_SERVERS = util.ETC + "/radcli/servers"
NFT_CONF = "/etc/nftables.conf"
NFT_LOCAL_INPUT = util.ETC + "/nftables-local-input.nft"
NFT_LOCAL_FORWARD = util.ETC + "/nftables-local-forward.nft"
SYSCTL_CONF = "/etc/sysctl.d/90-vpn-server.conf"
MODULES_CONF = "/etc/modules-load.d/vpn-server.conf"


def _net(subnet: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(subnet)


def _range(subnet: str, start_offset: int = 10) -> tuple[str, str]:
    net = _net(subnet)
    hosts = list(net.hosts())
    start = hosts[min(start_offset - 1, len(hosts) - 1)]
    return str(start), str(hosts[-1])


def server_id(state: dict) -> str:
    host = state["server"].get("public_host", "").strip()
    return host or util.default_route_info().get("ip") or "127.0.0.1"


def server_cert_names(state: dict) -> list[str]:
    names = [server_id(state)]
    names += util.local_ipv4_addresses()
    hn = util.hostname()
    if hn:
        names += [hn, hn + ".local"]
    out = []
    for n in names:
        if n and n not in out:
            out.append(n)
    return out


# --------------------------------------------------------------------------
# Einzelne Dienste
# --------------------------------------------------------------------------

def render_wireguard(state: dict) -> dict:
    wg = state["proto"]["wireguard"]
    content = _env.get_template("wg0.conf.j2").render(
        wg=wg, server_ip=wg_server_ip(state), prefixlen=_net(wg["subnet"]).prefixlen,
        clients=active_clients(state))
    return {WG_CONF: (content, 0o600)}


def ccd_dir(name: str) -> str:
    return f"{OVPN_DIR}/ccd-{name}"


def render_openvpn(state: dict) -> dict:
    ov = state["proto"]["openvpn"]
    out = {}
    v6 = util.ipv6_available()
    vlans = vlan.vlans(state)
    for name, is_udp in (("udp", True), ("tcp", False)):
        net = _net(ov[f"{name}_subnet"])
        pool = vlan.ovpn_default_pool(ov[f"{name}_subnet"]) if vlans else None
        # *6-Sockets sind unter Linux Dual-Stack (IPv4 + IPv6)
        if is_udp:
            proto = "udp6" if v6 else "udp"
        else:
            proto = "tcp6-server" if v6 else "tcp-server"
        content = _env.get_template("openvpn-server.conf.j2").render(
            name=name, port=ov[f"{name}_port"], proto=proto, dev=f"ovpn-{name}",
            network=str(net.network_address), netmask=str(net.netmask), pki=PKI_DIR,
            dns=dns_servers(state), udp=is_udp, pool=pool, ccd=ccd_dir(name) if vlans else "")
        content += f"management /run/openvpn-server/mgmt-{name}.sock unix\n"
        out[f"{OVPN_DIR}/{name}.conf"] = (content, 0o644)
        # Feste Adressen fuer Clients in VLANs (Datei je Zertifikats-CN = Clientname)
        ips = vlan.ovpn_client_ips(state, name)
        for c in active_clients(state):
            if c["name"] not in ips:
                continue
            v = vlan.client_vlan(state, c)
            lines = [f"# VLAN {v['id']} ({v['name']})",
                     f"ifconfig-push {ips[c['name']]} {net.netmask}"]
            if v.get("dns"):
                lines.append("push-remove dhcp-option")
                lines += [f'push "dhcp-option DNS {d}"' for d in v["dns"]]
            out[f"{ccd_dir(name)}/{c['name']}"] = ("\n".join(lines) + "\n", 0o644)
    return out


def _ipsec_pool(v: dict | None) -> str:
    return f"vlan{v['id']}-ipsec" if v else "vpn-ipsec"


def render_strongswan(state: dict) -> dict:
    start, end = _range(state["proto"]["ikev2"]["subnet"])
    vlans = vlan.vlans(state)
    clients = []
    for c in active_clients(state):
        v = vlan.client_vlan(state, c)
        clients.append(dict(c, pool=_ipsec_pool(v), cert_path=pki.client_paths(c["name"])[0]))
    # Gruppen fuer die Zuordnung nach der RADIUS-Anmeldung (Class-Attribut)
    groups = [{"group": "vlan0", "pool": "vpn-ipsec", "suffix": ""}]
    groups += [{"group": f"vlan{v['id']}", "pool": _ipsec_pool(v), "suffix": f"-vlan{v['id']}"}
               for v in vlans]
    pools = [{"name": "vpn-ipsec", "addrs": f"{start}-{end}", "dns": dns_servers(state)}]
    for v in vlans:
        a, b = vlan.proto_range(v, "ipsec")
        pools.append({"name": _ipsec_pool(v), "addrs": f"{a}-{b}", "dns": vlan.vlan_dns(state, v)})
    radius = vlan.radius_mode(state)
    content = _env.get_template("swanctl.conf.j2").render(
        ikev2=enabled(state, "ikev2"), ikev1_xauth=enabled(state, "ikev1_xauth"),
        l2tp=enabled(state, "l2tp"), clients=clients, radius=radius, groups=groups,
        per_client_certs=bool(vlans), pools=pools,
        server_id=server_id(state), ike2_proposals=IKE2_PROPOSALS,
        esp2_proposals=ESP2_PROPOSALS, ike1_proposals=IKE1_PROPOSALS,
        esp1_proposals=ESP1_PROPOSALS, ipsec_psk=state["proto"]["ipsec_psk"])
    sconf = _env.get_template("strongswan-vpn-server.conf.j2").render(
        radius=radius, secret=state["radius"].get("local_secret", ""))
    out = {
        SWANCTL_CONF: (content, 0o600),
        STRONGSWAN_CONF: (sconf, 0o600),
        SWANCTL_CA: (pki.ca_pem(), 0o644),
        SWANCTL_CRT: (util.read_file(pki.SERVER_CRT) or "", 0o644),
        SWANCTL_KEY: (util.read_file(pki.SERVER_KEY) or "", 0o600),
        SWANCTL_CRL: (util.read_file(pki.CRL) or "", 0o644),
    }
    return out


def _ppp_pool(subnet: str) -> tuple[str, str]:
    """Gateway-Adresse und accel-ppp-Bereich (letztes Oktett) fuer das PPP-Netz."""
    net = _net(subnet)
    hosts = list(net.hosts())
    gw = str(hosts[0])
    first = hosts[min(9, len(hosts) - 1)]
    last = hosts[-1]
    # accel-ppp versteht "a.b.c.X-Y" (nur letztes Oktett); auf ein /24 begrenzen
    if str(first).rsplit(".", 1)[0] != str(last).rsplit(".", 1)[0]:
        last = ipaddress.ip_address(str(first).rsplit(".", 1)[0] + ".254")
    return gw, f"{first}-{str(last).rsplit('.', 1)[1]}"


def render_accel(state: dict) -> dict:
    gw, pool = _ppp_pool(state["proto"]["ppp"]["subnet"])
    cert, key = pki.tls_cert_paths(state)
    vlan_pools = []
    for v in vlan.vlans(state):
        a, b = vlan.proto_range(v, "ppp")
        vlan_pools.append({"name": f"vlan{v['id']}", "range": f"{a}-{b.rsplit('.', 1)[1]}"})
    radius = vlan.radius_mode(state)
    content = _env.get_template("accel-ppp.conf.j2").render(
        l2tp=enabled(state, "l2tp"), sstp=enabled(state, "sstp"), pptp=enabled(state, "pptp"),
        sstp_port=state["proto"]["sstp"]["port"], tls_cert=cert, tls_key=key,
        dns=dns_servers(state), gw_ip=gw, pool_range=pool, vlan_pools=vlan_pools,
        radius=radius, secret=state["radius"].get("local_secret", ""))
    lines = ["# Verwaltet von VPN-Server - Format: Benutzer Server Passwort IP"]
    for c in active_clients(state) if not radius else []:
        lines.append(f'"{c["name"]}" * "{c["password"]}" *')
    return {ACCEL_CONF: (content, 0o600), CHAP_SECRETS: ("\n".join(lines) + "\n", 0o600)}


def _sha512_crypt(state: dict, name: str, password: str) -> str:
    """SHA-512-crypt mit deterministischem Salz (stabile Datei, kein Neuschreiben)."""
    salt = hmac.new(state["secret_key"].encode(), f"{name}:{password}".encode(),
                    hashlib.sha256).hexdigest()[:16]
    res = util.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"], input=password)
    return res.stdout.strip()


def render_ocserv(state: dict) -> dict:
    oc = state["proto"]["openconnect"]
    net = _net(oc["subnet"])
    cert, key = pki.tls_cert_paths(state)
    radius = vlan.radius_mode(state)
    content = _env.get_template("ocserv.conf.j2").render(
        port=oc["port"], tls_cert=cert, tls_key=key, network=str(net.network_address),
        netmask=str(net.netmask), dns=dns_servers(state), radius=radius,
        radcli=RADCLI_CONF, group_dir=OCSERV_GROUP_DIR)
    lines = [f'{c["name"]}:*:{_sha512_crypt(state, c["name"], c["password"])}'
             for c in (active_clients(state) if not radius else [])]
    out = {OCSERV_CONF: (content, 0o644), OCPASSWD: ("\n".join(lines) + "\n", 0o600)}
    for v in vlan.vlans(state):
        g = [f"# VLAN {v['id']} ({v['name']}) - verwaltet von VPN-Server",
             f"ipv4-network = {vlan.proto_net(v, 'openconnect')}"]
        g += [f"dns = {d}" for d in vlan.vlan_dns(state, v)]
        g.append("route = default")
        out[f"{OCSERV_GROUP_DIR}/vlan{v['id']}"] = ("\n".join(g) + "\n", 0o644)
    return out


# --------------------------------------------------------------------------
# Lokaler RADIUS-Dienst (FreeRADIUS) und RADIUS-Client fuer ocserv
# --------------------------------------------------------------------------

def _radius_users(state: dict) -> str:
    lines = ["# Verwaltet von VPN-Server - lokale VPN-Benutzer"]
    r = state["radius"]
    if r.get("enabled") and not r.get("local_users", True):
        lines.append("# Nur externer RADIUS-Server (lokale Benutzer deaktiviert)")
        return "\n".join(lines) + "\n"
    for c in sorted(state["clients"].values(), key=lambda c: c["name"]):
        if not c.get("enabled", True):
            lines += [f'"{c["name"]}" Auth-Type := Reject',
                      '\tReply-Message := "Zugang gesperrt"', ""]
            continue
        v = vlan.client_vlan(state, c)
        entry = f'"{c["name"]}" Cleartext-Password := \'{c["password"]}\''
        if v:
            entry += ("\n\tTunnel-Type := VLAN,\n\tTunnel-Medium-Type := IEEE-802,"
                      f'\n\tTunnel-Private-Group-Id := "{v["id"]}"')
        lines += [entry, ""]
    return "\n".join(lines) + "\n"


def render_radius(state: dict) -> dict:
    r = state["radius"]
    upstream = bool(r.get("enabled") and r.get("servers"))
    local_users = not r.get("enabled") or r.get("local_users", True)
    vlans = []
    for v in vlan.vlans(state):
        dns4 = [d for d in vlan.vlan_dns(state, v) if ":" not in d][:2]
        vlans.append(dict(v, dns4=dns4))
    local_names = [c["name"] for c in active_clients(state)] if local_users else []
    lan_ip = util.default_route_info().get("ip", "")
    content = _env.get_template("freeradius.conf.j2").render(
        confdir=RADIUS_DIR, users=RADIUS_USERS, secret=r["local_secret"],
        upstream=upstream, servers=r.get("servers", []), local_users=local_users,
        accounting=bool(r.get("accounting", True)), nas_id=r.get("nas_identifier") or "vpn-server",
        nas_ip=lan_ip, vlans=vlans, unknown_reject=r.get("unknown_vlan", "reject") == "reject",
        no_vlan_reject=r.get("no_vlan", "default") == "reject",
        local_regex="|".join(local_names))
    radcli = "\n".join([
        "# Verwaltet von VPN-Server - RADIUS-Client fuer ocserv",
        "nas-identifier vpn-ocserv",
        "authserver 127.0.0.1:1812",
        "acctserver 127.0.0.1:1813",
        f"servers {RADCLI_SERVERS}",
        "dictionary /etc/radcli/dictionary",
        "default_realm",
        "radius_timeout 10",
        "radius_retries 2",
        "bindaddr *",
        ""])
    return {
        RADIUSD_CONF: (content, 0o600),
        RADIUS_USERS: (_radius_users(state), 0o600),
        RADCLI_CONF: (radcli, 0o644),
        RADCLI_SERVERS: (f"127.0.0.1 {r['local_secret']}\n", 0o600),
    }


def render_firewall(state: dict) -> dict:
    s = state["server"]
    pr = state["proto"]
    dns_private = []
    for d in dns_servers(state):
        try:
            if ipaddress.ip_address(d).is_private:
                dns_private.append(d)
        except ValueError:
            pass
    vlans = [dict(v, ifname=vlan.ifname(v), sources=vlan.sources(state, v))
             for v in vlan.vlans(state)]
    ipsec_nets = [pr["ikev2"]["subnet"]] + [str(vlan.proto_net(v, "ipsec")) for v in vlans]
    content = _env.get_template("nftables.conf.j2").render(
        vpn_nets=vlan.all_vpn_nets(state), vlans=vlans, ipsec_nets=ipsec_nets,
        wireguard=enabled(state, "wireguard"), wg_port=pr["wireguard"]["port"],
        openvpn_udp=enabled(state, "openvpn") and pr["openvpn"]["udp"],
        openvpn_tcp=enabled(state, "openvpn") and pr["openvpn"]["tcp"],
        ovpn_udp_port=pr["openvpn"]["udp_port"], ovpn_tcp_port=pr["openvpn"]["tcp_port"],
        ipsec=any_ipsec(state), l2tp=enabled(state, "l2tp"),
        sstp=enabled(state, "sstp"), sstp_port=pr["sstp"]["port"],
        openconnect=enabled(state, "openconnect"), oc_port=pr["openconnect"]["port"],
        pptp=enabled(state, "pptp"), letsencrypt=state["letsencrypt"].get("enabled"),
        webui_public=s.get("webui_public"), webui_port=s.get("webui_port", 8443),
        ssh_public=s.get("ssh_public"), client_to_client=s.get("client_to_client"),
        lan_access=s.get("lan_access", True), dns_private=dns_private)
    out = {NFT_CONF: (content, 0o755)}
    # Lokale Erweiterungen nur anlegen, nie ueberschreiben
    for path in (NFT_LOCAL_INPUT, NFT_LOCAL_FORWARD):
        if util.read_file(path) is None:
            out[path] = ("# Eigene nftables-Regeln (werden nicht ueberschrieben)\n", 0o644)
    return out


def render_system(state: dict) -> dict:
    sysctl = "\n".join([
        "# Verwaltet von VPN-Server",
        "net.ipv4.ip_forward = 1",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.conf.all.send_redirects = 0",
        "net.ipv4.conf.default.accept_redirects = 0",
        "net.ipv4.conf.default.send_redirects = 0",
        "net.ipv4.conf.all.rp_filter = 2",
        "net.ipv4.conf.default.rp_filter = 2",
        "net.ipv4.tcp_mtu_probing = 1",
        "net.core.default_qdisc = fq",
        "net.ipv4.tcp_congestion_control = bbr",
        "",
    ])
    modules = "\n".join([
        "# Verwaltet von VPN-Server",
        "wireguard", "tun", "ppp_generic", "ppp_async", "ppp_mppe", "l2tp_ppp", "pptp",
        "nf_conntrack", "tcp_bbr", "",
    ])
    return {SYSCTL_CONF: (sysctl, 0o644), MODULES_CONF: (modules, 0o644)}


def render_all(state: dict) -> dict:
    files: dict = {}
    files.update(render_system(state))
    files.update(render_firewall(state))
    files.update(render_wireguard(state))
    files.update(render_openvpn(state))
    files.update(render_strongswan(state))
    files.update(render_accel(state))
    files.update(render_ocserv(state))
    files.update(render_radius(state))
    return files


# Verzeichnisse, deren Inhalt vollstaendig aus dem Zustand erzeugt wird
MANAGED_DIRS = [ccd_dir("udp"), ccd_dir("tcp"), OCSERV_GROUP_DIR]
