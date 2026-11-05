"""Client-Profile: WireGuard (inkl. QR-Code), OpenVPN, IKEv2 (Android, Apple,
strongSwan, Windows), SSTP, L2TP, PPTP sowie ZIP-Gesamtpaket."""

from __future__ import annotations

import base64
import io
import ipaddress
import json
import plistlib
import uuid
import zipfile

import qrcode
import qrcode.image.svg

from . import pki, util
from .state import dns_servers, enabled, public_host, vpn_subnets


def _uuid(state: dict, *parts: str) -> str:
    """Stabile UUID je Server/Client/Profil (Profile ersetzen sich beim Neuimport)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "vpn-server:" + state["secret_key"][:16] + ":"
                          + ":".join(parts))).upper()


def lan_subnet() -> str | None:
    info = util.default_route_info()
    if not info.get("ip"):
        return None
    try:
        return str(ipaddress.ip_interface(f"{info['ip']}/{info['prefixlen']}").network)
    except ValueError:
        return None


def split_routes(state: dict) -> list[str]:
    routes = list(vpn_subnets(state))
    lan = lan_subnet()
    if lan and state["server"].get("lan_access", True):
        routes.append(lan)
    return routes


def server_name(state: dict) -> str:
    return state["server"].get("name") or "VPN-Server"


# --------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------

def wireguard_conf(state: dict, client: dict) -> str:
    wg = state["proto"]["wireguard"]
    allowed = "0.0.0.0/0, ::/0" if client.get("full_tunnel", True) else ", ".join(split_routes(state))
    lines = [
        "[Interface]",
        f"# {server_name(state)} - {client['name']}",
        f"PrivateKey = {client['wg']['privkey']}",
        f"Address = {client['wg']['ip']}/32",
        f"DNS = {', '.join(dns_servers(state))}",
    ]
    if wg.get("mtu"):
        lines.append(f"MTU = {wg['mtu']}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {wg['pubkey']}",
        f"PresharedKey = {client['wg']['psk']}",
        f"Endpoint = {_host_port(public_host(state), wg['port'])}",
        f"AllowedIPs = {allowed}",
        f"PersistentKeepalive = {wg.get('keepalive', 25)}",
        "",
    ]
    return "\n".join(lines)


def _host_port(host: str, port: int) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2,
                      error_correction=qrcode.constants.ERROR_CORRECT_M)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    # XML-Deklaration entfernen, damit das SVG inline eingebettet werden kann
    if svg.startswith("<?xml"):
        svg = svg.split("?>", 1)[1]
    return svg.strip()


# --------------------------------------------------------------------------
# OpenVPN
# --------------------------------------------------------------------------

def openvpn_ovpn(state: dict, client: dict) -> str:
    ov = state["proto"]["openvpn"]
    host = public_host(state)
    lines = [
        f"# {server_name(state)} - OpenVPN-Profil fuer {client['name']}",
        "client",
        "dev tun",
        "nobind",
        "persist-key",
        "persist-tun",
        "resolv-retry infinite",
        "remote-cert-tls server",
        "tls-version-min 1.2",
        "auth SHA256",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "verb 3",
        "setenv opt block-outside-dns",
    ]
    if ov.get("udp"):
        lines.append(f"remote {host} {ov['udp_port']} udp")
    if ov.get("tcp"):
        lines.append(f"remote {host} {ov['tcp_port']} tcp")
    if ov.get("udp") and not ov.get("tcp"):
        lines.append("explicit-exit-notify 1")
    if ov.get("udp") and ov.get("tcp"):
        # Schnell auf TCP ausweichen, wenn UDP blockiert ist (Hotel-/Firmen-WLAN)
        lines.append("server-poll-timeout 10")
    if not client.get("full_tunnel", True):
        lines.append('pull-filter ignore "redirect-gateway"')
        for r in split_routes(state):
            net = ipaddress.ip_network(r)
            lines.append(f"route {net.network_address} {net.netmask}")
    lines += [
        "<ca>", pki.ca_pem().strip(), "</ca>",
        "<cert>", pki.client_cert_pem(client["name"]).strip(), "</cert>",
        "<key>", pki.client_key_pem(client["name"]).strip(), "</key>",
        "<tls-crypt>", pki.tls_crypt_key().strip(), "</tls-crypt>",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# IKEv2: PKCS#12, strongSwan-App (.sswan), Apple (.mobileconfig)
# --------------------------------------------------------------------------

def client_p12(state: dict, client: dict) -> bytes:
    return pki.client_p12(client["name"], client["p12_password"],
                          friendly=f"{client['name']} ({server_name(state)})")


def sswan(state: dict, client: dict, kind: str) -> str:
    host = public_host(state)
    profile = {
        "uuid": _uuid(state, client["name"], "sswan", kind).lower(),
        "name": f"{server_name(state)} ({'Zertifikat' if kind == 'cert' else 'Passwort'})",
        "type": "ikev2-cert" if kind == "cert" else "ikev2-eap",
        "remote": {
            "addr": host,
            "id": host,
            "cert": base64.b64encode(pki.ca_der()).decode(),
        },
        "local": {},
    }
    if kind == "cert":
        profile["local"]["p12"] = base64.b64encode(client_p12(state, client)).decode()
    else:
        profile["local"]["eap_id"] = client["name"]
    return json.dumps(profile, indent=2)


def mobileconfig(state: dict, client: dict, kind: str) -> bytes:
    host = public_host(state)
    name = client["name"]
    sname = server_name(state)
    ca_uuid = _uuid(state, "ca")
    p12_uuid = _uuid(state, name, "p12")
    vpn_uuid = _uuid(state, name, "vpn", kind)
    ike = {
        "RemoteAddress": host,
        "RemoteIdentifier": host,
        "LocalIdentifier": name,
        "ServerCertificateIssuerCommonName": pki.ca_common_name(),
        "ServerCertificateCommonName": host,
        "CertificateType": "RSA",
        "EnablePFS": 1,
        "DeadPeerDetectionRate": "Medium",
        "DisableMOBIKE": 0,
        "DisableRedirect": 1,
        "EnableCertificateRevocationCheck": 0,
        "UseConfigurationAttributeInternalIPSubnet": 0,
        "OnDemandEnabled": 0,
        "IKESecurityAssociationParameters": {
            "EncryptionAlgorithm": "AES-256-GCM",
            "IntegrityAlgorithm": "SHA2-384",
            "DiffieHellmanGroup": 20,
            "LifeTimeInMinutes": 1440,
        },
        "ChildSecurityAssociationParameters": {
            "EncryptionAlgorithm": "AES-256-GCM",
            "IntegrityAlgorithm": "SHA2-384",
            "DiffieHellmanGroup": 20,
            "LifeTimeInMinutes": 1440,
        },
    }
    if kind == "cert":
        ike.update({"AuthenticationMethod": "Certificate", "ExtendedAuthEnabled": 0,
                    "PayloadCertificateUUID": p12_uuid})
    else:
        ike.update({"AuthenticationMethod": "None", "ExtendedAuthEnabled": 1,
                    "AuthName": name, "AuthPassword": client["password"]})
    content = [
        {
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"vpnserver.{ca_uuid}",
            "PayloadUUID": ca_uuid,
            "PayloadDisplayName": pki.ca_common_name(),
            "PayloadContent": pki.ca_der(),
        },
        {
            "PayloadType": "com.apple.vpn.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"vpnserver.{vpn_uuid}",
            "PayloadUUID": vpn_uuid,
            "PayloadDisplayName": f"{sname} IKEv2",
            "UserDefinedName": f"{sname} ({'Zertifikat' if kind == 'cert' else 'Passwort'})",
            "VPNType": "IKEv2",
            "IKEv2": ike,
            "IPv4": {"OverridePrimary": 1},
        },
    ]
    if kind == "cert":
        content.append({
            "PayloadType": "com.apple.security.pkcs12",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"vpnserver.{p12_uuid}",
            "PayloadUUID": p12_uuid,
            "PayloadDisplayName": f"{name}.p12",
            "Password": client["p12_password"],
            "PayloadContent": client_p12(state, client),
        })
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"vpnserver.{_uuid(state, name, 'profile', kind)}",
        "PayloadUUID": _uuid(state, name, "profile", kind),
        "PayloadDisplayName": f"{sname} - {name}",
        "PayloadDescription": f"VPN-Zugang zu {sname} ({host})",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": content,
    }
    return plistlib.dumps(profile)


# --------------------------------------------------------------------------
# Windows (Batch-Datei mit eingebettetem PowerShell-Skript)
# --------------------------------------------------------------------------

_CMD_HEADER = """@echo off
rem VPN-Server: Rechtsklick auf diese Datei -> "Als Administrator ausfuehren"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0'); $i=$s.IndexOf('#PS'+'START'); Invoke-Expression $s.Substring($i)"
pause
exit /b
#PSSTART
"""

_PS_ADMIN = """$ErrorActionPreference = 'Stop'
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Bitte mit Rechtsklick -> Als Administrator ausfuehren starten!' -ForegroundColor Red
    return
}
"""


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ps_import_ca(state: dict) -> str:
    return (
        "$caPem = @'\n" + pki.ca_pem().strip() + "\n'@\n"
        "$caFile = Join-Path $env:TEMP 'vpn-server-ca.crt'\n"
        "Set-Content -Path $caFile -Value $caPem -Encoding Ascii\n"
        "Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null\n"
        "Remove-Item $caFile\n"
        "Write-Host 'CA-Zertifikat importiert.'\n"
    )


def windows_cmd(state: dict, client: dict, kind: str) -> str:
    host = public_host(state)
    sname = server_name(state)
    labels = {"ikev2-eap": "IKEv2", "ikev2-cert": "IKEv2-Zertifikat", "sstp": "SSTP",
              "l2tp": "L2TP", "pptp": "PPTP"}
    conn = f"{sname} {labels[kind]}"
    ps = _PS_ADMIN
    ps += f"$name = {_ps_quote(conn)}\n"
    ps += "Remove-VpnConnection -Name $name -AllUserConnection -Force -ErrorAction SilentlyContinue\n"
    ps += "Remove-VpnConnection -Name $name -Force -ErrorAction SilentlyContinue\n"
    if kind == "ikev2-eap":
        ps += _ps_import_ca(state)
        ps += (f"Add-VpnConnection -Name $name -ServerAddress {_ps_quote(host)} -TunnelType Ikev2 "
               "-AuthenticationMethod Eap -EncryptionLevel Required -RememberCredential -AllUserConnection\n")
        ps += ("Set-VpnConnectionIPsecConfiguration -ConnectionName $name -AllUserConnection "
               "-AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 "
               "-EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 "
               "-PfsGroup None -Force\n")
    elif kind == "ikev2-cert":
        p12 = base64.b64encode(client_p12(state, client)).decode()
        ps += _ps_import_ca(state)
        ps += (f"$p12 = [Convert]::FromBase64String('{p12}')\n"
               "$p12File = Join-Path $env:TEMP 'vpn-server-client.p12'\n"
               "[IO.File]::WriteAllBytes($p12File, $p12)\n"
               f"$pw = ConvertTo-SecureString -String {_ps_quote(client['p12_password'])} -AsPlainText -Force\n"
               "Import-PfxCertificate -FilePath $p12File -CertStoreLocation Cert:\\LocalMachine\\My "
               "-Password $pw | Out-Null\n"
               "Remove-Item $p12File\n"
               "Write-Host 'Client-Zertifikat importiert.'\n")
        ps += (f"Add-VpnConnection -Name $name -ServerAddress {_ps_quote(host)} -TunnelType Ikev2 "
               "-AuthenticationMethod MachineCertificate -EncryptionLevel Required -AllUserConnection\n")
        ps += ("Set-VpnConnectionIPsecConfiguration -ConnectionName $name -AllUserConnection "
               "-AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 "
               "-EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 "
               "-PfsGroup None -Force\n")
    elif kind == "sstp":
        port = state["proto"]["sstp"]["port"]
        addr = host if int(port) == 443 else f"{host}:{port}"
        if not (state["letsencrypt"].get("enabled") and pki.le_available()):
            ps += _ps_import_ca(state)
            ps += ("New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SstpSvc\\Parameters' "
                   "-Force | Out-Null\n"
                   "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SstpSvc\\Parameters' "
                   "-Name NoCertRevocationCheck -Value 1 -Type DWord\n")
        ps += (f"Add-VpnConnection -Name $name -ServerAddress {_ps_quote(addr)} -TunnelType Sstp "
               "-AuthenticationMethod MSChapv2 -EncryptionLevel Required -RememberCredential -AllUserConnection\n")
    elif kind == "l2tp":
        ps += (f"Add-VpnConnection -Name $name -ServerAddress {_ps_quote(host)} -TunnelType L2tp "
               f"-L2tpPsk {_ps_quote(state['proto']['ipsec_psk'])} -AuthenticationMethod MSChapv2 "
               "-EncryptionLevel Required -RememberCredential -AllUserConnection -Force\n")
        ps += ("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent' "
               "-Name AssumeUDPEncapsulationContextOnSendRule -Value 2 -Type DWord\n"
               "Write-Host 'Hinweis: Fuer L2TP hinter NAT ist ein Neustart von Windows erforderlich.' "
               "-ForegroundColor Yellow\n")
    elif kind == "pptp":
        ps += (f"Add-VpnConnection -Name $name -ServerAddress {_ps_quote(host)} -TunnelType Pptp "
               "-AuthenticationMethod MSChapv2 -EncryptionLevel Required -RememberCredential -AllUserConnection\n")
    if kind != "ikev2-cert":
        ps += (f"Write-Host ''\nWrite-Host 'Benutzername: {client['name']}' -ForegroundColor Cyan\n"
               f"Write-Host 'Passwort:     {client['password']}' -ForegroundColor Cyan\n")
    ps += ("Write-Host ''\nWrite-Host ('VPN-Verbindung \"' + $name + '\" wurde angelegt. Verbinden ueber "
           "Einstellungen -> Netzwerk und Internet -> VPN.') -ForegroundColor Green\n")
    return (_CMD_HEADER + ps).replace("\r\n", "\n").replace("\n", "\r\n")


# --------------------------------------------------------------------------
# Zugangsdaten als Text + ZIP-Paket
# --------------------------------------------------------------------------

def credentials_text(state: dict, client: dict) -> str:
    host = public_host(state)
    pr = state["proto"]
    out = [f"{server_name(state)} - Zugangsdaten fuer {client['name']}", "=" * 60, "",
           f"Server-Adresse:  {host}", f"Benutzername:    {client['name']}",
           f"Passwort:        {client['password']}", ""]
    if enabled(state, "wireguard"):
        out += ["WireGuard: Datei wireguard.conf importieren oder QR-Code scannen.", ""]
    if enabled(state, "openvpn"):
        out += ["OpenVPN: Datei openvpn.ovpn importieren.", ""]
    if enabled(state, "ikev2"):
        out += ["IKEv2/IPsec:",
                f"  Server / Remote-ID:      {host}",
                f"  PSK-Kennung (Identifier): {client['psk_id']}",
                f"  Pre-Shared Key (PSK):    {client['psk']}",
                f"  Zertifikat: client.p12   Passwort: {client['p12_password']}",
                f"  EAP (MSCHAPv2):          Benutzer {client['name']} / Passwort wie oben", ""]
    if enabled(state, "l2tp") or enabled(state, "ikev1_xauth"):
        out += ["L2TP/IPsec und Cisco IPsec (IKEv1):",
                f"  IPsec-PSK (Shared Secret): {pr['ipsec_psk']}",
                "  Benutzername/Passwort wie oben, Gruppenname leer lassen.", ""]
    if enabled(state, "sstp"):
        port = pr["sstp"]["port"]
        out += [f"SSTP: Server {host}{'' if int(port) == 443 else ':' + str(port)}, "
                "Benutzername/Passwort wie oben.", ""]
    if enabled(state, "openconnect"):
        out += [f"OpenConnect/AnyConnect: Server {host}:{pr['openconnect']['port']}, "
                "Benutzername/Passwort wie oben.",
                f"  Zertifikats-Pin: {pki.server_pin_sha256()}", ""]
    if enabled(state, "pptp"):
        out += ["PPTP (unsicher!): Server " + host + ", Benutzername/Passwort wie oben.", ""]
    out += ["CA-Zertifikat: ca.crt (fuer IKEv2, SSTP und OpenConnect importieren)", ""]
    return "\n".join(out)


def credentials_json(state: dict, client: dict) -> str:
    """Maschinenlesbare Zugangsdaten (fuer Automatisierung)."""
    pr = state["proto"]
    data = {
        "server": public_host(state),
        "username": client["name"],
        "password": client["password"],
        "ikev2": {"psk_id": client["psk_id"], "psk": client["psk"],
                  "p12_password": client["p12_password"], "remote_id": public_host(state)},
        "ipsec_psk": pr["ipsec_psk"],
        "wireguard_ip": client["wg"]["ip"],
        "ports": {
            "wireguard": pr["wireguard"]["port"], "openvpn_udp": pr["openvpn"]["udp_port"],
            "openvpn_tcp": pr["openvpn"]["tcp_port"], "sstp": pr["sstp"]["port"],
            "openconnect": pr["openconnect"]["port"],
        },
        "openconnect_pin": pki.server_pin_sha256(),
        "enabled": {p: enabled(state, p) for p in ("wireguard", "openvpn", "ikev2", "ikev1_xauth",
                                                    "l2tp", "sstp", "openconnect", "pptp")},
    }
    return json.dumps(data, indent=2)


DOWNLOADS = {
    # kind: (Dateiname, MIME-Typ, Protokoll-Voraussetzung)
    "wireguard": ("{name}-wireguard.conf", "text/plain", "wireguard"),
    "wireguard-qr": ("{name}-wireguard-qr.svg", "image/svg+xml", "wireguard"),
    "openvpn": ("{name}.ovpn", "application/x-openvpn-profile", "openvpn"),
    "ca": ("vpn-server-ca.crt", "application/x-x509-ca-cert", None),
    "p12": ("{name}.p12", "application/x-pkcs12", "ikev2"),
    "sswan-cert": ("{name}-zertifikat.sswan", "application/vnd.strongswan.profile", "ikev2"),
    "sswan-eap": ("{name}-passwort.sswan", "application/vnd.strongswan.profile", "ikev2"),
    "mobileconfig-cert": ("{name}-ikev2-zertifikat.mobileconfig",
                          "application/x-apple-aspen-config", "ikev2"),
    "mobileconfig-eap": ("{name}-ikev2-passwort.mobileconfig",
                         "application/x-apple-aspen-config", "ikev2"),
    "win-ikev2-eap": ("{name}-windows-ikev2.cmd", "application/octet-stream", "ikev2"),
    "win-ikev2-cert": ("{name}-windows-ikev2-zertifikat.cmd", "application/octet-stream", "ikev2"),
    "win-sstp": ("{name}-windows-sstp.cmd", "application/octet-stream", "sstp"),
    "win-l2tp": ("{name}-windows-l2tp.cmd", "application/octet-stream", "l2tp"),
    "win-pptp": ("{name}-windows-pptp.cmd", "application/octet-stream", "pptp"),
    "credentials": ("{name}-zugangsdaten.txt", "text/plain", None),
    "json": ("{name}-zugangsdaten.json", "application/json", None),
    "zip": ("{name}-vpn-profile.zip", "application/zip", None),
}


def generate(state: dict, client: dict, kind: str) -> tuple[str, str, bytes]:
    if kind not in DOWNLOADS:
        raise KeyError(kind)
    fname, mime, proto = DOWNLOADS[kind]
    if proto and not enabled(state, proto):
        raise KeyError(kind)
    fname = fname.format(name=client["name"])
    if kind == "wireguard":
        data = wireguard_conf(state, client).encode()
    elif kind == "wireguard-qr":
        data = qr_svg(wireguard_conf(state, client)).encode()
    elif kind == "openvpn":
        data = openvpn_ovpn(state, client).encode()
    elif kind == "ca":
        data = pki.ca_pem().encode()
    elif kind == "p12":
        data = client_p12(state, client)
    elif kind.startswith("sswan-"):
        data = sswan(state, client, kind.split("-", 1)[1]).encode()
    elif kind.startswith("mobileconfig-"):
        data = mobileconfig(state, client, kind.split("-", 1)[1])
    elif kind.startswith("win-"):
        data = windows_cmd(state, client, kind[4:]).encode()
    elif kind == "credentials":
        data = credentials_text(state, client).encode()
    elif kind == "json":
        data = credentials_json(state, client).encode()
    elif kind == "zip":
        data = zip_all(state, client)
    else:
        raise KeyError(kind)
    return fname, mime, data


def zip_all(state: dict, client: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for kind in DOWNLOADS:
            if kind == "zip":
                continue
            try:
                fname, _mime, data = generate(state, client, kind)
            except KeyError:
                continue
            zf.writestr(fname, data)
    return buf.getvalue()
