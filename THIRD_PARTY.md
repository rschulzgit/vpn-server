# Drittkomponenten

Dieses Dokument listet, welche fremden Komponenten mit VPN-Server verbreitet
bzw. installiert werden, unter welchen Lizenzen sie stehen und wo der
Quellcode zu finden ist. Maßgeblich sind jeweils die Lizenzangaben des
Projekts bzw. die Datei `/usr/share/doc/<paket>/copyright` im installierten
System.

## 1. Inhalt des Installations-ISOs

| Komponente | Herkunft | Lizenz | Quellcode |
|---|---|---|---|
| **Debian 13 „trixie“ Netinst** (Debian-Installer, Linux-Kernel, Bootloader GRUB/shim/isolinux, Basispakete) – unverändert übernommen; ergänzt wurden nur Bootmenü- und Preseed-Dateien | [debian.org](https://www.debian.org/CD/netinst/) | je Paket (überwiegend GPL-2.0/GPL-3.0/LGPL, BSD, MIT u. a.) | Quell-Images zur jeweiligen Version: `https://cdimage.debian.org/cdimage/archive/<version>/source/` (bzw. `https://cdimage.debian.org/debian-cd/current/source/`), Einzelpakete auf [sources.debian.org](https://sources.debian.org), ältere Stände auf [snapshot.debian.org](https://snapshot.debian.org) |
| **accel-ppp 1.15.0** (SSTP, L2TP, PPTP) als `.deb` | [github.com/accel-ppp/accel-ppp](https://github.com/accel-ppp/accel-ppp), Tag `1.15.0` | GPL-2.0 (siehe `COPYING` im Quellcode) | wird mit jedem Release als `accel-ppp-1.15.0-source.tar.gz` mitveröffentlicht; Build-Weg: [`installer/build-accel-ppp.sh`](installer/build-accel-ppp.sh) (cmake-Optionen dort, ohne eigene Patches), in der CI im Container `debian:trixie` |
| **VPN-Server** (Weboberfläche, `vpnctl`, Installer, Vorlagen) | dieses Repository | GPL-3.0-or-later | dieses Repository (Tag des jeweiligen Releases) |

Welche Debian-Version einem ISO zugrunde liegt, steht in den Release-Hinweisen
(Abschnitt „Lizenz und Quellcode“) sowie im Dateinamen des Basis-Images im
Build-Protokoll.

## 2. Während der Installation aus Debian geladene Pakete

Diese Pakete sind **nicht** im ISO enthalten, sondern werden bei der
Installation direkt von den Debian-Spiegeln geladen (bzw. bei `install.sh`
aus den Paketquellen des Systems). Quellcode: jeweils
`https://sources.debian.org/src/<quellpaket>/`.

| Paket(e) | Zweck | Lizenz (Upstream) |
|---|---|---|
| `wireguard-tools` | WireGuard | GPL-2.0 |
| `openvpn` | OpenVPN | GPL-2.0 (mit OpenSSL-Ausnahme) |
| `ocserv` | OpenConnect-Server | GPL-2.0-or-later |
| `strongswan-swanctl`, `charon-systemd`, `libcharon-*`, `libstrongswan-*` | IKEv2/IPsec, L2TP/IPsec, Cisco IPsec | GPL-2.0-or-later |
| `freeradius`, `freeradius-utils` | RADIUS-Vermittlung | GPL-2.0-or-later |
| `nftables`, `iproute2`, `kmod` | Firewall, Netzwerk, Kernelmodule | GPL-2.0 bzw. LGPL-2.1-or-later |
| `openssl`, `ca-certificates` | Kryptografie, Zertifikate | Apache-2.0 bzw. MPL-2.0 |
| `curl`, `sudo`, `avahi-daemon` | Hilfsprogramme, `vpn-server.local` | curl-Lizenz (MIT-artig), ISC-artig, LGPL-2.1-or-later |
| `iputils-ping`, `traceroute`, `bind9-dnsutils`, `tcpdump` | Werkzeuge der Weboberfläche | BSD-3-Clause/GPL-2.0-or-later, GPL-2.0-or-later, MPL-2.0, BSD-3-Clause |
| `unattended-upgrades`, `certbot` | Sicherheitsupdates, Let's Encrypt | GPL-2.0, Apache-2.0 |
| `python3`, `python3-flask`, `python3-jinja2`, `python3-qrcode`, `python3-cryptography`, `python3-gunicorn` | Weboberfläche | PSF-2.0, BSD-3-Clause, BSD-3-Clause, BSD-3-Clause, Apache-2.0/BSD-3-Clause, MIT |

Die Weboberfläche bindet keine externen JavaScript-, CSS- oder
Schriftarten-Bibliotheken ein; Diagramme und Symbole sind Teil dieses
Repositorys.

## 3. Nur zum Testen (nicht verbreitet)

Die CI verwendet zusätzlich QEMU, OVMF, strongSwan-, OpenVPN-, xl2tpd-,
sstp-client-, OpenConnect- und FreeRADIUS-Pakete von Ubuntu sowie PowerShell,
um Endgeräte nachzubilden. Diese Werkzeuge sind nicht Bestandteil des ISOs.

---

*Hinweis: Diese Übersicht ist keine Rechtsberatung.*
