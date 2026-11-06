# VPN-Server – ein ISO, alle gängigen VPN-Protokolle, Einrichtung per Weboberfläche

Ein bootfähiges Installations-ISO (Basis: **Debian 13 „trixie“**), das einen kompletten
VPN-Server vollautomatisch installiert. Danach erfolgt alles über eine deutschsprachige
Weboberfläche – Sie müssen am Router nur noch die angezeigten **Portfreigaben** einrichten.

Freie Software unter der **GPL-3.0-or-later** (siehe [Lizenz](#lizenz)).

## Unterstützte Protokolle

| Protokoll | Server-Software | Clients (Auswahl) | Anmeldung |
|---|---|---|---|
| **WireGuard** (empfohlen) | Linux-Kernel | WireGuard-App für Android, iOS, Windows, macOS, Linux – **QR-Code** | Schlüssel |
| **OpenVPN** UDP + TCP | OpenVPN 2.6 | OpenVPN Connect, OpenVPN for Android, Tunnelblick, NetworkManager | Zertifikat (in `.ovpn`) |
| **IKEv2/IPsec** | strongSwan | Android ohne App („IKEv2/IPSec **PSK**“, „**RSA**“ = Zertifikat, „MSCHAPv2“), iOS/macOS (Profil `.mobileconfig`), Windows (Einrichtungsskript), strongSwan-App (`.sswan`) | Zertifikat, PSK oder Benutzer/Passwort |
| **L2TP/IPsec** | strongSwan + accel-ppp | Windows, macOS, iOS, Android ≤ 11 | PSK + Benutzer/Passwort |
| **IPsec XAuth** („Cisco IPsec“ in iOS/macOS, IKEv1) | strongSwan | iOS/macOS „IPsec“, Android ≤ 11 | PSK + Benutzer/Passwort |
| **SSTP** | accel-ppp | Windows (eingebaut), Open SSTP Client (Android), sstp-client (Linux) | Benutzer/Passwort |
| **OpenConnect** (AnyConnect-kompatibel) | ocserv | OpenConnect, Cisco Secure Client | Benutzer/Passwort |
| **PPTP** (aus, unsicher) | accel-ppp | ältere Geräte | Benutzer/Passwort |

Für jeden angelegten Client erzeugt der Server automatisch alle Zugangsdaten und Profile
und zeigt pro Betriebssystem eine Schritt-für-Schritt-Anleitung an.

## Funktionsumfang der Weboberfläche

- Einrichtungsassistent (Admin-Passwort, öffentliche Adresse mit „IP ermitteln“, DNS)
- Clients anlegen, sperren, löschen (Zertifikate werden widerrufen, Verbindungen getrennt)
- Pro Client: **WireGuard-QR-Code**, `.conf`, `.ovpn`, `.p12`, `.mobileconfig`, `.sswan`,
  Windows-Einrichtungsskripte (IKEv2, SSTP, L2TP, PPTP), Zugangsdaten als TXT/JSON, alles als ZIP
- **Teilen-Link mit QR-Code**: Profile direkt auf dem Handy öffnen (24 h gültig, nur im Heimnetz)
- Split-Tunnel (nur Heimnetz) oder kompletter Internetverkehr pro Client
- **Übersicht** mit Live-Durchsatz (Download/Upload, letzte 5 Minuten), Kennzahlen, Systemlast
  (CPU, RAM, Datenträger, Temperatur) und **Netzwerkplan** (Internet → Router → Server → Netze/VLANs
  → verbundene Geräte)
- **Statistik**: Datenvolumen für 24 Stunden, 7 und 30 Tage – gesamt, je Benutzer und je VLAN
- **Verbindungen**: Live-Liste mit „Trennen“, **Verbindungsprotokoll** (wer war wann wie lange
  verbunden, mit Datenvolumen), Dienste mit Protokollanzeige
- **Werkzeuge**: Ping, Traceroute, DNS-Abfrage, Speedtest (Server ↔ Internet), Wake-on-LAN mit
  gespeicherten Geräten, Paketmitschnitt als `.pcap` für Wireshark
- Hell/Dunkel automatisch, für Handy optimiert
- Protokolle einzeln an-/abschalten, Ports und Adressbereiche ändern
- **DynDNS** (DuckDNS, dynv6, IPv64, No-IP/DynDNS2, eigene URL)
- **Let's Encrypt** (optional) für SSTP, OpenConnect und die Weboberfläche
- **RADIUS-Anmeldung** (externer RADIUS-Server, z. B. Windows NPS) und **VLAN-Zuweisung** wie beim
  WLAN-Controller (siehe unten)
- Netzwerk (DHCP/statische IP), Updates, Sicherung/Wiederherstellung, Neustart
- Automatische Sicherheitsupdates, Firewall (nftables), Weboberfläche und SSH standardmäßig
  nur aus dem Heimnetz bzw. über VPN erreichbar

## Installation

1. **ISO herunterladen** – unter *Releases* dieses Repositorys
   (`vpn-server-<version>-debian13-amd64.iso`, Prüfsumme in `.sha256`).
2. **USB-Stick erstellen** – z. B. mit [balenaEtcher](https://etcher.balena.io/), Rufus (DD-Modus)
   oder `sudo dd if=vpn-server-….iso of=/dev/sdX bs=4M status=progress`.
   Für virtuelle Maschinen (Proxmox, VirtualBox, Hyper-V, VMware) das ISO direkt einbinden.
3. **Starten** und im Menü **„VPN-Server automatisch installieren“** wählen.
   - ⚠️ Die **erste Festplatte wird vollständig gelöscht**.
   - Für mehrere Festplatten/Netzwerkkarten: „Festplatte und Netzwerk selbst wählen“.
   - Der Server braucht während der Installation **Internet per Netzwerkkabel (DHCP)**.
   - Dauer: ca. 10–20 Minuten, ohne weitere Eingaben. Danach startet der Server neu
     (USB-Stick entfernen).
4. Nach dem Start zeigt der **Bildschirm des Servers** die Adresse der Weboberfläche und das
   **Initialpasswort**:

   ```
   Weboberflaeche:   https://192.168.178.50:8443
                     https://vpn-server.local:8443
   Benutzer:         admin
   Initialpasswort:  aB3dE5fG7h
   ```
5. Weboberfläche im Browser öffnen (Zertifikatswarnung beim ersten Aufruf bestätigen),
   anmelden und dem **Einrichtungsassistenten** folgen.

Mindestanforderungen: x86-64 (64 Bit), 1 GB RAM, 8 GB Speicher, Netzwerkkarte.
UEFI (auch Secure Boot) und BIOS werden unterstützt.

### Alternative: Installation auf einem vorhandenen Server (z. B. VPS)

Auf einem frischen Debian 13 oder Ubuntu 24.04:

```bash
git clone https://github.com/rschulzgit/vpn-server.git
cd vpn-server
sudo ./installer/install.sh --public-host meinvpn.example.org
```

## Portfreigaben am Router

Die Weboberfläche zeigt die exakt benötigte Liste. Standard (alle Protokolle außer PPTP):

| Dienst | Protokoll | Port |
|---|---|---|
| WireGuard | UDP | 51820 |
| OpenVPN | UDP | 1194 |
| OpenVPN (TCP-Fallback) | TCP | 1194 |
| IPsec (IKEv2, L2TP/IPsec, Cisco IPsec) | UDP | 500 und 4500 |
| SSTP | TCP | 443 |
| OpenConnect (AnyConnect-kompatibel) | TCP + UDP | 4443 |
| *PPTP (nur falls aktiviert)* | *TCP 1723 + GRE* | |
| *Let's Encrypt (nur falls aktiviert)* | *TCP* | *80* |

Alle Freigaben zeigen auf die LAN-IP des Servers. **UDP 1701 (L2TP) nicht freigeben** – L2TP läuft
verschlüsselt innerhalb von IPsec. Die Weboberfläche (8443) und SSH (22) sollten **nicht**
freigegeben werden – für die Verwaltung von unterwegs einfach per VPN verbinden.

**FRITZ!Box:** *Internet → Freigaben → Portfreigaben → Gerät für Freigaben hinzufügen* → Server
auswählen → *Neue Freigabe* → *Portfreigabe* → je Zeile Protokoll und Port eintragen. Unter
*Heimnetz → Netzwerk* beim Server „Diesem Netzwerkgerät immer die gleiche IPv4-Adresse
zuweisen“ aktivieren. Einen DynDNS-Namen liefert z. B. *MyFRITZ!* (Adresse `xyz.myfritz.net`).

### Wichtig: DS-Lite / CGNAT

Viele Kabel- und Glasfaseranschlüsse (z. B. Vodafone Kabel, teilweise Telekom-Glasfaser, O2)
haben **keine eigene öffentliche IPv4-Adresse** („DS-Lite“). Dann sind IPv4-Portfreigaben
technisch unmöglich. Abhilfe: beim Provider einen „echten“ IPv4-/Dual-Stack-Anschluss
anfragen (oft kostenlos), oder den Server auf einem VPS installieren.

## Empfehlungen je Gerät

| Gerät | Empfehlung | Alternative ohne App |
|---|---|---|
| Android | WireGuard (QR-Code) | IKEv2/IPSec PSK oder RSA |
| iPhone/iPad | WireGuard (QR-Code) | IKEv2-Profil (`.mobileconfig`) |
| Windows | WireGuard | IKEv2- oder SSTP-Skript |
| macOS | WireGuard | IKEv2-Profil |
| Linux | WireGuard | NetworkManager (OpenVPN, IKEv2, OpenConnect …) |
| Firmennetz/Hotel mit strenger Firewall | SSTP (TCP 443), OpenConnect, OpenVPN TCP | |

## RADIUS-Anmeldung und VLANs (wie beim WLAN-Controller)

*Einstellungen → RADIUS / VLANs*

**RADIUS:** Benutzer melden sich mit den Zugangsdaten eines vorhandenen RADIUS-Servers an
(Windows NPS mit Active Directory, FreeRADIUS, UniFi, Synology …). Das gilt für alle Verfahren
mit Benutzername/Passwort: IKEv2 (EAP-MSCHAPv2), Cisco IPsec, L2TP/IPsec, SSTP, PPTP und
OpenConnect. Lokale Clients können zusätzlich erlaubt bleiben (werden zuerst geprüft). Ein
Ausweich-Server und Accounting werden unterstützt; der Verbindungstest in der Weboberfläche zeigt
das zugewiesene VLAN. Für RADIUS-Benutzer gibt es **Profile ohne gespeicherte Zugangsdaten**
(`.mobileconfig`, `.sswan`, Windows-Skripte), die an alle verteilt werden können.

Auf dem RADIUS-Server den VPN-Server als RADIUS-Client (NAS) mit seiner LAN-IP und dem
gemeinsamen Geheimnis eintragen und MS-CHAPv2/EAP-MSCHAPv2 (sowie PAP für OpenConnect und
Cisco IPsec) erlauben. NAS-Port-Type ist `Virtual`, der NAS-Identifier ist einstellbar.

**VLAN-Zuweisung:** Der RADIUS-Server liefert – genau wie für WLAN-Clients –
`Tunnel-Type = VLAN`, `Tunnel-Medium-Type = IEEE-802`, `Tunnel-Private-Group-Id = <VLAN-ID>`.
Der VPN-Benutzer landet dann in diesem VLAN: Er erhält eine Adresse aus dem VPN-Bereich des
VLANs, sein Verkehr verlässt den Server über die VLAN-Schnittstelle (802.1Q, mit NAT auf die
Server-Adresse im VLAN) und er erreicht **nur dieses VLAN** bzw. über dessen Gateway das
Internet – nicht das übrige Heimnetz, andere VLANs oder die Weboberfläche.

- Voraussetzung: Der Switch-Port des Servers ist ein **Trunk** mit den VLANs als *tagged*.
- Pro VLAN: ID, Name, Netzwerkkarte, Server-Adresse – **fest** (mit optionalem Gateway) oder
  **automatisch per DHCP** (Adresse und Gateway vom DHCP-Server des VLANs; ein eigener
  DHCP-Client je VLAN verändert weder die Default-Route des Servers noch dessen DNS) – sowie
  DNS-Server für die VPN-Clients.
- Lokale Clients bekommen ihr VLAN in der Weboberfläche – auch für WireGuard, OpenVPN und
  IKEv2 mit Zertifikat/PSK, die ohne RADIUS auskommen.
- Nicht eingerichtete VLAN-IDs werden standardmäßig abgelehnt (einstellbar), RADIUS-Benutzer
  ohne VLAN landen im Standardnetz (einstellbar). Eigene Adressvorgaben des RADIUS-Servers
  (Framed-IP-Address, Class …) werden ignoriert.
- Bis zu 8 VLANs; je VLAN und Protokoll ca. 30 gleichzeitige Verbindungen, OpenVPN 14 Geräte
  (größere Bereiche über die erweiterten Einstellungen).

Technik: Ein lokaler FreeRADIUS (`vpn-radius.service`, nur auf 127.0.0.1) prüft lokale Benutzer,
leitet andere an den externen Server weiter und übersetzt die VLAN-Zuweisung für strongSwan
(Gruppe), accel-ppp (Adresspool) und ocserv (Gruppe). Accounting wird sofort lokal bestätigt und
an den externen Server kopiert, damit ein nicht erreichbarer Accounting-Server keine Verbindung
trennt.

## Software-Update

*System → Updates* aktualisiert die Anwendung aus diesem Repository – standardmäßig auf
das **neueste Release** (geprüfte Stände, kein Token nötig). Alternativ kann ein Branch gewählt
werden; für private Forks bzw. Repositorys lässt sich optional ein GitHub-Token (nur Lesezugriff)
hinterlegen. Ablauf: Download → Prüfung → Sicherung des bisherigen Stands → Installation (inkl.
neuer Pakete und Dienste) → Funktionsprüfung. Schlägt etwas fehl, wird der vorherige Stand
automatisch wiederhergestellt; manuell geht das jederzeit per „Vorherige Version wiederherstellen“.
Auf Wunsch prüft der Server täglich und installiert Updates automatisch. Einstellungen, Clients
und Schlüssel bleiben dabei erhalten. Kommandozeile: `vpnctl update check|install|rollback|status`.

Sicherheitsupdates des Betriebssystems installiert Debian unabhängig davon automatisch.

## Kommandozeile (`vpnctl`)

Auf der Konsole bzw. per SSH als `vpnadmin`:

```bash
sudo vpnctl status                        # Dienste und Verbindungen
sudo vpnctl client add max-handy          # Client anlegen, Zugangsdaten anzeigen
sudo vpnctl client export max-handy wireguard -o max.conf
sudo vpnctl client del max-handy
sudo vpnctl set public-host meinvpn.duckdns.org
sudo vpnctl admin-password                # Admin-Passwort der Weboberfläche zurücksetzen
```

Konfiguration und Schlüssel liegen in `/etc/vpn-server/` (Zustand in `state.json`, PKI in `pki/`).
Die Konfigurationsdateien der Dienste werden daraus erzeugt – manuelle Änderungen daran werden
überschrieben. Eigene Firewall-Regeln: `/etc/vpn-server/nftables-local-*.nft`.

## Sicherheit

- Eigene Zertifizierungsstelle pro Installation (RSA, SHA-256), Client-Zertifikate werden beim
  Sperren/Löschen widerrufen (CRL für OpenVPN und strongSwan).
- Moderne Verschlüsselung (AES-GCM, ChaCha20, ECDH); ältere Algorithmen nur dort, wo
  Betriebssystem-Clients sie zwingend benötigen (Windows-IKEv2-Standard, L2TP, Cisco IPsec).
- Weboberfläche: TLS, Anmeldung mit scrypt-Passworthash, CSRF-Schutz, Sperre nach
  Fehlversuchen, strikte Content-Security-Policy.
- PPTP ist standardmäßig deaktiviert (kryptografisch gebrochen).

## Selbst bauen

Das ISO wird per GitHub Actions gebaut (`.github/workflows/iso.yml`) und bei jedem Lauf
automatisch getestet (`tests/e2e/`):

- **Installationsmedium:** Bootmenü unter BIOS (isolinux) und UEFI mit Secure Boot (GRUB)
- **Installation:** vollautomatisch in einer VM (UEFI), Neustart mit Secure Boot, Erststart,
  Initialpasswort auf der Konsole, Weboberfläche erreichbar
- **Weboberfläche:** Anmeldung, Assistent, Clients, alle Profile (51 Dateien), Sicherheitsheader,
  CSRF, TLS
- **Geräte** – nachgebildet mit Linux-Clients, die Identitäten, Anmeldeverfahren und
  Krypto-Vorschläge des jeweiligen Geräts verwenden bzw. dessen Profil direkt auswerten:
  WireGuard per QR-Code und Split-Tunnel, OpenVPN UDP mit TCP-Fallback, IKEv2 für Android
  (PSK, RSA, MSCHAPv2), strongSwan-App (.sswan), iPhone/Mac (.mobileconfig, manuell),
  Windows (Skript-Krypto, Standard-Krypto, Maschinenzertifikat), Linux, Cisco IPsec,
  L2TP/IPsec, SSTP, OpenConnect mit DTLS und TCP-Fallback; jeweils Heimnetz, Internet und
  DNS durch den Tunnel
- **Profile:** QR-Code wird dekodiert und verglichen, Windows-Skripte laufen in PowerShell mit
  nachgebildeten Windows-Befehlen, PKCS#12/.mobileconfig/.sswan werden geprüft
- **RADIUS/VLAN:** externer FreeRADIUS mit VLAN-Attributen, VLAN-Trunk an der Test-VM;
  RADIUS-Benutzer per IKEv2, Cisco IPsec, L2TP, SSTP und OpenConnect sowie lokale Geräte per
  WireGuard, OpenVPN, SSTP und IKEv2-Zertifikat landen im richtigen VLAN; VLAN mit Adresse per
  DHCP (dnsmasq im Test-VLAN, auch nach Neustart); Isolation, Ablehnungen, Accounting
- **Statistik & Werkzeuge:** Durchsatz und Datenvolumen je Client werden bei echtem Verkehr
  erfasst, Verbindungsprotokoll, Ping/DNS/Wake-on-LAN/Paketmitschnitt über die Weboberfläche
- **Funktionen:** Client-zu-Client, Heimnetz-Sperre, Protokolle an/aus, Passwortwechsel,
  Sperren/Entsperren, Schlüssel erneuern, Löschen, Teilen-Link, Sicherung, `vpnctl`, Neustart

Ein Tag `v*` veröffentlicht das ISO als Release – nur wenn alle Tests bestanden sind. Alternativ:
*Actions → ISO bauen und testen → Run workflow* mit `release_tag` (z. B. `v1.0.0`) und optional
dem zu veröffentlichenden `commit`.

Lokal (Debian/Ubuntu mit Internetzugang):

```bash
sudo apt install xorriso curl docker.io
./iso/build-iso.sh --build-accel        # Ergebnis in ./build/
python3 -m pytest tests                 # Unit-Tests
```

## Projektstruktur

```
vpnserver/            Python-Paket: Zustand, PKI, Konfig-Generatoren, Profile, Weboberfläche, vpnctl
vpnserver/templates/  Vorlagen der Dienstkonfigurationen (WireGuard, OpenVPN, strongSwan, accel-ppp, ocserv, nftables)
installer/            install.sh, accel-ppp-Build, systemd-Units
iso/                  ISO-Bau (Debian-Netinst + Preseed + Bootmenü)
tests/                Unit-Tests und End-to-End-Test (QEMU)
```

## Mitwirken

Fehlerberichte, Vorschläge und Pull Requests sind willkommen – Ablauf, Tests (pytest, shellcheck)
und die End-to-End-Prüfung in der CI beschreibt [CONTRIBUTING.md](CONTRIBUTING.md). Beiträge
werden unter der GPL-3.0-or-later veröffentlicht. Sicherheitslücken bitte vertraulich melden:
[SECURITY.md](SECURITY.md).

## Projekt unterstützen

Wenn Ihnen das Projekt nützt, können Sie die Weiterentwicklung über
[GitHub Sponsors](https://github.com/sponsors/rschulzgit) unterstützen.

## Lizenz

Copyright (C) 2026 rschulzgit und Mitwirkende.

VPN-Server ist freie Software: Sie können es unter den Bedingungen der
[GNU General Public License](LICENSE), Version 3 oder (nach Ihrer Wahl) jeder späteren Version,
weitergeben und/oder verändern (SPDX: `GPL-3.0-or-later`). Die Software wird ohne jede
Gewährleistung bereitgestellt.

Im ISO enthaltene bzw. bei der Installation geladene Fremdkomponenten (Debian, accel-ppp,
strongSwan, OpenVPN, WireGuard-Tools, ocserv, FreeRADIUS u. a.), ihre Lizenzen und Quellen:
[THIRD_PARTY.md](THIRD_PARTY.md).

### Name und Logo

Der Name „VPN-Server“ und das Logo dürfen nur für **unveränderte Originalversionen** verwendet
werden. Veränderte Versionen und Forks müssen einen **anderen Namen und ein anderes Logo**
verwenden. Details: [TRADEMARKS.md](TRADEMARKS.md) (keine Rechtsberatung).

Genannte Marken Dritter (z. B. Windows, macOS, iOS, Android, FRITZ!Box, Cisco/AnyConnect,
WireGuard, OpenVPN) gehören ihren Inhabern; sie werden nur beschreibend verwendet, eine Verbindung
zu den Inhabern besteht nicht.
