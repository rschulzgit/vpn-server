# VPN-Server – ein ISO, alle gängigen VPN-Protokolle, Einrichtung per Weboberfläche

Ein bootfähiges Installations-ISO (Basis: **Debian 13 „trixie“**), das einen kompletten
VPN-Server vollautomatisch installiert. Danach erfolgt alles über eine deutschsprachige
Weboberfläche – Sie müssen am Router nur noch die angezeigten **Portfreigaben** einrichten.

## Unterstützte Protokolle

| Protokoll | Server-Software | Clients (Auswahl) | Anmeldung |
|---|---|---|---|
| **WireGuard** (empfohlen) | Linux-Kernel | WireGuard-App für Android, iOS, Windows, macOS, Linux – **QR-Code** | Schlüssel |
| **OpenVPN** UDP + TCP | OpenVPN 2.6 | OpenVPN Connect, OpenVPN for Android, Tunnelblick, NetworkManager | Zertifikat (in `.ovpn`) |
| **IKEv2/IPsec** | strongSwan | Android ohne App („IKEv2/IPSec **PSK**“, „**RSA**“ = Zertifikat, „MSCHAPv2“), iOS/macOS (Profil `.mobileconfig`), Windows (Einrichtungsskript), strongSwan-App (`.sswan`) | Zertifikat, PSK oder Benutzer/Passwort |
| **L2TP/IPsec** | strongSwan + accel-ppp | Windows, macOS, iOS, Android ≤ 11 | PSK + Benutzer/Passwort |
| **Cisco IPsec** (IKEv1 XAuth) | strongSwan | iOS/macOS „IPsec“, Android ≤ 11 | PSK + Benutzer/Passwort |
| **SSTP** | accel-ppp | Windows (eingebaut), Open SSTP Client (Android), sstp-client (Linux) | Benutzer/Passwort |
| **OpenConnect / Cisco AnyConnect** | ocserv | Cisco Secure Client, OpenConnect | Benutzer/Passwort |
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
- Live-Status aller Verbindungen und Dienste, Protokollanzeige
- Protokolle einzeln an-/abschalten, Ports und Adressbereiche ändern
- **DynDNS** (DuckDNS, dynv6, IPv64, No-IP/DynDNS2, eigene URL)
- **Let's Encrypt** (optional) für SSTP, OpenConnect und die Weboberfläche
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
| OpenConnect / AnyConnect | TCP + UDP | 4443 |
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
