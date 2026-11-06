## VPN-Server – Installations-ISO (Debian 13)

**Download:** `vpn-server-…-debian13-amd64.iso` (Prüfsumme: `.sha256`)

1. ISO auf einen USB-Stick schreiben (balenaEtcher, Rufus im DD-Modus, `dd`) oder in einer VM einbinden.
2. Booten → **„VPN-Server automatisch installieren“** (⚠️ löscht die erste Festplatte; Internet per Kabel nötig).
3. Nach dem Neustart zeigt der Bildschirm die Adresse der Weboberfläche (`https://<IP>:8443`) und das Initialpasswort.
4. Im Browser anmelden, Assistent abschließen, die angezeigten **Portfreigaben** im Router einrichten, Clients anlegen.

Protokolle: WireGuard (QR-Code), OpenVPN UDP/TCP, IKEv2/IPsec (Zertifikat, PSK, EAP – Android ohne App), L2TP/IPsec,
Cisco IPsec (IKEv1 XAuth), SSTP, OpenConnect/AnyConnect, PPTP (optional, unsicher).

Optional: Anmeldung über einen vorhandenen RADIUS-Server (z. B. Windows NPS) und VLAN-Zuweisung
wie beim WLAN-Controller (Tunnel-Private-Group-Id), VLAN pro Client für WireGuard/OpenVPN.

Dieses ISO wurde automatisch in einer virtuellen Maschine installiert und mit echten Clients für alle Protokolle getestet.
Ausführliche Anleitung: siehe README im Repository.
