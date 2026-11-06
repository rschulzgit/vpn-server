# Sicherheit

## Sicherheitslücke melden

Bitte melden Sie Sicherheitslücken **nicht** als öffentliches Issue, sondern
vertraulich über GitHubs **Private vulnerability reporting**:

1. Im Repository auf **Security → Report a vulnerability** gehen
   (direkt: <https://github.com/rschulzgit/vpn-server/security/advisories/new>).
2. Beschreiben, was betroffen ist, wie es sich nachvollziehen lässt und welche
   Auswirkungen Sie erwarten (z. B. Zugriff ohne Anmeldung, Umgehung der
   Firewall, Preisgabe von Schlüsseln).

Sie erhalten eine Rückmeldung über die Meldung auf GitHub. Bitte geben Sie uns
Zeit für eine Korrektur, bevor Details veröffentlicht werden. Ein Update wird
als neues Release bereitgestellt; installierte Server erhalten es über
*System → Software-Update*.

## Unterstützte Versionen

| Version | Sicherheitsupdates |
|---|---|
| neuestes Release (1.x) | ja |
| ältere Releases | nein – bitte aktualisieren |
| Entwicklungsstände (Branches) | nein |

Sicherheitsupdates der Debian-Pakete (strongSwan, OpenVPN, OpenSSL, Kernel …)
installiert der Server unabhängig davon automatisch über `unattended-upgrades`.

## Umfang

Gemeldet werden können Fehler in diesem Repository (Weboberfläche, `vpnctl`,
Installer, erzeugte Konfigurationen und Profile, ISO-Aufbau). Lücken in
Debian-Paketen oder accel-ppp bitte zusätzlich beim jeweiligen Projekt melden.
