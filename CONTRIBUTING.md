# Mitwirken

Beiträge sind willkommen – Fehlerberichte, Verbesserungsvorschläge,
Dokumentation und Code.

## Ablauf

1. Für größere Änderungen bitte zuerst ein **Issue** eröffnen und den Ansatz
   kurz abstimmen.
2. Repository forken, einen Branch anlegen und die Änderung möglichst klein und
   in sich geschlossen halten.
3. Tests ergänzen bzw. anpassen (siehe unten) und lokal ausführen.
4. Pull Request stellen und die Vorlage ausfüllen. Die CI baut das ISO und
   führt die vollständige End-to-End-Prüfung aus; ein PR wird erst nach
   erfolgreichem Lauf übernommen.

Sicherheitslücken bitte **nicht** als Issue melden, sondern wie in
[SECURITY.md](SECURITY.md) beschrieben.

## Tests

Lokal (Debian/Ubuntu, Python 3.11+):

```bash
sudo apt install python3-flask python3-qrcode python3-cryptography python3-jinja2 \
  python3-pytest python3-gunicorn shellcheck nftables
sudo python3 -m pytest -q tests
shellcheck -S warning installer/*.sh iso/build-iso.sh tests/e2e/run.sh
```

Die **End-to-End-Tests** (`tests/e2e/`) laufen in der CI
(`.github/workflows/iso.yml`): Das ISO wird gebaut, in QEMU unter BIOS und
UEFI/Secure Boot gebootet, vollautomatisch installiert und anschließend mit
nachgebildeten Endgeräten für alle Protokolle getestet (inkl. RADIUS/VLAN,
Statistik, Werkzeuge und Selbst-Update). Lokal benötigen sie root, KVM und
einige Pakete – siehe `tests/e2e/run.sh`.

## Richtlinien

- Sprache der Oberfläche und Dokumentation: Deutsch.
- Keine neuen externen Abhängigkeiten in der Weboberfläche (kein CDN, strenge
  Content-Security-Policy, keine Inline-Skripte oder -Styles).
- Konfigurationsdateien der Dienste werden aus `vpnserver/templates/conf/`
  erzeugt – Änderungen dort, nicht in den erzeugten Dateien.
- Keine Geheimnisse, Zugangsdaten oder personenbezogenen Daten committen.

## Lizenz der Beiträge

Mit einem Beitrag erklären Sie sich einverstanden, dass er unter der
**GNU General Public License, Version 3 oder später (GPL-3.0-or-later)**
veröffentlicht wird – derselben Lizenz wie das Projekt. Bitte reichen Sie nur
Code ein, an dem Sie die nötigen Rechte haben.
