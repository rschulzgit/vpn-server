#!/bin/bash
# VPN-Server - Installation auf Debian 13 (trixie) oder Ubuntu 24.04
#
#   sudo ./installer/install.sh            Installation auf einem bestehenden System
#   ./installer/install.sh --iso           Aufruf durch den ISO-Installer (chroot, ohne Dienste-Start)
#
# Optionen:
#   --public-host NAME   Oeffentliche Adresse direkt setzen (sonst im Einrichtungsassistenten)
#   --no-accel           accel-ppp (SSTP/L2TP/PPTP) nicht installieren
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/vpn-server
MODE=standalone
PUBLIC_HOST=""
WITH_ACCEL=1

while [ $# -gt 0 ]; do
  case "$1" in
    --iso) MODE=iso ;;
    --public-host) PUBLIC_HOST="$2"; shift ;;
    --no-accel) WITH_ACCEL=0 ;;
    -h|--help) sed -n 2,12p "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
  shift
done

# Gesamte Ausgabe zusaetzlich protokollieren (im ISO-Installer landet stdout sonst im Installer-Syslog)
mkdir -p /var/log
exec > >(tee -a /var/log/vpn-server-install.log) 2>&1
echo "=== VPN-Server-Installation $(date -Is) (Modus: $MODE) ==="

log() { echo -e "\033[1;34m>>>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!!\033[0m $*" >&2; }

[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausfuehren (sudo)." >&2; exit 1; }

. /etc/os-release
case "${ID}:${VERSION_ID}" in
  debian:13*|ubuntu:24.04*) ;;
  *) warn "Getestet mit Debian 13 und Ubuntu 24.04 - gefunden: ${PRETTY_NAME}. Fortfahren auf eigenes Risiko." ;;
esac

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Im chroot des Installers keine Dienste starten
if [ "$MODE" = iso ] && [ ! -e /usr/sbin/policy-rc.d ]; then
  printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
  chmod +x /usr/sbin/policy-rc.d
  trap 'rm -f /usr/sbin/policy-rc.d' EXIT
fi

# ocserv bringt einen Socket auf Port 443 mit, der mit SSTP kollidiert -> vorab maskieren
systemctl mask ocserv.socket >/dev/null 2>&1 || true

# Im ISO-Installer ist die CD zu diesem Zeitpunkt noch als Paketquelle eingetragen
# (Debian deaktiviert sie erst ganz am Ende) -> fuer apt deaktivieren
if [ "$MODE" = iso ]; then
  sed -i -E 's/^(deb|deb-src)[[:space:]]+cdrom:/# &/' /etc/apt/sources.list 2>/dev/null || true
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] && grep -q "cdrom:" "$f" && sed -i '/^URIs:.*cdrom:/a Enabled: no' "$f"
  done
fi

log "Paketlisten aktualisieren"
apt-get update

PACKAGES=(
  # VPN-Dienste
  wireguard-tools openvpn ocserv
  strongswan-swanctl charon-systemd libcharon-extauth-plugins libcharon-extra-plugins
  libstrongswan-extra-plugins libstrongswan-standard-plugins
  # RADIUS (externer RADIUS-Server, VLAN-Zuordnung)
  freeradius freeradius-utils
  # System
  nftables iproute2 kmod openssl ca-certificates curl sudo avahi-daemon
  unattended-upgrades certbot
  # Weboberflaeche
  python3 python3-flask python3-jinja2 python3-qrcode python3-cryptography python3-gunicorn
)
MISSING=()
for pkg in "${PACKAGES[@]}"; do
  apt-cache show "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "FEHLER: Pakete nicht verfuegbar: ${MISSING[*]}" >&2
  exit 100
fi
log "Installiere Pakete"
apt-get install "${APT_OPTS[@]}" --no-install-recommends "${PACKAGES[@]}"
# ocserv startet nach der Installation mit Standardport 443 -> stoppen, vpnctl konfiguriert es
systemctl stop ocserv.service >/dev/null 2>&1 || true
# Der Standard-FreeRADIUS lauscht auf allen Schnittstellen -> nicht verwenden
# (vpn-radius.service startet FreeRADIUS mit eigener Konfiguration nur auf 127.0.0.1)
systemctl disable --now freeradius.service >/dev/null 2>&1 || true
systemctl mask freeradius.service >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# accel-ppp (SSTP, L2TP, PPTP)
# ---------------------------------------------------------------------------
if [ "$WITH_ACCEL" = 1 ]; then
  if command -v accel-pppd >/dev/null 2>&1; then
    log "accel-ppp ist bereits installiert"
  elif [ -f "$SRC_DIR/payload/accel-ppp.deb" ] && [ "${ID}:${VERSION_ID%%.*}" = "debian:13" ]; then
    log "Installiere mitgeliefertes accel-ppp-Paket"
    apt-get install "${APT_OPTS[@]}" "$SRC_DIR/payload/accel-ppp.deb"
  else
    log "Baue accel-ppp aus den Quellen (dauert einige Minuten)"
    if [ -f "$SRC_DIR/payload/accel-ppp-src.tar.gz" ]; then
      export ACCEL_PPP_SRC="$SRC_DIR/payload/accel-ppp-src.tar.gz"
    fi
    if bash "$SRC_DIR/installer/build-accel-ppp.sh" deb /tmp/accel-ppp-pkg; then
      apt-get install "${APT_OPTS[@]}" /tmp/accel-ppp-pkg/accel-ppp.deb
    else
      bash "$SRC_DIR/installer/build-accel-ppp.sh" install
    fi
    rm -rf /tmp/accel-ppp-pkg
    apt-get purge -y cmake libssl-dev libpcre2-dev >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
  fi
  # Paketeigenen SysV-Dienst nicht verwenden
  systemctl disable accel-ppp >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Anwendung
# ---------------------------------------------------------------------------
log "Installiere VPN-Server nach $APP_DIR"
install -d -m 0755 "$APP_DIR"
rm -rf "$APP_DIR/vpnserver"
cp -a "$SRC_DIR/vpnserver" "$APP_DIR/"
find "$APP_DIR" -name '__pycache__' -prune -exec rm -rf {} +
install -m 0644 "$SRC_DIR/README.md" "$APP_DIR/README.md" 2>/dev/null || true

cat > /usr/local/sbin/vpnctl <<'EOF'
#!/bin/sh
export PYTHONPATH=/opt/vpn-server
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -m vpnserver.cli "$@"
EOF
chmod 0755 /usr/local/sbin/vpnctl

log "Richte systemd-Dienste ein"
install -m 0644 "$SRC_DIR"/installer/systemd/*.service "$SRC_DIR"/installer/systemd/*.timer /etc/systemd/system/
for d in ocserv.service.d wg-quick@.service.d; do
  install -d /etc/systemd/system/$d
  install -m 0644 "$SRC_DIR/installer/systemd/$d/vpn-server.conf" /etc/systemd/system/$d/
done
install -d -m 0711 /etc/vpn-server
install -d /etc/openvpn/server /etc/swanctl/conf.d /var/log/accel-ppp

# Standarddienste, die vpnctl selbst steuert, zunaechst deaktivieren
for unit in ocserv.service strongswan.service openvpn.service strongswan-starter.service ipsec.service; do
  systemctl disable "$unit" >/dev/null 2>&1 || true
done
systemctl mask ocserv.socket >/dev/null 2>&1 || true
# Debians strongswan.service laedt swanctl.conf; unsere Konfiguration liegt in conf.d (wird inkludiert)

# Automatische Sicherheitsupdates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# SSH-Haertung: kein Root-Login per Passwort
if [ -d /etc/ssh/sshd_config.d ]; then
  cat > /etc/ssh/sshd_config.d/10-vpn-server.conf <<'EOF'
PermitRootLogin prohibit-password
MaxAuthTries 4
EOF
fi

# Netzwerk beim Booten abwarten (statt allow-hotplug), damit der Server
# zuverlaessig mit Adresse startet
if [ -f /etc/network/interfaces ]; then
  sed -i 's/^allow-hotplug /auto /' /etc/network/interfaces
fi

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable nftables.service vpn-webui.service vpn-ddns.timer vpn-maintenance.timer avahi-daemon.service >/dev/null 2>&1 || true

if [ "$MODE" = iso ]; then
  systemctl enable vpn-firstboot.service >/dev/null 2>&1 || true
  # Installer lief auf Englisch -> System auf Deutsch umstellen
  if locale -a 2>/dev/null | grep -qi '^de_DE\.utf8$'; then
    update-locale LANG=de_DE.UTF-8 >/dev/null 2>&1 || true
  fi
  cat > /etc/issue <<'EOF'

  VPN-Server (\n) - Ersteinrichtung laeuft ...
  Die Zugangsdaten erscheinen hier in Kuerze (ggf. Enter druecken).

EOF
  log "Installation abgeschlossen - die Einrichtung erfolgt beim ersten Start."
  exit 0
fi

# ---------------------------------------------------------------------------
# Bestehendes System: sofort einrichten und starten
# ---------------------------------------------------------------------------
log "Ersteinrichtung"
if [ -n "$PUBLIC_HOST" ]; then
  /usr/local/sbin/vpnctl init --public-host "$PUBLIC_HOST"
else
  /usr/local/sbin/vpnctl init
fi
systemctl restart vpn-webui.service
systemctl start vpn-ddns.timer vpn-maintenance.timer >/dev/null 2>&1 || true

IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
echo
log "Fertig! Weboberflaeche: https://${IP:-<server-ip>}:8443"
echo "    Die Zugangsdaten stehen oben bzw. in /etc/issue."
