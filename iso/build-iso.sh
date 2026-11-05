#!/bin/bash
# Baut das VPN-Server-Installations-ISO auf Basis des offiziellen Debian-13-Netinst-Images.
#
#   iso/build-iso.sh [Optionen]
#     --output DIR        Ausgabeverzeichnis (Standard: ./build)
#     --debian-iso PATH   Vorhandenes Debian-Netinst-ISO verwenden (statt Download)
#     --accel-deb PATH    Vorgebautes accel-ppp.deb (Debian 13) einbetten
#     --build-accel       accel-ppp.deb per Docker (debian:trixie) bauen und einbetten
#     --e2e               Testvariante: Installer schaltet am Ende aus statt neu zu starten
#     --version VER       Versionsbezeichnung (Standard: aus vpnserver/__init__.py)
#
# Benoetigt: curl, xorriso, openssl, sha256sum (optional: gpgv + debian-keyring, docker)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build"
DEBIAN_ISO=""
ACCEL_DEB=""
BUILD_ACCEL=0
E2E=0
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/vpnserver/__init__.py")"
DEBIAN_CD_BASES=(
  "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd"
  "https://cdimage.debian.org/cdimage/archive/latest-oldstable/amd64/iso-cd"
)

while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT="$2"; shift ;;
    --debian-iso) DEBIAN_ISO="$2"; shift ;;
    --accel-deb) ACCEL_DEB="$2"; shift ;;
    --build-accel) BUILD_ACCEL=1 ;;
    --e2e) E2E=1 ;;
    --version) VERSION="$2"; shift ;;
    -h|--help) sed -n 2,13p "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
  shift
done

log() { echo -e "\033[1;34m>>>\033[0m $*"; }
for tool in curl xorriso openssl sha256sum md5sum; do
  command -v "$tool" >/dev/null || { echo "Fehlt: $tool" >&2; exit 1; }
done

mkdir -p "$OUT/cache"
OUT="$(cd "$OUT" && pwd)"
[ -n "$DEBIAN_ISO" ] && DEBIAN_ISO="$(readlink -f "$DEBIAN_ISO")"
STAGE="$(mktemp -d "$OUT/stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# ---------------------------------------------------------------------------
# 1. Debian-Netinst-ISO besorgen und pruefen
# ---------------------------------------------------------------------------
if [ -z "$DEBIAN_ISO" ]; then
  for base in "${DEBIAN_CD_BASES[@]}"; do
    if curl -fsSL "$base/SHA256SUMS" -o "$STAGE/SHA256SUMS"; then
      ISO_NAME="$(grep -oE 'debian-13\.[0-9.]+-amd64-netinst\.iso' "$STAGE/SHA256SUMS" | head -1 || true)"
      if [ -n "$ISO_NAME" ]; then
        BASE="$base"
        break
      fi
    fi
  done
  [ -n "${ISO_NAME:-}" ] || { echo "Debian-13-Netinst-ISO nicht gefunden" >&2; exit 1; }
  if command -v gpgv >/dev/null && [ -f /usr/share/keyrings/debian-role-keys.gpg ]; then
    curl -fsSL "$BASE/SHA256SUMS.sign" -o "$STAGE/SHA256SUMS.sign"
    gpgv --keyring /usr/share/keyrings/debian-role-keys.gpg "$STAGE/SHA256SUMS.sign" "$STAGE/SHA256SUMS"
    log "GPG-Signatur der Pruefsummen ist gueltig"
  else
    log "Hinweis: gpgv/debian-keyring fehlt - pruefe nur die SHA256-Summe"
  fi
  DEBIAN_ISO="$OUT/cache/$ISO_NAME"
  if [ ! -f "$DEBIAN_ISO" ]; then
    log "Lade $ISO_NAME"
    curl -fL --retry 3 -o "$DEBIAN_ISO.part" "$BASE/$ISO_NAME"
    mv "$DEBIAN_ISO.part" "$DEBIAN_ISO"
  fi
  (cd "$OUT/cache" && grep " $ISO_NAME\$" "$STAGE/SHA256SUMS" | sha256sum -c -)
fi
log "Basis: $(basename "$DEBIAN_ISO")"

# ---------------------------------------------------------------------------
# 2. Payload (Anwendung + Installer + accel-ppp)
# ---------------------------------------------------------------------------
PAY="$STAGE/vpn-server"
mkdir -p "$PAY/payload"
cp -a "$ROOT/vpnserver" "$ROOT/installer" "$PAY/"
cp -a "$ROOT/README.md" "$PAY/" 2>/dev/null || true
find "$PAY" -name '__pycache__' -prune -exec rm -rf {} +

if [ "$BUILD_ACCEL" = 1 ] && [ -z "$ACCEL_DEB" ]; then
  log "Baue accel-ppp.deb in debian:trixie (Docker)"
  mkdir -p "$STAGE/accel"
  docker run --rm -v "$ROOT/installer:/src:ro" -v "$STAGE/accel:/out" debian:trixie \
    bash -c "apt-get update -qq && bash /src/build-accel-ppp.sh deb /out"
  ACCEL_DEB="$STAGE/accel/accel-ppp.deb"
fi
if [ -n "$ACCEL_DEB" ]; then
  cp "$ACCEL_DEB" "$PAY/payload/accel-ppp.deb"
  log "accel-ppp.deb eingebettet"
else
  log "Kein accel-ppp.deb - wird bei der Installation aus den Quellen gebaut"
fi
echo "$VERSION" > "$PAY/VERSION"

# ---------------------------------------------------------------------------
# 3. Preseed-Dateien und Bootmenues
# ---------------------------------------------------------------------------
PWHASH="$(openssl rand -base64 24 | openssl passwd -6 -stdin)"
sed "s|@@PWHASH@@|$PWHASH|; s|@@PARTMAN@@|gesamte erste Festplatte|" "$ROOT/iso/preseed.cfg" > "$STAGE/preseed.cfg"
# Manuelle Variante: Partitionierung und Netzwerkkarte werden abgefragt
grep -vE '^d-i (partman|netcfg/choose_interface)' "$STAGE/preseed.cfg" \
  | sed 's|(gesamte erste Festplatte)|(wird abgefragt)|' > "$STAGE/preseed-manual.cfg"
echo "d-i partman/mount_style select uuid" >> "$STAGE/preseed-manual.cfg"
if [ "$E2E" = 1 ]; then
  for f in preseed.cfg preseed-manual.cfg; do
    {
      echo "d-i debian-installer/exit/poweroff boolean true"
      echo "d-i finish-install/keep-consoles boolean true"
    } >> "$STAGE/$f"
  done
fi
cp "$ROOT/iso/grub.cfg" "$STAGE/grub.cfg"
cp "$ROOT/iso/isolinux.cfg" "$STAGE/isolinux.cfg"

MAPS=(
  -map "$PAY" /vpn-server
  -map "$STAGE/preseed.cfg" /preseed.cfg
  -map "$STAGE/preseed-manual.cfg" /preseed-manual.cfg
  -map "$STAGE/grub.cfg" /boot/grub/grub.cfg
)
if xorriso -indev "$DEBIAN_ISO" -find /isolinux/isolinux.cfg 2>/dev/null | grep -q isolinux.cfg; then
  MAPS+=(-map "$STAGE/isolinux.cfg" /isolinux/isolinux.cfg)
fi

# md5sum.txt aktualisieren (fuer die Integritaetspruefung des Installers)
xorriso -osirrox on -indev "$DEBIAN_ISO" -extract /md5sum.txt "$STAGE/md5sum.orig" 2>/dev/null
chmod u+w "$STAGE/md5sum.orig"
grep -vE '  \./(vpn-server/|preseed|boot/grub/grub\.cfg$|isolinux/isolinux\.cfg$)' "$STAGE/md5sum.orig" > "$STAGE/md5sum.txt" || true
(
  cd "$STAGE"
  find vpn-server -type f -print0 | sort -z | xargs -0 md5sum | sed 's|  |  ./|'
  md5sum preseed.cfg preseed-manual.cfg | sed 's|  |  ./|'
  echo "$(md5sum < grub.cfg | cut -d' ' -f1)  ./boot/grub/grub.cfg"
  echo "$(md5sum < isolinux.cfg | cut -d' ' -f1)  ./isolinux/isolinux.cfg"
) >> "$STAGE/md5sum.txt"
MAPS+=(-map "$STAGE/md5sum.txt" /md5sum.txt)

# ---------------------------------------------------------------------------
# 4. ISO schreiben (Bootkonfiguration BIOS + UEFI wird uebernommen)
# ---------------------------------------------------------------------------
SUFFIX=""
[ "$E2E" = 1 ] && SUFFIX="-e2e"
OUT_ISO="$OUT/vpn-server-${VERSION}-debian13-amd64${SUFFIX}.iso"
rm -f "$OUT_ISO"
log "Schreibe $(basename "$OUT_ISO")"
xorriso -indev "$DEBIAN_ISO" -outdev "$OUT_ISO" "${MAPS[@]}" -boot_image any replay 2>&1 \
  | grep -vE '^(xorriso : UPDATE|Drive current|Media current|Media status|Media summary|Volume id|Boot record)' || true
[ -s "$OUT_ISO" ] || { echo "ISO wurde nicht erzeugt" >&2; exit 1; }
(cd "$OUT" && sha256sum "$(basename "$OUT_ISO")" > "$(basename "$OUT_ISO").sha256")
log "Fertig: $OUT_ISO ($(du -h "$OUT_ISO" | cut -f1))"
