#!/bin/bash
# Baut accel-ppp (SSTP, L2TP, PPTP) aus den Quellen.
#
#   build-accel-ppp.sh deb  <Ausgabeverzeichnis>   -> erzeugt accel-ppp.deb (Debian/Ubuntu)
#   build-accel-ppp.sh install                    -> baut und installiert direkt
#
# Optional: ACCEL_PPP_SRC=/pfad/zu/accel-ppp.tar.gz (sonst git clone der festen Version)
set -euo pipefail

ACCEL_PPP_VERSION="${ACCEL_PPP_VERSION:-1.15.0}"
ACCEL_PPP_REPO="${ACCEL_PPP_REPO:-https://github.com/accel-ppp/accel-ppp.git}"
MODE="${1:-deb}"
OUT="${2:-$PWD}"

export DEBIAN_FRONTEND=noninteractive
BUILD_DEPS="build-essential cmake libssl-dev libpcre2-dev pkgconf git ca-certificates"

. /etc/os-release
case "${ID}:${VERSION_ID%%.*}" in
  debian:13) CPACK_TYPE=Debian13 ;;
  debian:12) CPACK_TYPE=Debian12 ;;
  ubuntu:24) CPACK_TYPE=Ubuntu24 ;;
  ubuntu:22) CPACK_TYPE=Ubuntu22 ;;
  *) CPACK_TYPE="" ;;
esac

echo ">>> Installiere Build-Abhaengigkeiten"
apt-get install -y --no-install-recommends $BUILD_DEPS >/dev/null

WORK="$(mktemp -d /tmp/accel-ppp-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "${ACCEL_PPP_SRC:-}" ] && [ -f "$ACCEL_PPP_SRC" ]; then
  echo ">>> Entpacke $ACCEL_PPP_SRC"
  mkdir -p "$WORK/src"
  tar -xzf "$ACCEL_PPP_SRC" -C "$WORK/src" --strip-components=1
else
  echo ">>> Lade accel-ppp $ACCEL_PPP_VERSION"
  git clone --quiet --depth 1 --branch "$ACCEL_PPP_VERSION" "$ACCEL_PPP_REPO" "$WORK/src"
fi

mkdir -p "$WORK/src/build"
cd "$WORK/src/build"
CMAKE_ARGS=(
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX=/usr
  -DBUILD_IPOE_DRIVER=FALSE
  -DBUILD_VLAN_MON_DRIVER=FALSE
  -DRADIUS=TRUE
  -DNETSNMP=FALSE
  -DLUA=FALSE
  -DSHAPER=FALSE
  -DLOG_PGSQL=FALSE
  -DIGNORE_GIT=TRUE
)
[ -n "$CPACK_TYPE" ] && CMAKE_ARGS+=(-DCPACK_TYPE="$CPACK_TYPE")

echo ">>> Konfiguriere (cmake ${CPACK_TYPE:-generic})"
cmake "${CMAKE_ARGS[@]}" .. >/dev/null
echo ">>> Kompiliere"
make -j"$(nproc)" >/dev/null

if [ "$MODE" = "deb" ]; then
  if [ -z "$CPACK_TYPE" ]; then
    echo "Kein Paketformat fuer ${ID} ${VERSION_ID} bekannt" >&2
    exit 1
  fi
  cpack -G DEB >/dev/null
  mkdir -p "$OUT"
  cp -v ./*.deb "$OUT/accel-ppp.deb"
else
  make install >/dev/null
  install -d /var/log/accel-ppp /var/lib/accel-ppp
  echo ">>> accel-ppp installiert: $(command -v accel-pppd)"
fi
