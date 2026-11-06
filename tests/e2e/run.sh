#!/bin/bash
# End-to-End-Test des Installations-ISOs:
#   0. Bootmenue-Test: BIOS (isolinux) und UEFI mit Secure Boot (GRUB) -> Installer startet
#   1. Vollautomatische Installation in QEMU
#   2. Start des installierten Systems, Erststart, Initialpasswort auf der Konsole
#   3. Geraete- und Funktionstests (tests/e2e/suite.py)
#
#   sudo [PHASES="boot install test"] tests/e2e/run.sh <e2e-iso>
set -uo pipefail

ISO="$(readlink -f "$1")"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-/tmp/e2e}"
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-150m}"
PHASES="${PHASES:-boot install test}"
mkdir -p "$WORK"
cd "$WORK" || exit 1
phase() { [[ " $PHASES " == *" $1 "* ]]; }
if phase boot || [ ! -f boot-results.jsonl ]; then : > boot-results.jsonl; fi

log() { echo -e "\n\033[1;34m===== $* =====\033[0m"; }
result() {  # Kategorie, Name, ok(true/false), Detail
  python3 -c 'import json,sys; print(json.dumps({"category":sys.argv[1],"name":sys.argv[2],"ok":sys.argv[3]=="true","detail":sys.argv[4],"secs":0}, ensure_ascii=False))' \
    "$1" "$2" "$3" "${4:-}" >> boot-results.jsonl
  if [ "$3" = true ]; then echo -e "\033[1;32mPASS\033[0m $2 ${4:-}"; else echo -e "\033[1;31mFAIL\033[0m $2 ${4:-}"; fi
}
strip_ansi() { sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' "$1" | tr -d '\r'; }
show_screen() { python3 "$HERE/screen.py" "$1" 2>/dev/null; }
screen_sig() { python3 "$HERE/screen.py" --sig "$1" 2>/dev/null; }
sendkey() {
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(("sendkey %s\n" % sys.argv[2]).encode())' "$1" "$2" 2>/dev/null
}

# Firmware der Test-VM: UEFI (Installation ohne, Neustart mit Secure Boot)
OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_CODE_SB=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
OVMF_VARS_MS=/usr/share/OVMF/OVMF_VARS_4M.ms.fd
FW_INSTALL=()
FW_BOOT=()
if [ -f "$OVMF_CODE" ] && [ -f "$OVMF_CODE_SB" ] && [ -f "$OVMF_VARS_MS" ] && [ "${E2E_FIRMWARE:-uefi}" = uefi ]; then
  FW_INSTALL=(-machine q35 -drive "if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on"
              -drive "if=pflash,format=raw,unit=1,file=$WORK/vm-vars.fd")
  FW_BOOT=(-machine "q35,smm=on" -global "driver=cfi.pflash01,property=secure,value=on"
           -drive "if=pflash,format=raw,unit=0,file=$OVMF_CODE_SB,readonly=on"
           -drive "if=pflash,format=raw,unit=1,file=$WORK/vm-vars.fd")
fi

if [ -w /dev/kvm ]; then
  ACCEL=(-accel kvm -cpu host)
  KVM=1
  echo "KVM verfuegbar"
else
  ACCEL=(-accel tcg)
  KVM=0
  echo "Kein KVM - Emulation (langsam), Bootmenue-Tests werden uebersprungen"
fi

# ---------------------------------------------------------------------------
log "Phase 0: Bootmenue (BIOS und UEFI mit Secure Boot)"
# ---------------------------------------------------------------------------
boot_menu_test() {  # Name, QEMU-Firmware-Argumente ...
  local name="$1"; shift
  rm -f "boot-$name.pcap" "mon-$name.sock" "boot-$name.qcow2"
  qemu-img create -f qcow2 "boot-$name.qcow2" 16G >/dev/null
  qemu-system-x86_64 "${ACCEL[@]}" -m 2048 -smp 2 "$@" -display none -cdrom "$ISO" \
    -drive "file=$WORK/boot-$name.qcow2,if=virtio,format=qcow2" \
    -serial "file:$WORK/boot-$name-serial.log" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -object "filter-dump,id=f0,netdev=n0,file=$WORK/boot-$name.pcap" \
    -monitor "unix:$WORK/mon-$name.sock,server,nowait" -daemonize -pidfile "$WORK/qemu-$name.pid" || return 1
  sleep 15; sendkey "$WORK/mon-$name.sock" ret
  sleep 10; sendkey "$WORK/mon-$name.sock" ret
  # Erfolg: Installer hat Bootmenue + Preseed durchlaufen, partitioniert und laedt das
  # Basissystem vom Debian-Spiegel (deb.debian.org)
  local ok=1
  for _ in $(seq 1 72); do
    if python3 - "$WORK/boot-$name.pcap" <<'EOF'
import sys
d = open(sys.argv[1], "rb").read()
sys.exit(0 if (b"Host: deb.debian.org" in d or b"\x03deb\x06debian\x03org" in d) else 1)
EOF
    then ok=0; break; fi
    sleep 5
  done
  echo "Bildschirm (serielle Konsole) nach dem Test:"
  show_screen "$WORK/boot-$name-serial.log"
  kill "$(cat "$WORK/qemu-$name.pid")" 2>/dev/null
  sleep 2
  rm -f "boot-$name.qcow2"
  return $ok
}

if [ "$KVM" = 1 ] && phase boot; then
  if boot_menu_test bios -boot d; then
    result "Installationsmedium" "BIOS: Bootmenü (isolinux) startet den automatischen Installer" true
  else
    result "Installationsmedium" "BIOS: Bootmenü (isolinux) startet den automatischen Installer" false "kein Installer-Netzverkehr"
  fi
  OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.ms.fd
  if [ -f "$OVMF_CODE" ] && [ -f "$OVMF_VARS" ]; then
    cp "$OVMF_VARS" "$WORK/ovmf-vars.fd"
    if boot_menu_test uefi -machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on \
         -drive "if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on" \
         -drive "if=pflash,format=raw,unit=1,file=$WORK/ovmf-vars.fd"; then
      result "Installationsmedium" "UEFI mit Secure Boot: Bootmenü (GRUB) startet den automatischen Installer" true
    else
      result "Installationsmedium" "UEFI mit Secure Boot: Bootmenü (GRUB) startet den automatischen Installer" false "kein Installer-Netzverkehr"
    fi
  else
    result "Installationsmedium" "UEFI mit Secure Boot" false "OVMF nicht installiert"
  fi
fi

if phase install; then
# ---------------------------------------------------------------------------
log "Phase 1: Vollautomatische Installation"
# ---------------------------------------------------------------------------
xorriso -osirrox on -indev "$ISO" -extract /install.amd/vmlinuz vmlinuz \
  -extract /install.amd/initrd.gz initrd.gz >/dev/null 2>&1
rm -f disk.qcow2
qemu-img create -f qcow2 disk.qcow2 16G >/dev/null
[ ${#FW_INSTALL[@]} -gt 0 ] && cp "$OVMF_VARS_MS" vm-vars.fd
echo "Firmware: ${FW_INSTALL[*]:-BIOS (SeaBIOS)}"
START=$(date +%s)
: > install-serial.log
timeout "$INSTALL_TIMEOUT" qemu-system-x86_64 "${ACCEL[@]}" "${FW_INSTALL[@]}" -m 2048 -smp 2 -no-reboot \
  -display none -monitor none -serial file:install-serial.log \
  -drive file=disk.qcow2,if=virtio,format=qcow2 -cdrom "$ISO" \
  -kernel vmlinuz -initrd initrd.gz \
  -append "auto=true priority=critical preseed/file=/cdrom/preseed.cfg locale=en_US.UTF-8 keymap=de console=ttyS0,115200n8 DEBIAN_FRONTEND=text --- console=ttyS0,115200n8" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 &
QPID=$!
# Watchdog: Bildschirm des Installers rendern (die Uhr der screen-Statuszeile
# wird ignoriert) und einen haengenden Installer (wartet auf Eingabe) erkennen
LAST_SIG=""
LAST_CHANGE=$(date +%s)
LAST_SHOWN=0
STALL_LIMIT=$(( KVM == 1 ? 600 : 2700 ))
while kill -0 $QPID 2>/dev/null; do
  sleep 30
  SIG="$(screen_sig install-serial.log)"
  NOW=$(date +%s)
  if [ "$SIG" != "$LAST_SIG" ]; then
    LAST_SIG=$SIG
    LAST_CHANGE=$NOW
    if [ $((NOW - LAST_SHOWN)) -ge 180 ]; then
      echo "[$(( (NOW - START) / 60 )) min] Installer-Bildschirm:"
      show_screen install-serial.log | grep -v '^|  *|$'
      LAST_SHOWN=$NOW
    fi
  elif [ $((NOW - LAST_CHANGE)) -gt "$STALL_LIMIT" ]; then
    echo "!!! Bildschirm seit $STALL_LIMIT s unveraendert - der Installer wartet vermutlich auf eine Eingabe:"
    show_screen install-serial.log
    STALLED=1
    kill $QPID 2>/dev/null
    break
  fi
done
wait $QPID
RC=$?
[ "${STALLED:-0}" = 1 ] && RC=99
MIN=$(( ($(date +%s) - START) / 60 ))
echo "Installation beendet nach $MIN Minuten (Exit $RC)"
modprobe nbd max_part=8 >/dev/null 2>&1
if qemu-nbd -c /dev/nbd0 disk.qcow2 >/dev/null 2>&1; then
  sleep 2
  mkdir -p /mnt/e2e
  for part in /dev/nbd0p1 /dev/nbd0p2 /dev/nbd0p3; do
    if mount -o ro "$part" /mnt/e2e 2>/dev/null; then
      if [ -d /mnt/e2e/var/log ]; then
        cp /mnt/e2e/var/log/vpn-server-install.log install.log 2>/dev/null
        cp /mnt/e2e/var/log/installer/syslog installer-syslog.log 2>/dev/null
      fi
      umount /mnt/e2e
    fi
  done
  qemu-nbd -d /dev/nbd0 >/dev/null 2>&1
fi
[ -s install.log ] && { echo "--- Ende von /var/log/vpn-server-install.log ---"; tail -n 40 install.log; }
if [ $RC -ne 0 ]; then
  show_screen install-serial.log
  [ -f installer-syslog.log ] && grep -iE "error|fail|late_command" installer-syslog.log | tail -40
  result "Installation" "Vollautomatische Installation ohne Eingaben" false "Exit $RC nach $MIN min"
  exit 1
fi
result "Installation" "Vollautomatische Installation ohne Eingaben" true "($MIN min)"
fi
phase test || exit 0

# ---------------------------------------------------------------------------
log "Phase 2: Start des installierten Systems"
# ---------------------------------------------------------------------------
# Testnetz: Bruecke 192.168.250.1 (QEMU-Portweiterleitungen = "Router mit Portfreigaben"),
# Geraet A 192.168.250.2, Geraet B 192.168.250.3. Ohne Tunnel kein Internet/Heimnetz.
for ns in vpncli vpncli2; do ip netns del $ns 2>/dev/null; done
ip link del br-e2e 2>/dev/null
ip link add br-e2e type bridge
ip addr add 192.168.250.1/24 dev br-e2e
ip link set br-e2e up
i=2
for ns in vpncli vpncli2; do
  ip netns add $ns
  ip link add "v-$ns" type veth peer name eth0 netns $ns
  ip link set "v-$ns" master br-e2e up
  ip -n $ns addr add "192.168.250.$i/24" dev eth0
  ip -n $ns link set eth0 up
  ip -n $ns link set lo up
  ip -n $ns route add default via 192.168.250.1
  ip netns exec $ns sysctl -qw net.ipv4.conf.all.src_valid_mark=1
  i=$((i + 1))
done
# AppArmor-Profile (charon, pppd ...) des Test-Hosts wuerden Testpfade blockieren
command -v aa-teardown >/dev/null && aa-teardown >/dev/null 2>&1
iptables -I FORWARD -i br-e2e -j DROP
iptables -I FORWARD -o br-e2e -j DROP
grep -q " vpn.test" /etc/hosts || echo "192.168.250.1 vpn.test" >> /etc/hosts
modprobe -a ppp_generic ppp_async ppp_deflate ppp_mppe l2tp_ppp wireguard >/dev/null 2>&1

# Externer RADIUS-Server (FreeRADIUS auf dem Test-Host, fuer den Gast 10.0.2.2) mit
# VLAN-Zuweisung wie bei einem WLAN-Controller
if command -v freeradius >/dev/null 2>&1; then
  RADDB=/etc/freeradius/3.0
  cat > "$RADDB/mods-config/files/authorize" <<'EOF'
"radvlan10" Cleartext-Password := "Radius-Pass10"
	Tunnel-Type = VLAN,
	Tunnel-Medium-Type = IEEE-802,
	Tunnel-Private-Group-Id = "10",
	Class = "nps-klasse-die-der-vpn-server-nicht-verwenden-darf-0123456789",
	Framed-IP-Address = 192.0.2.99

"radnovlan" Cleartext-Password := "Radius-Pass00"

"radvlan99" Cleartext-Password := "Radius-Pass99"
	Tunnel-Type = VLAN,
	Tunnel-Medium-Type = IEEE-802,
	Tunnel-Private-Group-Id = "99"

"radwrong" Cleartext-Password := "Richtig-Pass1"
EOF
  rm -rf /var/log/freeradius/radacct/127.0.0.1
  systemctl restart freeradius && echo "FreeRADIUS (extern) bereit"
fi

# VLAN-Trunk: zweite Netzwerkkarte des Servers; VLAN 10 und 20 sind eigene Netze
# (Namespaces) mit einem HTTP-Dienst, der die Absenderadresse zurueckgibt
TRUNK=(-netdev "tap,id=trunk,ifname=tap-trunk,script=no,downscript=no"
       -device "virtio-net-pci,netdev=trunk,addr=0x9,mac=52:54:00:00:99:01")

FWD="hostfwd=tcp:127.0.0.1:8443-:8443,hostfwd=tcp:127.0.0.1:2222-:22"
for p in udp:51820 udp:1194 tcp:1194 udp:500 udp:4500 tcp:443 tcp:4443 udp:4443 tcp:1723; do
  FWD="$FWD,hostfwd=${p%%:*}:192.168.250.1:${p##*:}-:${p##*:}"
done
rm -f boot-serial.log
if [ ! -f vm-vars.fd ]; then FW_BOOT=(); fi
echo "Firmware beim Start: ${FW_BOOT[*]:-BIOS (SeaBIOS)}"
qemu-system-x86_64 "${ACCEL[@]}" "${FW_BOOT[@]}" -m 2048 -smp 2 -display none -monitor none \
  -serial file:boot-serial.log -drive file=disk.qcow2,if=virtio,format=qcow2 \
  -netdev "user,id=n0,$FWD" -device virtio-net-pci,netdev=n0 "${TRUNK[@]}" \
  -daemonize -pidfile qemu.pid || { echo "QEMU-Start fehlgeschlagen"; exit 1; }
ip link set tap-trunk up
for v in 10 20; do
  ip netns del "vlan$v" 2>/dev/null
  ip netns add "vlan$v"
  ip link add link tap-trunk name "trunk.$v" type vlan id "$v"
  ip link set "trunk.$v" netns "vlan$v"
  ip -n "vlan$v" addr add "192.168.$v.1/24" dev "trunk.$v"
  ip -n "vlan$v" link set "trunk.$v" up
  ip -n "vlan$v" link set lo up
  ip netns exec "vlan$v" python3 "$HERE/echo_ip.py" 8080 >/dev/null 2>&1 &
done

# "Heimnetz"-Dienst: fuer den Gast ist der QEMU-Host 10.0.2.2
python3 -m http.server 8099 --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
HTTP_PID=$!
# Nachgebildete GitHub-API fuer das Selbst-Update (privates Repository mit Token)
python3 "$HERE/fake_github.py" --port 8097 --repo-dir "$HERE/../.." --version 9.9.9 \
  --token e2e_update_token_0123456789 > "$WORK/fake-github.log" 2>&1 &
GH_PID=$!
trap 'kill $HTTP_PID $GH_PID 2>/dev/null; kill $(cat "$WORK/qemu.pid" 2>/dev/null) 2>/dev/null' EXIT

echo "Warte auf die Weboberflaeche ..."
for _ in $(seq 1 180); do
  curl -skf --max-time 5 --noproxy '*' https://127.0.0.1:8443/health >/dev/null 2>&1 && break
  sleep 5
done
if curl -skf --max-time 5 --noproxy '*' https://127.0.0.1:8443/health >/dev/null; then
  if [ ${#FW_BOOT[@]} -gt 0 ]; then
    result "Erststart" "Installiertes System startet mit UEFI Secure Boot (shim, GRUB, Kernel signiert)" true
  fi
  result "Erststart" "Weboberfläche nach dem ersten Start erreichbar (https://<IP>:8443)" true
else
  strip_ansi boot-serial.log | tail -60
  result "Erststart" "Weboberfläche nach dem ersten Start erreichbar (https://<IP>:8443)" false
  exit 1
fi

INITPW="$(strip_ansi boot-serial.log | grep -oE 'Initialpasswort:[[:space:]]+[A-Za-z0-9]+' | tail -1 | awk '{print $2}')"
if [ -n "$INITPW" ]; then
  result "Erststart" "Initialpasswort wird auf der Konsole angezeigt" true
else
  result "Erststart" "Initialpasswort wird auf der Konsole angezeigt" false
  strip_ansi boot-serial.log | tail -40
  exit 1
fi

# ---------------------------------------------------------------------------
log "Phase 3: Geraete- und Funktionstests"
# ---------------------------------------------------------------------------
python3 "$HERE/suite.py" --work "$WORK" --initial-password "$INITPW"
RC=$?

log "Diagnose vom Server"
sshpass -p "E2e-Admin-Passwort-1" ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 \
  vpnadmin@127.0.0.1 "echo 'E2e-Admin-Passwort-1' | sudo -S -p '' bash -c 'systemctl --failed --no-legend; vpnctl status; journalctl -b -p warning --no-pager -n 80; tail -n 40 /var/log/accel-ppp/accel-ppp.log'" \
  > server-diag.log 2>&1
cat server-diag.log
exit $RC
