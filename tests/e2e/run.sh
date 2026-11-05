#!/bin/bash
# End-to-End-Test: ISO in QEMU vollautomatisch installieren, booten, ueber die
# Weboberflaeche einrichten und jedes VPN-Protokoll mit echten Clients pruefen.
#
#   sudo tests/e2e/run.sh <e2e-iso>
#
# Erwartet (Ubuntu 24.04): qemu-system-x86 xorriso wireguard-tools openvpn openconnect
#   strongswan-swanctl charon-systemd libcharon-extauth-plugins libcharon-extra-plugins
#   sstp-client xl2tpd ppp sshpass curl python3
set -uo pipefail

ISO="$(readlink -f "$1")"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-/tmp/e2e}"
NS=vpncli
HOST_IP=192.168.250.1
CLI_IP=192.168.250.2
VPN_HOST=vpn.test
NEWPW="E2e-Admin-Passwort-1"
CPW="E2eTest-Pass1"
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-150m}"
mkdir -p "$WORK"
cd "$WORK" || exit 1

log() { echo -e "\n\033[1;34m===== $* =====\033[0m"; }
declare -A RESULT
pass() { RESULT[$1]=PASS; echo -e "\033[1;32mPASS\033[0m $1"; }
fail() { RESULT[$1]=FAIL; echo -e "\033[1;31mFAIL\033[0m $1 ${2:-}"; }

if [ -w /dev/kvm ]; then
  ACCEL=(-accel kvm -cpu host)
  echo "KVM verfuegbar"
else
  ACCEL=(-accel tcg)
  echo "Kein KVM - Emulation (langsam)"
fi

# ---------------------------------------------------------------------------
log "Phase 1: Installation"
# ---------------------------------------------------------------------------
if [ ! -f disk.qcow2 ] || [ "${REINSTALL:-1}" = 1 ]; then
  xorriso -osirrox on -indev "$ISO" -extract /install.amd/vmlinuz vmlinuz \
    -extract /install.amd/initrd.gz initrd.gz >/dev/null 2>&1
  rm -f disk.qcow2
  qemu-img create -f qcow2 disk.qcow2 16G >/dev/null
  START=$(date +%s)
  timeout "$INSTALL_TIMEOUT" qemu-system-x86_64 "${ACCEL[@]}" -m 2048 -smp 2 -no-reboot \
    -display none -monitor none -serial file:install-serial.log \
    -drive file=disk.qcow2,if=virtio,format=qcow2 -cdrom "$ISO" \
    -kernel vmlinuz -initrd initrd.gz \
    -append "auto=true priority=critical preseed/file=/cdrom/preseed.cfg locale=de_DE.UTF-8 keymap=de console=ttyS0,115200n8 DEBIAN_FRONTEND=text --- console=ttyS0,115200n8" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0
  RC=$?
  echo "Installation beendet nach $(( ($(date +%s) - START) / 60 )) Minuten (Exit $RC)"
  if [ $RC -ne 0 ]; then
    tail -c 4000 install-serial.log | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g'
    echo "Installation fehlgeschlagen oder Zeitueberschreitung"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
log "Phase 2: Start des installierten Systems"
# ---------------------------------------------------------------------------
ip netns del $NS 2>/dev/null
ip link del veth-host 2>/dev/null
ip netns add $NS
ip link add veth-host type veth peer name veth-cli
ip link set veth-cli netns $NS
ip addr add $HOST_IP/24 dev veth-host
ip link set veth-host up
ip -n $NS addr add $CLI_IP/24 dev veth-cli
ip -n $NS link set veth-cli up
ip -n $NS link set lo up
grep -q " $VPN_HOST" /etc/hosts || echo "$HOST_IP $VPN_HOST" >> /etc/hosts

FWD="hostfwd=tcp:127.0.0.1:8443-:8443,hostfwd=tcp:127.0.0.1:2222-:22"
for p in udp:51820 udp:1194 tcp:1194 udp:500 udp:4500 tcp:443 tcp:4443 udp:4443 tcp:1723; do
  FWD="$FWD,hostfwd=${p%%:*}:$HOST_IP:${p##*:}-:${p##*:}"
done
rm -f boot-serial.log
qemu-system-x86_64 "${ACCEL[@]}" -m 2048 -smp 2 -display none -monitor none \
  -serial file:boot-serial.log -drive file=disk.qcow2,if=virtio,format=qcow2 \
  -netdev "user,id=n0,$FWD" -device virtio-net-pci,netdev=n0 \
  -daemonize -pidfile qemu.pid || { echo "QEMU-Start fehlgeschlagen"; exit 1; }
trap 'kill $(cat "$WORK/qemu.pid" 2>/dev/null) 2>/dev/null' EXIT

# Zielserver im "Heimnetz": der QEMU-Host ist fuer den Gast 10.0.2.2
python3 -m http.server 8099 --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null; kill $(cat "$WORK/qemu.pid" 2>/dev/null) 2>/dev/null' EXIT

echo "Warte auf die Weboberflaeche ..."
for _ in $(seq 1 180); do
  curl -skf --noproxy '*' https://127.0.0.1:8443/health >/dev/null 2>&1 && break
  sleep 5
done
curl -skf --noproxy '*' https://127.0.0.1:8443/health >/dev/null || {
  sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' boot-serial.log | tail -60; echo "Weboberflaeche nicht erreichbar"; exit 1; }
pass "Weboberflaeche erreichbar"

INITPW="$(sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' boot-serial.log | grep -oE 'Initialpasswort:[[:space:]]+[A-Za-z0-9]+' | tail -1 | awk '{print $2}')"
[ -n "$INITPW" ] && pass "Initialpasswort auf der Konsole angezeigt" || { fail "Initialpasswort auf der Konsole angezeigt"; exit 1; }

# ---------------------------------------------------------------------------
log "Phase 3: Einrichtung ueber die Weboberflaeche"
# ---------------------------------------------------------------------------
if python3 "$HERE/webui.py" --url https://127.0.0.1:8443 --password "$INITPW" \
     --new-password "$NEWPW" --host "$VPN_HOST" --client e2e --client-password "$CPW" --out "$WORK/profiles"; then
  pass "Einrichtung, Client anlegen, Profile herunterladen"
else
  fail "Einrichtung, Client anlegen, Profile herunterladen"
fi

remote() {
  sshpass -p "$NEWPW" ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 \
    vpnadmin@127.0.0.1 "echo '$NEWPW' | sudo -S -p '' bash -c \"$1\""
}
J() { python3 -c "import json,sys; d=json.load(open('$WORK/profiles/json.json')); print($1)"; }

reach() {  # Erreichbarkeit des "Heimnetzes" (QEMU-Host 10.0.2.2) durch den Tunnel
  ip netns exec $NS curl -s --noproxy '*' --max-time 8 -o /dev/null -w '%{http_code}' http://10.0.2.2:8099/ 2>/dev/null | grep -q 200
}

# ---------------------------------------------------------------------------
log "Test: WireGuard"
# ---------------------------------------------------------------------------
sed -e '/^DNS/d' -e 's|^AllowedIPs.*|AllowedIPs = 10.66.66.0/24, 10.0.2.0/24|' profiles/wireguard.conf > wg-e2e.conf
chmod 600 wg-e2e.conf
ip netns exec $NS wg-quick up ./wg-e2e.conf >/dev/null 2>&1
sleep 2
if ip netns exec $NS ping -c2 -W3 10.66.66.1 >/dev/null && reach; then pass WireGuard; else fail WireGuard; ip netns exec $NS wg show; fi
ip netns exec $NS wg-quick down ./wg-e2e.conf >/dev/null 2>&1

# ---------------------------------------------------------------------------
log "Test: OpenVPN UDP/TCP"
# ---------------------------------------------------------------------------
for proto in udp tcp; do
  grep -v '^remote ' profiles/openvpn.ovpn | sed "s|^client\$|client\nremote $VPN_HOST 1194 $proto|" > ovpn-$proto.ovpn
  rm -f ovpn-$proto.log
  ip netns exec $NS openvpn --config ovpn-$proto.ovpn --route-nopull --route 10.0.2.0 255.255.255.0 \
    --daemon ovpn-e2e-$proto --log "$WORK/ovpn-$proto.log" --writepid "$WORK/ovpn-$proto.pid"
  for _ in $(seq 1 30); do grep -q "Initialization Sequence Completed" ovpn-$proto.log 2>/dev/null && break; sleep 1; done
  if grep -q "Initialization Sequence Completed" ovpn-$proto.log && reach; then pass "OpenVPN $proto"; else fail "OpenVPN $proto"; tail -20 ovpn-$proto.log; fi
  kill "$(cat ovpn-$proto.pid)" 2>/dev/null; sleep 2
done

# ---------------------------------------------------------------------------
log "Test: IPsec (IKEv2 PSK/Zertifikat/EAP, IKEv1 XAuth, L2TP)"
# ---------------------------------------------------------------------------
command -v aa-teardown >/dev/null && aa-teardown >/dev/null 2>&1
systemctl stop strongswan xl2tpd >/dev/null 2>&1
install -d /etc/swanctl/conf.d /etc/swanctl/pkcs12 /etc/swanctl/x509ca
cp profiles/p12.p12 /etc/swanctl/pkcs12/e2e.p12
cp profiles/ca.crt /etc/swanctl/x509ca/vpn-ca.crt
cat > /etc/strongswan.d/zz-e2e.conf <<EOF
charon-systemd {
  filelog { e2e { path = $WORK/charon-cli.log
    default = 1
    ike = 2 } }
}
EOF
cat > /etc/swanctl/conf.d/e2e.conf <<EOF
connections {
  t-psk {
    version = 2
    remote_addrs = $VPN_HOST
    vips = 0.0.0.0
    local {
      auth = psk
      id = $(J 'd["ikev2"]["psk_id"]')
    }
    remote {
      auth = psk
      id = $VPN_HOST
    }
    children { t-psk { remote_ts = 10.0.2.0/24 } }
  }
  t-cert {
    version = 2
    remote_addrs = $VPN_HOST
    vips = 0.0.0.0
    local {
      auth = pubkey
      id = e2e
    }
    remote {
      auth = pubkey
      id = $VPN_HOST
    }
    children { t-cert { remote_ts = 10.0.2.0/24 } }
  }
  t-eap {
    version = 2
    remote_addrs = $VPN_HOST
    vips = 0.0.0.0
    local {
      auth = eap-mschapv2
      eap_id = e2e
      id = e2e
    }
    remote {
      auth = pubkey
      id = $VPN_HOST
    }
    children { t-eap { remote_ts = 10.0.2.0/24 } }
  }
  t-xauth {
    version = 1
    remote_addrs = $VPN_HOST
    vips = 0.0.0.0
    proposals = aes256-sha1-modp1024
    local {
      auth = psk
    }
    local-x {
      auth = xauth
      xauth_id = e2e
    }
    remote {
      auth = psk
    }
    children {
      t-xauth {
        remote_ts = 10.0.2.0/24
        esp_proposals = aes256-sha1
      }
    }
  }
  t-l2tp {
    version = 1
    remote_addrs = $VPN_HOST
    proposals = aes256-sha1-modp1024
    local {
      auth = psk
    }
    remote {
      auth = psk
    }
    children {
      t-l2tp {
        mode = transport
        local_ts = dynamic[udp/1701]
        remote_ts = dynamic[udp/1701]
        esp_proposals = aes128-sha1
      }
    }
  }
}
secrets {
  ike-psk {
    id = $(J 'd["ikev2"]["psk_id"]')
    secret = "$(J 'd["ikev2"]["psk"]')"
  }
  ike-v1 {
    id-1 = $HOST_IP
    secret = "$(J 'd["ipsec_psk"]')"
  }
  eap-e2e {
    id = e2e
    secret = "$CPW"
  }
  xauth-e2e {
    id = e2e
    secret = "$CPW"
  }
  private-p12 {
    file = e2e.p12
    secret = "$(J 'd["ikev2"]["p12_password"]')"
  }
}
EOF
ip netns exec $NS /usr/sbin/charon-systemd >/dev/null 2>&1 &
CHARON_PID=$!
sleep 3
ip netns exec $NS swanctl --load-all --noprompt 2>&1 | grep -E "failed|loaded connection" || true
for c in t-psk t-cert t-eap t-xauth; do
  ip netns exec $NS timeout 40 swanctl --initiate --child $c >/dev/null 2>&1
  sleep 1
  if reach; then pass "IPsec $c"; else fail "IPsec $c"; ip netns exec $NS swanctl --list-sas | head -20; fi
  ip netns exec $NS swanctl --terminate --ike $c --force >/dev/null 2>&1
  sleep 2
done

# L2TP/IPsec: Transport-SA + xl2tpd + pppd
modprobe -a ppp_generic ppp_async l2tp_ppp ppp_deflate ppp_mppe >/dev/null 2>&1
ip netns exec $NS timeout 40 swanctl --initiate --child t-l2tp >/dev/null 2>&1
cat > xl2tpd.conf <<EOF
[global]
port = 1701
access control = no
[lac vpn]
lns = $HOST_IP
ppp debug = yes
pppoptfile = $WORK/options.l2tp
length bit = yes
autodial = yes
redial = no
EOF
cat > options.l2tp <<EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
noccp
noauth
mtu 1280
mru 1280
noipdefault
nodefaultroute
name e2e
password $CPW
connect-delay 2000
logfile $WORK/pppd-l2tp.log
EOF
ip netns exec $NS xl2tpd -D -c "$WORK/xl2tpd.conf" -p "$WORK/xl2tpd.pid" -C "$WORK/l2tp-control" > xl2tpd.log 2>&1 &
XL_PID=$!
PPPIF=""
for _ in $(seq 1 30); do
  PPPIF="$(ip -n $NS -o -4 addr show | awk '/ppp/ {print $2; exit}')"
  [ -n "$PPPIF" ] && break
  sleep 1
done
if [ -n "$PPPIF" ]; then
  ip -n $NS route add 10.0.2.0/24 dev "$PPPIF" 2>/dev/null
  if reach; then pass "L2TP/IPsec"; else fail "L2TP/IPsec" "(PPP steht, aber kein Durchgang)"; fi
else
  fail "L2TP/IPsec"; tail -20 xl2tpd.log; tail -20 pppd-l2tp.log 2>/dev/null
fi
kill $XL_PID 2>/dev/null; sleep 2
ip netns exec $NS swanctl --terminate --ike t-l2tp --force >/dev/null 2>&1
kill $CHARON_PID 2>/dev/null; sleep 1

# ---------------------------------------------------------------------------
log "Test: SSTP"
# ---------------------------------------------------------------------------
ip netns exec $NS sstpc --log-stderr --log-level 2 --ca-cert "$WORK/profiles/ca.crt" \
  --user e2e --password "$CPW" "$VPN_HOST" require-mschap-v2 refuse-eap refuse-pap refuse-chap \
  refuse-mschap noauth noipdefault nodefaultroute noccp nobsdcomp nodeflate > sstp.log 2>&1 &
SSTP_PID=$!
PPPIF=""
for _ in $(seq 1 30); do
  PPPIF="$(ip -n $NS -o -4 addr show | awk '/ppp/ {print $2; exit}')"
  [ -n "$PPPIF" ] && break
  sleep 1
done
if [ -n "$PPPIF" ]; then
  ip -n $NS route add 10.0.2.0/24 dev "$PPPIF" 2>/dev/null
  if reach; then pass SSTP; else fail SSTP "(PPP steht, aber kein Durchgang)"; fi
else
  fail SSTP; tail -30 sstp.log
fi
kill $SSTP_PID 2>/dev/null; sleep 2

# ---------------------------------------------------------------------------
log "Test: OpenConnect"
# ---------------------------------------------------------------------------
cat > oc-script.sh <<'EOF'
#!/bin/sh
if [ "$reason" = connect ]; then
  ip link set dev "$TUNDEV" up mtu "${INTERNAL_IP4_MTU:-1300}"
  ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
  ip route add 10.0.2.0/24 dev "$TUNDEV"
fi
exit 0
EOF
chmod +x oc-script.sh
echo "$CPW" | ip netns exec $NS openconnect --servercert "$(J 'd["openconnect_pin"]')" -u e2e \
  --passwd-on-stdin --script "$WORK/oc-script.sh" --background --pid-file "$WORK/oc.pid" \
  "$VPN_HOST:4443" > oc.log 2>&1
sleep 5
if reach; then pass OpenConnect; else fail OpenConnect; tail -20 oc.log; fi
kill "$(cat oc.pid 2>/dev/null)" 2>/dev/null

# ---------------------------------------------------------------------------
log "Test: PPTP-Dienst lauscht (GRE ist durch QEMU-NAT nicht testbar)"
# ---------------------------------------------------------------------------
if remote "ss -ltn | grep -q ':1723 '"; then pass "PPTP-Port offen"; else fail "PPTP-Port offen"; fi

# ---------------------------------------------------------------------------
log "Test: Client sperren -> Verbindung abgewiesen"
# ---------------------------------------------------------------------------
remote "vpnctl client del e2e" >/dev/null 2>&1
rm -f ovpn-udp.log
ip netns exec $NS openvpn --config ovpn-udp.ovpn --route-nopull --daemon ovpn-e2e-revoked \
  --log "$WORK/ovpn-udp.log" --writepid "$WORK/ovpn-rev.pid"
sleep 12
if grep -q "Initialization Sequence Completed" ovpn-udp.log; then fail "Geloeschter Client abgewiesen"; else pass "Geloeschter Client abgewiesen"; fi
kill "$(cat ovpn-rev.pid 2>/dev/null)" 2>/dev/null

# ---------------------------------------------------------------------------
log "Diagnose vom Server"
# ---------------------------------------------------------------------------
remote "systemctl --failed --no-legend; vpnctl status; tail -n 30 /var/log/vpn-server-install.log; journalctl -b -u vpn-firstboot -u accel-ppp -u strongswan -u ocserv -u vpn-webui --no-pager -n 150; tail -n 60 /var/log/accel-ppp/accel-ppp.log" > server-diag.log 2>&1
cat server-diag.log

# ---------------------------------------------------------------------------
log "Ergebnis"
# ---------------------------------------------------------------------------
FAILED=0
for k in "${!RESULT[@]}"; do
  printf '%-50s %s\n' "$k" "${RESULT[$k]}"
  [ "${RESULT[$k]}" = FAIL ] && FAILED=1
done | sort
for k in "${!RESULT[@]}"; do [ "${RESULT[$k]}" = FAIL ] && FAILED=1; done
exit $FAILED
