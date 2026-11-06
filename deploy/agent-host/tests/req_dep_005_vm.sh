#!/usr/bin/env bash
# REQ-DEP-005 (issue #24): run deploy/agent-host/provision.sh in a fresh
# Debian VM and check the result, with this machine as the broker.
#
#  1. Boot the Debian cloud image (checksum-verified) under QEMU, with
#     SSH and the WireGuard UDP port forwarded to localhost.
#  2. Make a broker WireGuard key here, run provision.sh in the VM with
#     its public key, and bring up the broker end here.
#  3. In the VM: ptrace_scope is 1; Chromium runs only as `browser`;
#     CDP listens on 127.0.0.1 and on the tunnel address only; the
#     profile is 0700 and unreadable by a separate agent user, who can
#     still reach CDP on loopback; nothing named kharon exists
#     (REQ-ARCH-001).
#  4. Here, through the tunnel: CDP answers, and chrome://prefs-internals
#     shows the password manager and autofill off by managed policy.
#
# Needs: qemu-system-x86_64 (KVM if /dev/kvm is writable, else TCG),
# qemu-img, cloud-localds, wireguard-tools, curl, ssh, node 22+, and
# sudo (for the broker's wg-quick). CI: .github/workflows/agent-host.yml.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
provision="$here/../provision.sh"
image_dir="${DEBIAN_IMAGE_DIR:-https://cloud.debian.org/images/cloud/trixie/latest}"
image_name="${DEBIAN_IMAGE_NAME:-debian-13-generic-amd64.qcow2}"
work="${REQ_DEP_005_WORK:-${RUNNER_TEMP:-/tmp}/req_dep_005}"
ssh_port=2222
wg_port=51820
agent_addr=10.66.0.2
broker_addr=10.66.0.1
cdp_port=9222
wg_if=kharon-test

mkdir -p "$work"
cd "$work"

log() { printf '\n== %s\n' "$*"; }

cleanup() {
    sudo wg-quick down "$wg_if" >/dev/null 2>&1 || true
    sudo rm -f "/etc/wireguard/$wg_if.conf"
    if [ -s qemu.pid ]; then
        sudo kill "$(cat qemu.pid)" 2>/dev/null || kill "$(cat qemu.pid)" 2>/dev/null || true
    fi
}
trap cleanup EXIT

log "Debian image"
if [ ! -s "$image_name" ]; then
    curl -fsSL --retry 3 -o "$image_name" "$image_dir/$image_name"
fi
curl -fsSL --retry 3 -o SHA512SUMS "$image_dir/SHA512SUMS"
grep " $image_name\$" SHA512SUMS | sha512sum -c -
rm -f disk.qcow2
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$image_name" disk.qcow2 10G

log "cloud-init seed"
rm -f id id.pub
ssh-keygen -q -t ed25519 -N '' -f id
cat >user-data <<CLOUD
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat id.pub)
CLOUD
cloud-localds seed.img user-data

log "boot"
rm -f qemu.pid console.log
if [ -w /dev/kvm ]; then
    accel=(-accel kvm -cpu host)
else
    echo "no writable /dev/kvm: falling back to TCG, which is much slower"
    accel=(-accel tcg -cpu max)
fi
qemu-system-x86_64 "${accel[@]}" -smp 2 -m 3072 \
    -drive file=disk.qcow2,if=virtio \
    -drive file=seed.img,if=virtio,format=raw \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22,hostfwd=udp:127.0.0.1:${wg_port}-:${wg_port}" \
    -device virtio-net-pci,netdev=n0 \
    -display none -serial file:console.log \
    -pidfile qemu.pid -daemonize

ssh_opts=(-i id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR -o ConnectTimeout=5)
vm() { ssh "${ssh_opts[@]}" -p "$ssh_port" debian@127.0.0.1 "$@"; }

for i in $(seq 1 180); do
    if vm true 2>/dev/null; then break; fi
    if [ "$i" -eq 180 ]; then
        tail -50 console.log
        echo "FAIL: the VM did not come up" >&2
        exit 1
    fi
    sleep 5
done
vm cloud-init status --wait >/dev/null || true

log "provision"
umask 077
wg genkey >broker.key
broker_pub="$(wg pubkey <broker.key)"
scp "${ssh_opts[@]}" -P "$ssh_port" "$provision" debian@127.0.0.1:/tmp/provision.sh
vm "sudo BROKER_WG_PUBKEY='$broker_pub' bash /tmp/provision.sh && rm /tmp/provision.sh" | tee provision.log
agent_pub="$(sed -n 's/^  PublicKey = //p' provision.log)"
test -n "$agent_pub"

log "broker end of the tunnel"
# wg-quick reads its config from /etc/wireguard: Ubuntu's AppArmor
# profile for it refuses other paths, even to root.
sudo install -D -m 600 /dev/stdin "/etc/wireguard/$wg_if.conf" <<WG
[Interface]
Address = ${broker_addr}/32
PrivateKey = $(cat broker.key)

[Peer]
PublicKey = ${agent_pub}
AllowedIPs = ${agent_addr}/32
Endpoint = 127.0.0.1:${wg_port}
PersistentKeepalive = 5
WG
sudo wg-quick up "$wg_if"

version_url="http://${agent_addr}:${cdp_port}/json/version"
for i in $(seq 1 30); do
    if curl -fsS --noproxy '*' -m 3 "$version_url" >version.json 2>/dev/null; then break; fi
    if [ "$i" -eq 30 ]; then
        sudo wg show || true
        vm 'sudo systemctl --no-pager status browser.service cdp-relay.service wg-quick@wg0.service; sudo journalctl --no-pager -n 60 -u browser.service -u cdp-relay.service' || true
        echo "FAIL: CDP not reachable through the tunnel" >&2
        exit 1
    fi
    sleep 2
done
cat version.json

log "checks in the VM"
vm sudo bash -s <<'CHECKS'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

[ "$(sysctl -n kernel.yama.ptrace_scope)" = 1 ] || fail "ptrace_scope is not 1"
ok "kernel.yama.ptrace_scope = 1"

systemctl is-active --quiet browser.service cdp-relay.service wg-quick@wg0.service \
    || fail "a service is not active"
ok "browser, cdp-relay and wg-quick@wg0 are active"

procs="$(ps -eo user:32=,comm= | awk '$2 ~ /^chrom/')"
[ -n "$procs" ] || fail "no Chromium processes"
others="$(printf '%s\n' "$procs" | awk '$1 != "browser"')"
[ -z "$others" ] || fail "Chromium processes not run by browser: $others"
ok "every Chromium process runs as browser ($(printf '%s\n' "$procs" | wc -l))"

listeners="$(ss -ltnH 'sport = :9222' | awk '{print $4}' | sort -u | tr '\n' ' ')"
[ "$listeners" = "10.66.0.2:9222 127.0.0.1:9222 " ] \
    || fail "unexpected CDP listeners: $listeners"
ok "CDP listens on 127.0.0.1 and the tunnel address only"

[ "$(stat -c '%U %a' /var/lib/browser)" = "browser 700" ] || fail "profile dir is not browser 0700"
ok "/var/lib/browser is browser 0700"

id -u agent >/dev/null 2>&1 || useradd --create-home agent
pid="$(pgrep -u browser -o chromium || pgrep -u browser -o -f /usr/lib/chromium/chromium)"
if runuser -u agent -- ls /var/lib/browser >/dev/null 2>&1; then fail "agent can list the profile dir"; fi
if runuser -u agent -- head -c1 "/proc/$pid/environ" >/dev/null 2>&1; then fail "agent can read Chromium's /proc"; fi
if runuser -u agent -- python3 -c '
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
sys.exit(0 if libc.ptrace(16, int(sys.argv[1]), None, None) == 0 else 1)  # PTRACE_ATTACH
' "$pid"; then fail "agent can ptrace Chromium"; fi
ok "a separate agent user cannot read the profile, read Chromium's /proc or ptrace it"
runuser -u agent -- python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=5).read()' \
    || fail "agent cannot reach CDP on loopback"
ok "the agent reaches CDP on 127.0.0.1"

test -s /etc/chromium/policies/managed/no-password-manager.json || fail "policy file missing"
python3 -m json.tool /etc/chromium/policies/managed/no-password-manager.json >/dev/null
ok "managed policy in place"

# REQ-ARCH-001: no kharon binary or config on the agent host.
for bin in kharon kharond; do
    if command -v "$bin" >/dev/null; then fail "$bin is installed"; fi
done
found="$(find / -xdev -iname '*kharon*' 2>/dev/null || true)"
[ -z "$found" ] || fail "kharon files on the agent host: $found"
ok "no kharon binary or file on the agent host"
CHECKS

log "managed policy, read through the tunnel"
ws_url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["webSocketDebuggerUrl"])' version.json)"
case "$ws_url" in
    "ws://${agent_addr}:${cdp_port}/devtools/browser/"*) ;;
    *) echo "FAIL: unexpected browser websocket URL $ws_url" >&2; exit 1 ;;
esac
NO_PROXY='*' node "$here/cdp-policy-check.mjs" "$ws_url"

log "req_dep_005_vm passed"
