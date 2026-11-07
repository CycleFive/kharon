#!/usr/bin/env bash
# Agent-host provisioning for path (A), WireGuard (SPEC §3.3, REQ-DEP-005).
# Egress-shaped hosts use provision-connector.sh (path B) instead.
#
# Run as root on a fresh Debian 12 or 13 agent host. It sets up only
# Chromium and the tunnel the broker uses to reach it (REQ-ARCH-001):
#
#   - Chromium as the `browser` OS user, profile dir mode 0700, CDP on
#     127.0.0.1 only;
#   - kernel.yama.ptrace_scope = 1, so the agent's user cannot read the
#     browser's memory or attach to it;
#   - Chromium's password manager, leak check, autofill and sync off by
#     managed policy;
#   - a WireGuard peer for the broker and a relay that exposes CDP on the
#     WireGuard address to the broker's address only.
#
# Nothing kharon-specific is installed: no kharon binary, no kharon
# config, no vault credential. The only secret on this host is the
# WireGuard private key, generated here and never printed.
#
# Inputs (environment):
#   BROKER_WG_PUBKEY   required: the broker's WireGuard public key
#   BROKER_ENDPOINT    optional host:port of the broker's WireGuard
#                      listener; leave unset when the broker dials in
#   AGENT_WG_ADDR      this host's tunnel address   (default 10.66.0.2)
#   BROKER_WG_ADDR     the broker's tunnel address  (default 10.66.0.1)
#   WG_LISTEN_PORT     WireGuard UDP port           (default 51820)
#   CDP_PORT           DevTools port                (default 9222)
#
# Re-running is safe: files are rewritten, the key is kept, and the
# services are restarted.
#
# Every file this writes goes through put_file, and CI checks that each
# put_file target is Chromium policy, tunnel config, a sysctl or a
# systemd unit (crates/kharond/tests/req_arch_001_agent_host_docs.rs).

set -euo pipefail

: "${BROKER_WG_PUBKEY:?set BROKER_WG_PUBKEY to the WireGuard public key of the broker}"
BROKER_ENDPOINT="${BROKER_ENDPOINT:-}"
AGENT_WG_ADDR="${AGENT_WG_ADDR:-10.66.0.2}"
BROKER_WG_ADDR="${BROKER_WG_ADDR:-10.66.0.1}"
WG_LISTEN_PORT="${WG_LISTEN_PORT:-51820}"
CDP_PORT="${CDP_PORT:-9222}"

if [ "$(id -u)" -ne 0 ]; then
    echo "provision.sh: run as root" >&2
    exit 1
fi
if [ ! -r /etc/debian_version ]; then
    echo "provision.sh: written for Debian 12 or 13" >&2
    exit 1
fi

# put_file PATH MODE: write stdin to PATH with MODE, owned by root.
put_file() {
    install -D -m "$2" -o root -g root /dev/stdin "$1"
}

# 1. Packages: the browser, its fonts, the tunnel, and the relay.
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends \
    chromium fonts-liberation wireguard-tools socat

# 2. The `browser` user owns the profile; the agent runs as another user.
if ! id -u browser >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/browser \
        --shell /usr/sbin/nologin browser
fi
install -d -m 0700 -o browser -g browser /var/lib/browser

# 3. No ptrace across users, and none of non-descendants at all.
put_file /etc/sysctl.d/60-ptrace-scope.conf 0644 <<'CONF'
kernel.yama.ptrace_scope = 1
CONF
sysctl -q -p /etc/sysctl.d/60-ptrace-scope.conf

# 4. Chromium never offers to save, and never fills, passwords or forms.
put_file /etc/chromium/policies/managed/no-password-manager.json 0644 <<'JSON'
{
  "PasswordManagerEnabled": false,
  "PasswordLeakDetectionEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "PaymentMethodQueryEnabled": false,
  "SyncDisabled": true,
  "MetricsReportingEnabled": false
}
JSON

# 5. Chromium as `browser`, CDP on loopback. The agent connects to
# http://127.0.0.1:${CDP_PORT}; the broker comes in through the relay.
put_file /etc/systemd/system/browser.service 0644 <<UNIT
[Unit]
Description=Chromium for the agent (CDP on 127.0.0.1:${CDP_PORT})
After=network-online.target
Wants=network-online.target

[Service]
User=browser
Group=browser
UMask=0077
ExecStart=/usr/bin/chromium --headless=new \\
    --remote-debugging-address=127.0.0.1 --remote-debugging-port=${CDP_PORT} \\
    --user-data-dir=/var/lib/browser/profile \\
    --no-first-run --no-default-browser-check --password-store=basic \\
    about:blank
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT

# 6. The WireGuard peer. The private key stays in its own 0600 file.
if [ ! -s /etc/wireguard/wg0.key ]; then
    (umask 077 && wg genkey) | put_file /etc/wireguard/wg0.key 0600
fi
{
    printf '[Interface]\n'
    printf 'Address = %s/32\n' "$AGENT_WG_ADDR"
    printf 'ListenPort = %s\n' "$WG_LISTEN_PORT"
    printf 'PostUp = wg set %%i private-key /etc/wireguard/wg0.key\n'
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "$BROKER_WG_PUBKEY"
    printf 'AllowedIPs = %s/32\n' "$BROKER_WG_ADDR"
    if [ -n "$BROKER_ENDPOINT" ]; then
        printf 'Endpoint = %s\n' "$BROKER_ENDPOINT"
        printf 'PersistentKeepalive = 25\n'
    fi
} | put_file /etc/wireguard/wg0.conf 0600

# 7. The relay: the tunnel address to Chromium's loopback port, for the
# broker's tunnel address only, as a throwaway uid that is neither the
# browser's nor the agent's.
put_file /etc/systemd/system/cdp-relay.service 0644 <<UNIT
[Unit]
Description=CDP relay ${AGENT_WG_ADDR}:${CDP_PORT} -> 127.0.0.1:${CDP_PORT}, broker only
BindsTo=wg-quick@wg0.service
After=wg-quick@wg0.service browser.service

[Service]
DynamicUser=yes
ExecStart=/usr/bin/socat \\
    TCP-LISTEN:${CDP_PORT},bind=${AGENT_WG_ADDR},range=${BROKER_WG_ADDR}/32,fork,reuseaddr \\
    TCP:127.0.0.1:${CDP_PORT}
Restart=always
RestartSec=1
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable -q wg-quick@wg0.service browser.service cdp-relay.service
systemctl restart wg-quick@wg0.service browser.service cdp-relay.service

echo "Agent host ready. Add this peer on the broker:"
echo "  PublicKey = $(wg pubkey </etc/wireguard/wg0.key)"
echo "  AllowedIPs = ${AGENT_WG_ADDR}/32"
