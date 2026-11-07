#!/usr/bin/env bash
# Agent-host provisioning for path (B): outbound TLS connector
# (REQ-DEP-005, REQ-ARCH-001, REQ-ARCH-002).
#
# Run as root on a Debian 12 or 13 agent host that can open outbound
# TCP/TLS and nothing else. It does not install WireGuard, does not
# listen on UDP, and does not set CAP_NET_ADMIN.
#
# Chromium matches path (A): user `browser`, profile mode 0700, CDP on
# 127.0.0.1, ptrace_scope=1, password manager off. The connector is a
# separate user. It holds a tunnel credential and dials the broker; it
# does not hold an agent API token or any vault material.
#
# Inputs (environment):
#   CONNECTOR_BIN       required: path to the kharon-agent-connector binary
#   BROKER_ADDR         required: host:port of the broker's connector listen
#   BROKER_PIN          required: 64 hex chars, SHA-256 of the broker cert DER
#   AGENT_ID            required: [a-z0-9-]{1,64}
#   TUNNEL_TOKEN_FILE   required: file whose contents are the tunnel credential
#   CDP_PORT            optional, default 9222
#   PROXY               optional http://host:port with no userinfo
#   PROXY_CREDS_FILE    optional: file holding one user:password line for
#                       Proxy-Authorization on CONNECT (requires PROXY).
#                       Installed mode 0400 like the tunnel token; never
#                       put credentials in the PROXY URL.
#
# Re-running is safe: units and config are rewritten. The token file is
# replaced from TUNNEL_TOKEN_FILE. PROXY_CREDS_FILE is replaced the same way.

set -euo pipefail

: "${CONNECTOR_BIN:?set CONNECTOR_BIN to the connector binary}"
: "${BROKER_ADDR:?set BROKER_ADDR to host:port of the broker connector listen}"
: "${BROKER_PIN:?set BROKER_PIN to the SHA-256 hex of the broker certificate DER}"
: "${AGENT_ID:?set AGENT_ID to the [agents.<id>] table name}"
: "${TUNNEL_TOKEN_FILE:?set TUNNEL_TOKEN_FILE to the tunnel credential file}"
CDP_PORT="${CDP_PORT:-9222}"
PROXY="${PROXY:-}"
PROXY_CREDS_FILE="${PROXY_CREDS_FILE:-}"

if [ "$(id -u)" -ne 0 ]; then
    echo "provision-connector.sh: run as root" >&2
    exit 1
fi
if [ ! -r /etc/debian_version ]; then
    echo "provision-connector.sh: written for Debian 12 or 13" >&2
    exit 1
fi
if [ ! -f "$CONNECTOR_BIN" ]; then
    echo "provision-connector.sh: CONNECTOR_BIN is not a file" >&2
    exit 1
fi
if [ ! -f "$TUNNEL_TOKEN_FILE" ]; then
    echo "provision-connector.sh: TUNNEL_TOKEN_FILE is not a file" >&2
    exit 1
fi
case "$AGENT_ID" in
    *[!a-z0-9-]*)
        echo "provision-connector.sh: AGENT_ID must match [a-z0-9-]{1,64}" >&2
        exit 1
        ;;
esac
if [ "${#AGENT_ID}" -lt 1 ] || [ "${#AGENT_ID}" -gt 64 ]; then
    echo "provision-connector.sh: AGENT_ID must match [a-z0-9-]{1,64}" >&2
    exit 1
fi
case "$BROKER_PIN" in
    *[!0-9a-fA-F]*)
        echo "provision-connector.sh: BROKER_PIN must be 64 hex characters" >&2
        exit 1
        ;;
esac
if [ "${#BROKER_PIN}" -ne 64 ]; then
    echo "provision-connector.sh: BROKER_PIN must be 64 hex characters" >&2
    exit 1
fi
if [ -n "$PROXY" ]; then
    case "$PROXY" in
        http://*@*|http://*:*@*)
            echo "provision-connector.sh: PROXY must not carry userinfo (use PROXY_CREDS_FILE)" >&2
            exit 1
            ;;
        http://*)
            ;;
        *)
            echo "provision-connector.sh: PROXY must be http://host:port" >&2
            exit 1
            ;;
    esac
fi
if [ -n "$PROXY_CREDS_FILE" ]; then
    if [ -z "$PROXY" ]; then
        echo "provision-connector.sh: PROXY_CREDS_FILE requires PROXY" >&2
        exit 1
    fi
    if [ ! -f "$PROXY_CREDS_FILE" ]; then
        echo "provision-connector.sh: PROXY_CREDS_FILE is not a file" >&2
        exit 1
    fi
fi

put_file() {
    install -D -m "$2" -o root -g root /dev/stdin "$1"
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends \
    chromium fonts-liberation

if ! id -u browser >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/browser \
        --shell /usr/sbin/nologin browser
fi
install -d -m 0700 -o browser -g browser /var/lib/browser

if ! id -u connector >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/kharon-connector \
        --shell /usr/sbin/nologin connector
fi
install -d -m 0700 -o connector -g connector /var/lib/kharon-connector
install -d -m 0755 -o root -g root /etc/kharon-connector

put_file /etc/sysctl.d/60-ptrace-scope.conf 0644 <<'CONF'
kernel.yama.ptrace_scope = 1
CONF
sysctl -q -p /etc/sysctl.d/60-ptrace-scope.conf

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

install -m 0755 -o root -g root "$CONNECTOR_BIN" /usr/local/bin/kharon-agent-connector
install -m 0400 -o connector -g connector "$TUNNEL_TOKEN_FILE" /etc/kharon-connector/token
if [ -n "$PROXY_CREDS_FILE" ]; then
    install -m 0400 -o connector -g connector "$PROXY_CREDS_FILE" /etc/kharon-connector/proxy-creds
fi

{
    printf 'broker = "%s"\n' "$BROKER_ADDR"
    printf 'broker_pin = "%s"\n' "$BROKER_PIN"
    printf 'agent_id = "%s"\n' "$AGENT_ID"
    printf 'token_file = "/etc/kharon-connector/token"\n'
    printf 'cdp = "127.0.0.1:%s"\n' "$CDP_PORT"
    if [ -n "$PROXY" ]; then
        printf 'proxy = "%s"\n' "$PROXY"
    fi
    if [ -n "$PROXY_CREDS_FILE" ]; then
        printf 'proxy_creds_file = "/etc/kharon-connector/proxy-creds"\n'
    fi
} | put_file /etc/kharon-connector/connector.toml 0644

put_file /etc/systemd/system/kharon-agent-connector.service 0644 <<'UNIT'
[Unit]
Description=Outbound TLS connector to loopback CDP
After=network-online.target browser.service
Wants=network-online.target

[Service]
User=connector
Group=connector
ExecStart=/usr/local/bin/kharon-agent-connector --config /etc/kharon-connector/connector.toml
Restart=always
RestartSec=1
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/kharon-connector

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable -q browser.service kharon-agent-connector.service
systemctl restart browser.service kharon-agent-connector.service

echo "Agent connector ready. It dials ${BROKER_ADDR} and relays to 127.0.0.1:${CDP_PORT}."
