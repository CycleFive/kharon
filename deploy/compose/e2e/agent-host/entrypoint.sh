#!/bin/sh
# Agent-host stand-in (compose E2E, issue #24). Starts Chromium with
# CDP on loopback, relays AGENT_HOST_ADDR:9222 to it (the WireGuard
# peer's role), and stays up after Chromium exits so the E2E can
# inspect the filesystem and profile after a clean browser shutdown.
#
# /e2e/page-spki: SPKI SHA-256 (base64) of the E2E test page's
# throwaway certificate, the only certificate trusted beyond the
# system store; PAGE_HOST_RULES maps the test hosts to the page server.
set -eu
: "${AGENT_HOST_ADDR:?}"
: "${PAGE_HOST_RULES:?}"
profile=/home/browser/profile
spki="$(cat /e2e/page-spki)"
chromium \
  --headless=new \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --no-first-run \
  --no-default-browser-check \
  --disable-background-networking \
  --password-store=basic \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9222 \
  --user-data-dir="$profile" \
  --host-resolver-rules="$PAGE_HOST_RULES" \
  --ignore-certificate-errors-spki-list="$spki" \
  about:blank &
browser=$!
socat "TCP-LISTEN:9222,bind=$AGENT_HOST_ADDR,fork,reuseaddr" TCP:127.0.0.1:9222 &
wait "$browser" || true
echo "agent-host: chromium exited" >&2
exec sleep infinity
