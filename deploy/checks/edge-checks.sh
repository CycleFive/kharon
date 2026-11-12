#!/usr/bin/env bash
# Edge checks for a published kharon deploy, run from the internet
# (off the tailnet, not from an agent host). Read-only: it sends no
# token, credential or password, and needs none.
#
#   GATEWAY=kharon.example.com OWNER=kharon-owner.example.com ./edge-checks.sh
#
# Environment:
#   GATEWAY    gateway hostname (required)
#   OWNER      owner UI hostname (optional; skips the owner checks if unset)
#   OAUTH=1    the deploy has [oauth]: check the discovery documents
#   ACCESS=1   Cloudflare Access fronts the owner hostname
#   CONNECTOR=0  the deploy has no `[connector] websocket = true`
#
# Exit 0 when every check passes, 1 otherwise. One line per check.
#
# Side effects, all expected:
# - The /connector checks send 3 requests. The edge's /connector rate
#   limit (5 per 10 s per IP on the Free form) counts them, so don't
#   run this script twice within 10 s. The /connector burst check in
#   docs/deployment.md is separate on purpose, because it gets the
#   source IP blocked.
# - The WebSocket check holds one of kharond's 8 pre-auth slots for a
#   few seconds.
# - The owner `POST /owner/panic` check (no Origin) is refused 403 and
#   writes one capped `owner_auth_fail` (`origin`) audit entry. It is
#   not a throttled route. With OAUTH=1, the `POST /oauth/token` check
#   is a deliberate `invalid_request`, and counts one failure in the
#   owner UI's per-source throttle (10 in 10 minutes blocks sign-in
#   from that address).
#
# Reconstructed for #290 from the checks in docs/deployment.md
# ("Verifying", "Checks on the first live deploy", "Over WebSocket")
# and the #201/#223 edge evidence. It is not a verbatim copy of the
# script used on 2026-11-12.
set -u
: "${GATEWAY:?set GATEWAY to the gateway hostname}"
OWNER=${OWNER:-}
OAUTH=${OAUTH:-0}
ACCESS=${ACCESS:-0}
CONNECTOR=${CONNECTOR:-1}
pass=0 fail=0

check() { # name expected-regex actual
  if [[ $3 =~ ^($2)$ ]]; then
    printf 'ok   %-58s %s\n' "$1" "$3"; pass=$((pass + 1))
  else
    printf 'FAIL %-58s %s (want %s)\n' "$1" "$3" "$2"; fail=$((fail + 1))
  fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

G="https://$GATEWAY"
# Gateway: everything but the allow-listed routes is 404 at the edge.
for p in / /ui /healthz /v1/status /v1/items /v1/openapi.json /owner/session /owner/approve/x /json/version /oauth/token; do
  check "gateway GET $p" 404 "$(code "$G$p")"
done
check "gateway POST /v1/fill" 404 "$(code -X POST "$G/v1/fill")"
check "gateway GET /mcp (POST only)" 404 "$(code "$G/mcp")"
check "gateway POST /mcp, no token" 401 \
  "$(code -X POST "$G/mcp" -H 'Content-Type: application/json' -d '{}')"
challenge=$(curl -s -o /dev/null -D - --max-time 10 -X POST "$G/mcp" \
  -H 'Content-Type: application/json' -d '{}' | tr -d '\r' | grep -i '^www-authenticate:' || true)
if [[ $OAUTH == 1 ]]; then
  check "gateway 401 challenge names resource_metadata" yes \
    "$([[ $challenge == *"resource_metadata=\"$G/.well-known/oauth-protected-resource/mcp\""* ]] && echo yes || echo no)"
  for p in /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/mcp; do
    body=$(curl -s --max-time 10 "$G$p")
    check "gateway GET $p names an authorization server" yes \
      "$([[ $body == *'"authorization_servers"'* ]] && echo yes || echo no)"
  done
else
  check "gateway 401 challenge is the bare one" yes \
    "$([[ -n $challenge && $challenge != *resource_metadata* ]] && echo yes || echo no)"
fi

if [[ $CONNECTOR == 1 ]]; then
  ws=(--http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket'
      -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='
      -H 'Sec-WebSocket-Protocol: kharon-connector.v1')
  # curl does not speak the inner protocol; it waits until --max-time
  # after the 101, and the status is what counts.
  check "gateway /connector upgrade" 101 \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${ws[@]}" "$G/connector")"
  check "gateway /connector upgrade with an Origin header" 403 \
    "$(code "${ws[@]}" -H "Origin: https://$GATEWAY" "$G/connector")"
  check "gateway /connector plain GET (no upgrade)" 400 "$(code "$G/connector")"
fi

if [[ -n $OWNER ]]; then
  O="https://$OWNER"
  # The owner hostname serves the owner UI only: no gateway routes.
  for p in /mcp /connector /v1/status /json/version; do
    check "owner GET $p" 404 "$(code "$O$p")"
  done
  if [[ $ACCESS == 1 ]]; then
    # No Access login: the edge answers (redirect to the login, or 403).
    check "owner GET / without an Access login" '302|403' "$(code "$O/")"
  else
    check "owner GET /" 200 "$(code "$O/")"
    check "owner GET /enroll" 200 "$(code "$O/enroll")"
    check "owner GET /owner/session, no cookie" 401 "$(code "$O/owner/session")"
    check "owner POST /owner/panic, no Origin" 403 \
      "$(code -X POST "$O/owner/panic" -H 'Content-Type: application/json' -d '{"confirm":true}')"
  fi
  if [[ $OAUTH == 1 ]]; then
    body=$(curl -s --max-time 10 "$O/.well-known/oauth-authorization-server")
    check "owner RFC 8414 metadata names $O as issuer" yes \
      "$([[ $body == *"\"issuer\":\"$O\""* ]] && echo yes || echo no)"
    check "owner POST /oauth/token, empty (reaches kharond)" 400 \
      "$(code -X POST "$O/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' -d '')"
  fi
fi

printf '%d ok, %d FAIL\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
