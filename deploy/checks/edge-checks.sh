#!/usr/bin/env bash
# Edge checks for a published kharon deploy, run from the internet
# (off the tailnet, not from an agent host). It sends no real token,
# credential or password, and needs none.
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
# Exit 0 when every scored check passes, 1 otherwise. One line per
# check; `info` lines are reported but fail only on a 5xx or no answer.
# The first line names the host it ran from, the UTC time and the
# hostnames, so a pasted run describes itself.
#
# Don't run this from a monitor or on a timer: it writes audit entries
# (below), and those are meant to be read by a person.
#
# Side effects, all expected:
# - The /connector checks send 3 requests to the gateway. The edge's
#   /connector rate limit (5 per 10 s per IP) counts them. The Free
#   form's expression is path-only, so with OWNER set the owner
#   `GET /connector` check counts too: 4 on the Free form.
#   Don't run this script twice within 10 s. The /connector burst
#   check in docs/deployment.md is separate on purpose, because it
#   gets the source IP blocked.
# - The WebSocket check holds one of kharond's 8 pre-auth slots for a
#   few seconds.
# - The `POST /mcp` checks with no token and with a made-up one count
#   against the gateway's per-IP /mcp budget like any request. The
#   made-up bearer costs one Argon2id evaluation; there is no agent
#   auth-failure audit event, so it writes no audit entry.
# - The owner `POST /owner/login/options` check (no Origin) is refused
#   403 by public mode's Origin rule and writes one capped
#   `owner_auth_fail` (`origin`) audit entry. A refused Origin is never
#   counted by the throttle on any route. With OAUTH=1, the
#   `POST /oauth/token` check is a deliberate `invalid_request`, and
#   counts one failure in the owner UI's per-source throttle (10 in
#   10 minutes blocks sign-in from that address).
#
# Reconstructed for #290 from the checks in docs/deployment.md
# ("Verifying", "Checks on the first live deploy", "Over WebSocket")
# and the #201/#223 edge evidence, then reconciled against the cases
# of the 26-case script used on 2026-11-12.
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
info() { # name actual: any 1xx-4xx answer is fine
  if [[ $2 =~ ^[1-4][0-9][0-9]$ ]]; then
    printf 'info %-58s %s\n' "$1" "$2"
  else
    printf 'FAIL %-58s %s (want any non-5xx answer)\n' "$1" "$2"; fail=$((fail + 1))
  fi
}
code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

printf '# edge-checks from %s at %s: gateway=%s owner=%s oauth=%s access=%s connector=%s\n' \
  "$(hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "https://$GATEWAY" \
  "${OWNER:+https://$OWNER}" "$OAUTH" "$ACCESS" "$CONNECTOR"

G="https://$GATEWAY"
# Gateway: everything but the allow-listed routes is 404 at the edge,
# the vault's own paths included (#201: vault unreachable publicly).
for p in / /ui /healthz /v1/status /v1/items /v1/openapi.json /owner/session /owner/approve/x \
         /json/version /oauth/token /api/sync /identity/connect/token; do
  check "gateway GET $p" 404 "$(code "$G$p")"
done
check "gateway POST /v1/fill" 404 "$(code -X POST "$G/v1/fill")"
check "gateway GET /mcp (POST only)" 404 "$(code "$G/mcp")"
# The route regex is anchored and case-sensitive.
for p in /mcp/ /MCP //mcp; do
  check "gateway POST $p" 404 "$(code -X POST "$G$p" -H 'Content-Type: application/json' -d '{}')"
done
info "gateway POST /mcp?x=1" \
  "$(code -X POST "$G/mcp?x=1" -H 'Content-Type: application/json' -d '{}')"
check "gateway POST /mcp, no token" 401 \
  "$(code -X POST "$G/mcp" -H 'Content-Type: application/json' -d '{}')"
check "gateway POST /mcp, made-up bearer" 401 \
  "$(code -X POST "$G/mcp" -H 'Authorization: Bearer kh_agent_bogus_0000' \
     -H 'Content-Type: application/json' -d '{}')"
challenge=$(curl -s --path-as-is -o /dev/null -D - --max-time 10 -X POST "$G/mcp" \
  -H 'Content-Type: application/json' -d '{}' | tr -d '\r' | grep -i '^www-authenticate:' || true)
if [[ $OAUTH == 1 ]]; then
  check "gateway 401 challenge names resource_metadata" yes \
    "$([[ $challenge == *"resource_metadata=\"$G/.well-known/oauth-protected-resource/mcp\""* ]] && echo yes || echo no)"
  for p in /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/mcp; do
    body=$(curl -s --path-as-is --max-time 10 "$G$p")
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
    "$(curl -s --path-as-is -o /dev/null -w '%{http_code}' --max-time 3 "${ws[@]}" "$G/connector")"
  check "gateway /connector upgrade with an Origin header" 403 \
    "$(code "${ws[@]}" -H "Origin: https://$GATEWAY" "$G/connector")"
  check "gateway /connector plain GET (no upgrade)" 400 "$(code "$G/connector")"
fi

if [[ -n $OWNER ]]; then
  O="https://$OWNER"
  if [[ $ACCESS == 1 ]]; then
    # Behind Access the edge answers every path on the owner hostname
    # with the login redirect (or 403), so only that is checkable.
    for p in / /mcp /connector /v1/status /json/version /api/sync; do
      check "owner GET $p without an Access login" '302|403' "$(code "$O$p")"
    done
  else
    # The owner hostname serves the owner UI only: no gateway routes,
    # no vault paths.
    for p in /mcp /connector /v1/status /json/version /api/sync /identity/connect/token; do
      check "owner GET $p" 404 "$(code "$O$p")"
    done
    # With the owner Origin the request passes the Origin rule, so the
    # 404 comes from kharond's router.
    for p in /mcp /v1/fill; do
      check "owner POST $p with the owner Origin" 404 \
        "$(code -X POST "$O$p" -H "Origin: $O" -H 'Content-Type: application/json' -d '{}')"
    done
    check "owner GET /" 200 "$(code "$O/")"
    check "owner GET /enroll" 200 "$(code "$O/enroll")"
    check "owner GET /owner/session, no cookie" 401 "$(code "$O/owner/session")"
    # A session-less route: refused only by public mode's Origin rule.
    check "owner POST /owner/login/options, no Origin" 403 \
      "$(code -X POST "$O/owner/login/options")"
  fi
  if [[ $OAUTH == 1 ]]; then
    body=$(curl -s --path-as-is --max-time 10 "$O/.well-known/oauth-authorization-server")
    check "owner RFC 8414 metadata names $O as issuer" yes \
      "$([[ $body == *"\"issuer\":\"$O\""* ]] && echo yes || echo no)"
    check "owner POST /oauth/token, empty (reaches kharond)" 400 \
      "$(code -X POST "$O/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' -d '')"
  fi
fi

printf '%d ok, %d FAIL\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
