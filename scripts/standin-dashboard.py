#!/usr/bin/env python3
"""Stand-in dashboard for the kharon v0.3.0 (#235 phase 2) live test.

Plays a real dashboard end to end against a live deploy, interactively:

  1. PKCE authorization-code flow against the owner hostname. The
     operator (Lothrop) opens the printed authorize URL, consents with
     his passkey, and pastes the final redirect URL back here.
     NOTE: kharond's codes live 60 seconds — this script sits at the
     paste prompt *before* consent, and the paste must be fast.
  2. Redeems the code at POST /oauth/token (resource pinned to the
     deploy's /mcp URL) for the MCP token pair.
  3. Pre-attach check: a kharon_fill with no connector session must
     answer `no_browser`.
  4. Connector spawn: the extension grant
     (grant_type=urn:kharon:oauth:grant-type:connector,
     resource=<deploy>/connector) exchanges the MCP family's refresh
     token for the connector family. The connector access token is
     written, mode 0600, to a token file — never printed.
  5. Pin discipline (#235 D1): the broker pin is read from a
     provisioned local file (--broker-pin-file, mode 0400/0600) and
     *compared* with the pin published at
     /.well-known/oauth-protected-resource/connector. A mismatch is a
     hard stop. The published value is never adopted.
  6. Starts kharon-agent-connector (ws transport) with that token
     file, agent_id = the Connect identity learned from kharon_status
     (the hello's claimed agent_id must equal the token's identity,
     connector.rs #235 D4). KNOWN MASTER GAP at time of writing:
     kharon-agent-connector's read_token still refuses any token not
     starting kh_tunnel_ — if the binary rejects the kh_at_ file,
     this script reports that verbatim; it is a test finding, not a
     script bug.
  7. Post-attach check: kharon_context, then a kharon_fill that must
     reach an owner-UI approval (the operator approves it) and fill.
  8. The connector token presented to /mcp must answer 401
     (connector audience, #304).
  9. Disconnect: stop the connector, wait, and the same fill must
     answer `no_browser` again. The operator confirms the live
     session on the owner UI's Connections page when prompted.

The CIMD this client uses is hosted (for the test) at
  https://minplus.xyz/kharon-test-client.json
and that exact URL must be listed in the deploy's [oauth].clients.
cimd.rs refuses loopback redirect URIs (all redirect_uris must be
https, non-localhost), so the redirect is
  https://minplus.xyz/oauth/callback
a static page that displays the returned code for paste-back; this
script never follows it.

No token, refresh token, or pin is ever printed, logged, or written
anywhere except the 0600 token/state files under --workdir.
Token *prefixes and lengths only* are reported, as in past live tests.

Usage:
  python3 scripts/standin-dashboard.py \
      --broker-pin-file /path/to/provisioned/pin.txt \
      --connector-bin /path/to/kharon-agent-connector \
      --item-id <uuid-from-kharon_list> \
      [--cdp 127.0.0.1:9222] [--workdir ./standin-run] \
      [--target-id <cdp-target-id-of-login-tab>]

Stdlib only. Python 3.11+.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = "https://kharon-owner.twkr.io"
PUBLIC = "https://kharon.twkr.io"
MCP_URL = PUBLIC + "/mcp"
MCP_RESOURCE = MCP_URL
CONNECTOR_RESOURCE = PUBLIC + "/connector"
CONNECTOR_METADATA = PUBLIC + "/.well-known/oauth-protected-resource/connector"
AS_METADATA = OWNER + "/.well-known/oauth-authorization-server"
TOKEN_URL = OWNER + "/oauth/token"
AUTHORIZE_URL = OWNER + "/oauth/authorize"

CLIENT_ID = "https://minplus.xyz/kharon-test-client.json"
REDIRECT_URI = "https://minplus.xyz/oauth/callback"
CONNECTOR_GRANT = "urn:kharon:oauth:grant-type:connector"
SCOPES = "kharon:read kharon:fill kharon:request"
PROTOCOL = "2025-11-25"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def die(msg: str) -> "SystemExit":
    print(f"\nSTOP: {msg}", file=sys.stderr)
    raise SystemExit(1)


def http(method, url, *, headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers or {})


def post_form(url, form: dict):
    body = urllib.parse.urlencode(form).encode()
    return http("POST", url, headers={
        "Content-Type": "application/x-www-form-urlencoded"}, data=body)


def describe(token: str) -> str:
    """Prefix + length only. The value itself never leaves the process."""
    return f"{token.split('_', 2)[0]}_{token.split('_', 2)[1]}_… len={len(token)}" \
        if token.count("_") >= 2 else f"len={len(token)}"


class Mcp:
    def __init__(self, access_token: str):
        self.token = access_token
        self._id = 0

    def call_raw(self, method, params=None, *, token=None):
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            payload["params"] = params
        status, text, _ = http("POST", MCP_URL, headers={
            "Authorization": f"Bearer {token or self.token}",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL,
        }, data=json.dumps(payload).encode(), timeout=120)
        return status, text

    def initialize(self):
        status, text = self.call_raw("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "kharon-standin-dashboard", "version": "0"}})
        if status != 200:
            die(f"initialize: HTTP {status}: {text[:300]}")
        http("POST", MCP_URL, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL,
        }, data=json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())

    def tool(self, name, arguments=None, *, token=None):
        return self.call_raw("tools/call",
                             {"name": name, "arguments": arguments or {}},
                             token=token)


def tool_text(status, text):
    try:
        v = json.loads(text)
    except Exception:
        return text
    result = v.get("result") or {}
    parts = [c.get("text", "") for c in result.get("content", [])
             if isinstance(c, dict)]
    return " ".join(parts) if parts else json.dumps(v)[:600]


def write_secret_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(path, 0o600)


def read_pin_file(path):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        die(f"broker pin file {path} must be mode 0400 or 0600 (is {oct(mode)})")
    pin = open(path).read().strip().lower()
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        die("broker pin file must hold exactly 64 hex characters")
    return pin


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--broker-pin-file", required=True,
                    help="provisioned broker pin (64 hex, mode 0400/0600)")
    ap.add_argument("--connector-bin", required=True,
                    help="path to kharon-agent-connector built from master")
    ap.add_argument("--item-id", required=True,
                    help="vault item id (uuid) the fill checks use")
    ap.add_argument("--cdp", default="127.0.0.1:9222",
                    help="loopback CDP address of the connector's Chromium")
    ap.add_argument("--workdir", default="./standin-run",
                    help="where 0600 token/config files are written")
    ap.add_argument("--proxy", default=None,
                    help="optional http://host:port CONNECT proxy for the "
                         "connector's ws leg (e.g. on the Muse host: "
                         "http://hatch-egress-proxy:3130)")
    ap.add_argument("--target-id", default=None,
                    help="CDP target id of the login tab (post-attach fill); "
                         "prompted for if omitted")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    pin_provisioned = read_pin_file(args.broker_pin_file)

    # --- 0. Discovery sanity (no secrets) ---------------------------------
    print("== discovery ==")
    status, text, _ = http("GET", AS_METADATA)
    if status != 200:
        die(f"AS metadata: HTTP {status} — is [oauth] on on VM 125 yet? "
            f"(pre-phase-2 deploys 404 here). Body: {text[:200]}")
    meta = json.loads(text)
    print(f"issuer={meta.get('issuer')} grants={meta.get('grant_types_supported')}")
    if CONNECTOR_GRANT not in (meta.get("grant_types_supported") or []):
        die("AS metadata does not list the connector grant type")

    status, text, _ = http("GET", CONNECTOR_METADATA)
    if status != 200:
        die(f"connector protected-resource metadata: HTTP {status} "
            "(needs [oauth] + a [connector] certificate; 404 otherwise)")
    cmeta = json.loads(text)
    pin_published = (cmeta.get("kharon_connector_pin") or "").lower()
    if pin_published != pin_provisioned:
        die("broker pin MISMATCH: the published pin does not equal the "
            "provisioned pin. Hard stop (deployment.md: compare, never adopt).")
    print("broker pin: provisioned == published (value not shown)")

    # --- 1. PKCE authorization code ---------------------------------------
    print("\n== authorize (PKCE S256) ==")
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))
    q = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "resource": MCP_RESOURCE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    print("Open this URL in the owner's browser and consent with the passkey:")
    print(f"\n  {AUTHORIZE_URL}?{q}\n")
    print("After approving, the browser lands on the callback page showing")
    print("the full redirect URL. Paste that whole URL here WITHIN 60 SECONDS")
    print("(codes expire after 60s), then press Enter.")
    pasted = input("redirect URL> ").strip()
    got = urllib.parse.parse_qs(urllib.parse.urlparse(pasted).query)
    if got.get("state", [None])[0] != state:
        die("state mismatch in pasted redirect URL")
    if "error" in got:
        die(f"authorize returned error: {got['error'][0]}")
    code = (got.get("code") or [None])[0]
    if not code:
        die("no code in pasted redirect URL")

    # --- 2. Redeem for the MCP pair ---------------------------------------
    print("\n== redeem code ==")
    status, text, _ = post_form(TOKEN_URL, {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "resource": MCP_RESOURCE,
    })
    if status != 200:
        die(f"token redemption: HTTP {status}: {text[:300]} "
            "(was the paste inside the 60s code lifetime?)")
    mcp_pair = json.loads(text)
    mcp_access, mcp_refresh = mcp_pair["access_token"], mcp_pair["refresh_token"]
    print(f"mcp access:  {describe(mcp_access)}")
    print(f"mcp refresh: {describe(mcp_refresh)}  scope={mcp_pair.get('scope')}")

    mcp = Mcp(mcp_access)
    mcp.initialize()
    status, text = mcp.tool("kharon_status")
    status_body = tool_text(status, text)
    print(f"kharon_status: HTTP {status}: {status_body[:300]}")
    try:
        identity = json.loads(status_body).get("agent_id") or ""
    except Exception:
        identity = ""
    if not identity.startswith("c-"):
        print("WARNING: kharon_status did not yield a c-… identity; the "
              "connector hello's agent_id must equal the Connect identity. "
              f"Got: {identity!r}")
        identity = input("Connect identity (c-…) as shown on Connections page> ").strip()

    fill_args = {
        "item_id": args.item_id,
        "target": {"cdp_target_id": args.target_id or "standin-pre-attach"},
        "fields": [{"kind": "username"}, {"kind": "password"}],
        "submit": False,
    }

    # --- 3. Pre-attach fill: no_browser ------------------------------------
    print("\n== check 1: fill before connector attaches -> no_browser ==")
    status, text = mcp.tool("kharon_fill", fill_args)
    body = tool_text(status, text)
    print(f"HTTP {status}: {body[:300]}")
    print("PASS" if "no_browser" in body else
          "CHECK FAILED: expected no_browser before attach")

    # --- 4. Connector spawn -------------------------------------------------
    print("\n== connector spawn (extension grant) ==")
    status, text, _ = post_form(TOKEN_URL, {
        "grant_type": CONNECTOR_GRANT,
        "refresh_token": mcp_refresh,
        "client_id": CLIENT_ID,
        "resource": CONNECTOR_RESOURCE,
    })
    if status != 200:
        die(f"connector spawn: HTTP {status}: {text[:300]} "
            "(unauthorized_client here means the CIMD's connector-grant "
            "declaration was not recorded at consent, #235 D3)")
    conn_pair = json.loads(text)
    conn_access, conn_refresh = conn_pair["access_token"], conn_pair["refresh_token"]
    print(f"connector access:  {describe(conn_access)}")
    print(f"connector refresh: {describe(conn_refresh)}  scope={conn_pair.get('scope')}")
    write_secret_file(os.path.join(args.workdir, "mcp-refresh.txt"), mcp_refresh)
    write_secret_file(os.path.join(args.workdir, "connector-refresh.txt"), conn_refresh)

    # --- 5. Connector token on /mcp: 401 ------------------------------------
    print("\n== check: connector token presented to /mcp -> 401 ==")
    status, text = mcp.tool("kharon_status", token=conn_access)
    print(f"HTTP {status}")
    print("PASS" if status == 401 else
          "CHECK FAILED: connector-audience token was accepted on /mcp")

    # --- 6. Start the connector ---------------------------------------------
    print("\n== start kharon-agent-connector ==")
    token_file = os.path.join(args.workdir, "connector-token")
    write_secret_file(token_file, conn_access + "\n")
    config_path = os.path.join(args.workdir, "connector.toml")
    with open(config_path, "w") as f:
        f.write('transport = "ws"\n')
        f.write(f'broker_url = "wss://kharon.twkr.io/connector"\n')
        f.write(f'broker_pin = "{pin_provisioned}"\n')
        f.write(f'agent_id = "{identity}"\n')
        f.write(f'token_file = "{os.path.abspath(token_file)}"\n')
        f.write(f'cdp = "{args.cdp}"\n')
        if args.proxy:
            f.write(f'proxy = "{args.proxy}"\n')
    os.chmod(config_path, 0o600)
    proc = subprocess.Popen(
        [args.connector_bin, "--config", config_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(3)
    if proc.poll() is not None:
        out = proc.stdout.read() if proc.stdout else ""
        die(f"connector exited immediately (rc={proc.returncode}):\n{out[:800]}\n"
            "If this is the kh_tunnel_-prefix refusal of a kh_at_ token file, "
            "that is the known master gap flagged in #general — the broker "
            "side accepts kh_at_, the client binary's read_token does not.")
    print("connector running; confirm 'agent connector attached' broker-side,")
    input("and that the Connections page shows the live session, then Enter> ")

    # --- 7. Post-attach fill --------------------------------------------------
    print("\n== check 2: fill after attach reaches approval and fills ==")
    status, text = mcp.tool("kharon_context")
    print(f"kharon_context: HTTP {status}: {tool_text(status, text)[:300]}")
    if not args.target_id:
        fill_args["target"]["cdp_target_id"] = input(
            "CDP target id of the login tab in that context> ").strip()
    print("Calling kharon_fill — approve it in the owner UI when it appears…")
    status, text = mcp.tool("kharon_fill", fill_args)
    body = tool_text(status, text)
    print(f"HTTP {status}: {body[:400]}")
    print("PASS (verify the fields filled in the tab; lengths only broker-side)"
          if status == 200 and "no_browser" not in body else
          "CHECK FAILED: post-attach fill did not complete")

    # --- 8. Disconnect: no_browser again ---------------------------------------
    print("\n== check 3: disconnect -> no_browser again ==")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print("connector stopped; waiting 5s for the session to drop…")
    time.sleep(5)
    status, text = mcp.tool("kharon_fill", fill_args)
    body = tool_text(status, text)
    print(f"HTTP {status}: {body[:300]}")
    print("PASS" if "no_browser" in body else
          "CHECK FAILED: expected no_browser after disconnect")

    print("\nDone. Remaining manual confirmation: the Connections page showed")
    print("the live session during step 7. Token files are in "
          f"{args.workdir} (0600) — shred them when the test is over.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
