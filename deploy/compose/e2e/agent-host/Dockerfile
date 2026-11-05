# Agent-host stand-in for the compose E2E (issue #24): Debian's
# Chromium running as the unprivileged `browser` user, with the
# password manager and autofill saving disabled by managed policy
# (REQ-ARCH-004, REQ-GOAL-002), CDP on 127.0.0.1:9222 only, and a
# socat relay on the wg address standing in for the WireGuard peer
# (in deployment kharond reaches 127.0.0.1:9222 through the tunnel;
# see the agent-host guide). TEST IMAGE ONLY: it carries sqlite3 and
# socat for the E2E's checks and runs Chromium with --no-sandbox
# because CI runners refuse the unprivileged user namespaces the
# sandbox needs. No kharon binary or kharon config is installed here
# (REQ-ARCH-001).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation socat sqlite3 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10002 browser
COPY policy.json /etc/chromium/policies/managed/kharon-agent-host.json
COPY entrypoint.sh /usr/local/bin/agent-host
USER browser
ENTRYPOINT ["/usr/local/bin/agent-host"]
