# Agent-host connector image for the path-B compose E2E (issue #220):
# kharon-agent-connector as a static musl binary on distroless/static,
# non-root. TEST IMAGE ONLY; the build context is the repo root (the
# root .dockerignore applies), set by compose.e2e-ws.yml. The base
# images are the same digests as the root Dockerfile.

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
# aws-lc-sys (rustls's aws_lc_rs provider) compiles C with cc.
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
# The ldd check fails the build on any dynamic dependency:
# distroless/static has no libc to load.
RUN cargo build --release --locked -p kharon-agent-connector \
 && mkdir -p /out \
 && cp target/release/kharon-agent-connector /out/ \
 && ! ldd /out/kharon-agent-connector 2>&1 | grep -q '=>'

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/kharon-agent-connector /usr/local/bin/kharon-agent-connector
USER nonroot
ENTRYPOINT ["/usr/local/bin/kharon-agent-connector"]
