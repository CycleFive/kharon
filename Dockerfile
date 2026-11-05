# kharond image (issue #24, REQ-DEP-001): static musl binaries on
# distroless/static, non-root (10001:10001, SPEC §9), no shell, and
# nothing in the image needs a writable root filesystem: the only
# writable path is the /data volume (data_dir default, SPEC §9).
#
#   docker build -t kharon:dev .
#   docker run --read-only -v kharon-data:/data \
#     -v ./kharon.toml:/etc/kharon.toml:ro kharon:dev
#
# The image carries kharond (entrypoint) and the owner CLI `kharon`,
# so the owner can unlock with
# `docker exec -it <container> kharon unlock` against the owner
# socket in /data. Base images are pinned by digest; bump them
# together with a Trivy run (the `image` workflow).

# --- build: static (musl) release binaries -------------------------
FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
# aws-lc-sys (rustls's aws_lc_rs provider) compiles C with cc.
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# Static by default on the alpine (musl) host target. Symbols are
# stripped to keep the image under REQ-DEP-001's 30 MB. The ldd
# checks fail the build on any dynamic dependency: distroless/static
# has no libc to load.
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
RUN cargo build --release --locked -p kharond -p kharon-cli \
 && mkdir -p /out/data \
 && cp target/release/kharond target/release/kharon /out/ \
 && ! ldd /out/kharond 2>&1 | grep -q '=>' \
 && ! ldd /out/kharon 2>&1 | grep -q '=>'

# --- runtime --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/kharond /out/kharon /usr/local/bin/
# /data owned by the runtime uid, so a fresh named volume mounted
# there inherits it (bind mounts must be chowned by the operator).
COPY --from=build --chown=10001:10001 /out/data /data
USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/kharond"]
CMD ["--config", "/etc/kharon.toml"]
