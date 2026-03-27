# Cross-compilation images — selected by TARGETARCH (set automatically by buildx)
ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=registry_token \
    mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "shroudb-cratesio"\n\n[source.shroudb-cratesio]\nregistry = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\n\n[registries.shroudb-cratesio]\nindex = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\ncredential-provider = ["cargo:token"]\n\n[registries.shroudb]\nindex = "sparse+https://crates.shroudb.dev/api/v1/crates/"\ncredential-provider = ["cargo:token"]\n' > /root/.cargo/config.toml && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    CARGO_REGISTRIES_SHROUDB_CRATESIO_TOKEN="$(cat /run/secrets/registry_token)" \
    CARGO_REGISTRIES_SHROUDB_TOKEN="$(cat /run/secrets/registry_token)" \
    cargo build --release --target "$RUST_TARGET" \
    -p shroudb-veil-server -p shroudb-veil-cli && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-veil" /out/ && \
    cp "target/$RUST_TARGET/release/shroudb-veil-cli" /out/

# --- shroudb-veil: encrypted search over E2EE data ---
FROM alpine:3.21 AS shroudb-veil
RUN adduser -D -u 65532 shroudb && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Veil" \
      org.opencontainers.image.description="Encrypted search over E2EE data" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-veil" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-veil" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-veil /shroudb-veil
VOLUME /data
WORKDIR /data
USER shroudb
EXPOSE 6599
ENTRYPOINT ["/shroudb-veil"]

# --- shroudb-veil-cli: command-line client ---
FROM alpine:3.21 AS shroudb-veil-cli
RUN adduser -D -u 65532 shroudb
LABEL org.opencontainers.image.title="ShrouDB Veil CLI" \
      org.opencontainers.image.description="Command-line client for ShrouDB Veil" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-veil" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-veil" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-veil-cli /shroudb-veil-cli
USER shroudb
ENTRYPOINT ["/shroudb-veil-cli"]
