# Base images are pinned by digest so a rebuild cannot silently pick up a re-tagged upstream image.
# Refresh a digest with `docker buildx imagetools inspect <image>:<tag>` and update the tag with it.
FROM rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends clang libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
# Dependency layer: compile the full dependency graph (and the protobuf codegen in
# build.rs) against stub sources, so it caches until Cargo.toml, Cargo.lock,
# build.rs or the contracts change. Source edits never recompile dependencies.
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --locked --release \
    && rm -rf src
COPY src ./src
# The stub-built artifacts are newer than the sources just copied; touch so cargo
# rebuilds the workspace crate against the cached dependencies.
RUN find src -type f -exec touch {} + \
    && cargo build --locked --release \
    && cp /src/target/release/rustyauth /usr/local/bin/rustyauth

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
LABEL org.opencontainers.image.title="RustyAuth" \
      org.opencontainers.image.description="Built in Rust. Built on SableDB. Built for passkeys." \
      org.opencontainers.image.source="https://github.com/rusty-auth/rustyauth" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin passkey-auth
COPY --from=build /usr/local/bin/rustyauth /usr/local/bin/rustyauth
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html /usr/share/doc/rustyauth/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rustyauth"]
