# Base images are pinned by digest so a rebuild cannot silently pick up a re-tagged upstream image.
# Refresh a digest with `docker buildx imagetools inspect <image>:<tag>` and update the tag with it.
FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends clang libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/* \
  && cargo install cargo-auditable --version 0.7.5 --locked
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
COPY rustyauth.example.yaml rustyauth.fleet.example.yaml ./
COPY src ./src
# The stub-built artifacts are newer than the sources just copied; touch so cargo
# rebuilds the workspace crate against the cached dependencies.
RUN find src -type f -exec touch {} + \
    && cargo auditable build --locked --release \
    && cp /src/target/release/rustyauth /usr/local/bin/rustyauth
RUN install -d /runtime-root/etc/rustyauth /runtime-root/etc/ssl/certs \
    && install -d -m 1777 /runtime-root/tmp \
    && ldd /usr/local/bin/rustyauth \
       | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
       | sort -u > /tmp/runtime-libraries \
    && while IFS= read -r library; do \
         cp --parents --dereference "$library" /runtime-root; \
       done < /tmp/runtime-libraries \
    && cp /etc/ssl/certs/ca-certificates.crt /runtime-root/etc/ssl/certs/ \
    && cp /etc/nsswitch.conf /runtime-root/etc/

FROM scratch
LABEL org.opencontainers.image.title="RustyAuth" \
      org.opencontainers.image.description="Built in Rust. Built on SableDB. Built for passkeys." \
      org.opencontainers.image.source="https://github.com/rusty-auth/rustyauth" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /runtime-root/ /
COPY --from=build /usr/local/bin/rustyauth /usr/local/bin/rustyauth
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html /usr/share/doc/rustyauth/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rustyauth"]
