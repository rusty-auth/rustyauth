FROM rust:1.94.1-slim-bookworm AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends clang libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN find src -type f -exec touch {} + \
    && cargo build --locked --release \
    && cp /src/target/release/passkey-auth-service /usr/local/bin/passkey-auth-service

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="RustyAuth" \
      org.opencontainers.image.description="Built in Rust. Built on SableDB. Built for passkeys." \
      org.opencontainers.image.source="https://github.com/rusty-auth/rustyauth" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin passkey-auth
COPY --from=build /usr/local/bin/passkey-auth-service /usr/local/bin/passkey-auth-service
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html /usr/share/doc/rustyauth/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/passkey-auth-service"]
