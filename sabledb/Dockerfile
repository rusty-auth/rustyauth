FROM rust:1.97-slim-bookworm AS build

ARG SABLEDB_REVISION=8bebc4a60dee404e95608b40ec5c58799e7fa820
RUN apt-get update \
  && apt-get install -y --no-install-recommends clang git libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --filter=blob:none https://github.com/sabledb-io/sabledb.git . \
  && git checkout --detach "$SABLEDB_REVISION" \
  && git submodule update --init --recursive \
  && cargo build --release --bin sabledb

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libssl3 libclang1 procps \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10002 --home /var/lib/sabledb --shell /usr/sbin/nologin sabledb \
  && mkdir -p /var/lib/sabledb/data /var/lib/sabledb/conf \
  && chown -R sabledb:sabledb /var/lib/sabledb
COPY --from=build /src/target/release/sabledb /usr/local/bin/sabledb
COPY --from=build /src/LICENSE /usr/share/licenses/sabledb/LICENSE
COPY server.ini /etc/sabledb/server.ini
USER 10002:10002
EXPOSE 6379
ENTRYPOINT ["/usr/local/bin/sabledb", "/etc/sabledb/server.ini"]
