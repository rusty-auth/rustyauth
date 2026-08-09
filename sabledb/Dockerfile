# Both stages are digest-pinned so a RustyAuth release always rebuilds the
# reviewed SableDB revision on the same base-image contents.
FROM rust:1.97-slim-bookworm@sha256:96c0af8cf054fd006435089f0076729716784ec9be485bd655de59c55df105ce AS build

ARG SABLEDB_REVISION=8bebc4a60dee404e95608b40ec5c58799e7fa820
RUN apt-get update \
  && apt-get install -y --no-install-recommends clang git libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --filter=blob:none https://github.com/sabledb-io/sabledb.git . \
  && git checkout --detach "$SABLEDB_REVISION" \
  && git submodule update --init --recursive \
  && cargo build --release --bin sabledb

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libssl3 libclang1 \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --user-group --uid 10002 --home /var/lib/sabledb --shell /usr/sbin/nologin sabledb \
  && mkdir -p /var/lib/sabledb/data /var/lib/sabledb/conf \
  && chown -R sabledb:sabledb /var/lib/sabledb
COPY --from=build /src/target/release/sabledb /usr/local/bin/sabledb
COPY --from=build /src/LICENSE /usr/share/licenses/sabledb/LICENSE
COPY server.ini /etc/sabledb/server.ini
USER 10002:10002
EXPOSE 6379
ENTRYPOINT ["/usr/local/bin/sabledb"]
CMD ["/etc/sabledb/server.ini"]
