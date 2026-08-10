# Both stages are digest-pinned so a RustyAuth release always rebuilds the
# reviewed SableDB revision on the same base-image contents.
FROM rust:1.97-slim-bookworm@sha256:96c0af8cf054fd006435089f0076729716784ec9be485bd655de59c55df105ce AS build

ARG SABLEDB_REVISION=8bebc4a60dee404e95608b40ec5c58799e7fa820
RUN apt-get update \
  && apt-get install -y --no-install-recommends clang git libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/* \
  && cargo install cargo-auditable --version 0.7.5 --locked
WORKDIR /src
COPY sabledb/Cargo.lock /rustyauth-sabledb.Cargo.lock
RUN git clone --filter=blob:none https://github.com/sabledb-io/sabledb.git . \
  && git checkout --detach "$SABLEDB_REVISION" \
  && git submodule update --init --recursive \
  && cp /rustyauth-sabledb.Cargo.lock Cargo.lock \
  && cargo auditable build --locked --release --bin sabledb
RUN install -d /runtime-root/etc/ssl/certs \
  && install -d -m 1777 /runtime-root/tmp \
  && install -d -m 0750 -o 10002 -g 10002 \
     /runtime-root/var/lib/sabledb/data /runtime-root/var/lib/sabledb/conf \
  && ldd /src/target/release/sabledb \
     | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
     | sort -u > /tmp/runtime-libraries \
  && while IFS= read -r library; do \
       cp --parents --dereference "$library" /runtime-root; \
     done < /tmp/runtime-libraries \
  && cp /etc/ssl/certs/ca-certificates.crt /runtime-root/etc/ssl/certs/ \
  && cp /etc/nsswitch.conf /runtime-root/etc/

FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS healthcheck
COPY container-healthcheck /src/container-healthcheck
WORKDIR /src/container-healthcheck
RUN go test ./... \
  && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/container-healthcheck . \
  && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
     -o /usr/local/bin/sabledb-entrypoint ./sabledb-entrypoint

FROM scratch
COPY --from=build /runtime-root/ /
COPY --from=build /src/target/release/sabledb /usr/local/bin/sabledb
COPY --from=healthcheck /usr/local/bin/container-healthcheck /usr/local/bin/container-healthcheck
COPY --from=healthcheck /usr/local/bin/sabledb-entrypoint /usr/local/bin/sabledb-entrypoint
COPY --from=build /src/LICENSE /usr/share/licenses/sabledb/LICENSE
COPY --chown=10002:10002 sabledb/server.ini /etc/sabledb/server.ini
# Railway and several other container platforms attach a new persistent volume
# as root:root without applying Kubernetes fsGroup semantics. The tiny PID 1
# below owns only the volume bootstrap: it validates and prepares the three
# expected directories, drops supplementary groups, gid and uid to 10002, then
# execs SableDB. SableDB itself never runs as root.
USER 0:0
EXPOSE 6379
ENTRYPOINT ["/usr/local/bin/sabledb-entrypoint"]
CMD ["/etc/sabledb/server.ini"]
