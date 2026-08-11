# Both stages are digest-pinned so a RustyAuth release always rebuilds the
# reviewed vendor/sabledb gitlink on the same base-image contents.
FROM rust:1.97-slim-bookworm@sha256:96c0af8cf054fd006435089f0076729716784ec9be485bd655de59c55df105ce AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends clang libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/* \
  && cargo install cargo-auditable --version 0.7.5 --locked
WORKDIR /src

# Compile the locked third-party graph in a layer that changes only when a
# manifest or lockfile changes. SableDB source is patched frequently during
# qualification; copying the complete checkout before the first Cargo build
# forced RocksDB and the full dependency graph to rebuild on every source-only
# change in both CI and the production publisher.
COPY vendor/sabledb/Cargo.toml ./Cargo.toml
COPY vendor/sabledb/crates/libsabledb/Cargo.toml ./crates/libsabledb/Cargo.toml
COPY vendor/sabledb/crates/libsabledb/build.rs ./crates/libsabledb/build.rs
COPY vendor/sabledb/crates/sabledb/Cargo.toml ./crates/sabledb/Cargo.toml
COPY vendor/sabledb/crates/sabledb/build.rs ./crates/sabledb/build.rs
COPY vendor/sabledb/crates/sdb-admin/Cargo.toml ./crates/sdb-admin/Cargo.toml
COPY vendor/sabledb/crates/sdb-cli/Cargo.toml ./crates/sdb-cli/Cargo.toml
COPY vendor/sabledb/submodules/benchmark/Cargo.toml ./submodules/benchmark/Cargo.toml
COPY vendor/sabledb/submodules/benchmark/common/Cargo.toml ./submodules/benchmark/common/Cargo.toml
COPY vendor/sabledb/submodules/benchmark/sabledb-benchmark/Cargo.toml ./submodules/benchmark/sabledb-benchmark/Cargo.toml
COPY sabledb/Cargo.lock /rustyauth-sabledb.Cargo.lock
RUN cp /rustyauth-sabledb.Cargo.lock Cargo.lock \
  && mkdir -p \
     crates/libsabledb/src \
     crates/sabledb/src \
     crates/sdb-admin/src \
     crates/sdb-cli/src \
     submodules/benchmark/common/src \
     submodules/benchmark/sabledb-benchmark/src \
  && printf 'pub fn dependency_cache_marker() {}\n' > crates/libsabledb/src/lib.rs \
  && printf 'pub fn dependency_cache_marker() {}\n' > submodules/benchmark/common/src/lib.rs \
  && printf 'fn main() {}\n' > crates/sabledb/src/main.rs \
  && printf 'fn main() {}\n' > crates/sdb-admin/src/main.rs \
  && printf 'fn main() {}\n' > crates/sdb-cli/src/main.rs \
  && printf 'fn main() {}\n' > submodules/benchmark/sabledb-benchmark/src/main.rs \
  && cargo auditable build --locked --release --bin sabledb
COPY vendor/sabledb/ ./
COPY sabledb/Cargo.lock /rustyauth-sabledb.Cargo.lock
RUN cp /rustyauth-sabledb.Cargo.lock Cargo.lock \
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
