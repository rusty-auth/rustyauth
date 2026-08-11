#!/usr/bin/env bash
set -euo pipefail

image=${RUSTYAUTH_SMOKE_SABLEDB_IMAGE:-rustyauth-sabledb:ci}
run_id=$$
railway_volume="rustyauth-sable-volume-${run_id}"
railway_container="rustyauth-sable-volume-${run_id}"
kubernetes_volume="rustyauth-sable-fsgroup-${run_id}"
kubernetes_container="rustyauth-sable-fsgroup-${run_id}"
storage_accounts=250
maximum_storage_mb=64

cleanup() {
  exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    if docker container inspect "$railway_container" >/dev/null 2>&1; then
      docker logs --tail 200 "$railway_container" 2>&1 || true
    fi
    if docker container inspect "$kubernetes_container" >/dev/null 2>&1; then
      docker logs --tail 200 "$kubernetes_container" 2>&1 || true
    fi
  fi
  docker rm -f "$railway_container" "$kubernetes_container" >/dev/null 2>&1 || true
  docker volume rm "$railway_volume" "$kubernetes_volume" >/dev/null 2>&1 || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

wait_until_ready() {
  container=$1
  for attempt in $(seq 1 60); do
    if docker exec "$container" /usr/local/bin/container-healthcheck redis 127.0.0.1:6379 >/dev/null 2>&1; then
      return
    fi
    if [[ $attempt -eq 60 ]]; then
      echo "SableDB did not become ready" >&2
      exit 1
    fi
    sleep 1
  done
}

assert_unprivileged_database() {
  container=$1
  docker top "$container" -eo uid,pid,comm | awk '
    NR > 1 && $3 == "sabledb" { if ($1 != "10002") exit 1; found = 1 }
    END { if (!found) exit 1 }
  '
}

mapped_port() {
  docker port "$1" 6379/tcp | awk -F: 'NR == 1 { print $NF }'
}

exercise_transaction_storage() {
  port=$(mapped_port "$railway_container")
  python3 - "$port" "$storage_accounts" <<'PY'
import socket
import sys

port = int(sys.argv[1])
accounts = int(sys.argv[2])
value = b"x" * 1024

def encode(*parts):
    result = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        if isinstance(part, str):
            part = part.encode()
        result.extend((f"${len(part)}\r\n".encode(), part, b"\r\n"))
    return b"".join(result)

def read_reply(stream):
    marker = stream.read(1)
    if marker in (b"+", b"-", b":"):
        line = stream.readline()
        if not line.endswith(b"\r\n"):
            raise RuntimeError("truncated Redis response")
        if marker == b"-":
            raise RuntimeError(f"Redis error: {line.decode(errors='replace').strip()}")
        return int(line) if marker == b":" else line[:-2]
    if marker == b"$":
        size = int(stream.readline())
        if size == -1:
            return None
        payload = stream.read(size)
        if len(payload) != size or stream.read(2) != b"\r\n":
            raise RuntimeError("truncated Redis bulk response")
        return payload
    if marker == b"*":
        count = int(stream.readline())
        return [read_reply(stream) for _ in range(count)]
    raise RuntimeError(f"unexpected Redis response marker {marker!r}")

with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
    connection.settimeout(5)
    stream = connection.makefile("rb")
    for index in range(accounts):
        commands = [("MULTI",)]
        commands.extend(("SET", f"auth:user:{index}:{part}", value) for part in range(6))
        commands.extend([
            ("EXEC",),
            ("SETEX", f"auth:session:{index}", "86400", value),
            ("MULTI",),
            ("SET", f"auth:event:{index}", value),
            ("SET", "auth:event-sequence", str(index)),
            ("EXEC",),
        ])
        connection.sendall(b"".join(encode(*command) for command in commands))
        for _ in commands:
            read_reply(stream)

    # A completed transaction must not be replayed by the next EXEC on this
    # connection. An abandoned transaction must not leak into a later EXEC.
    commands = [
        ("MULTI",),
        ("SET", "auth:replay-guard", "old"),
        ("EXEC",),
        ("SET", "auth:replay-guard", "new"),
        ("MULTI",),
        ("SET", "auth:replay-companion", "committed"),
        ("EXEC",),
        ("GET", "auth:replay-guard"),
        ("MULTI",),
        ("SET", "auth:discard-guard", "must-not-persist"),
        ("DISCARD",),
        ("MULTI",),
        ("SET", "auth:discard-companion", "committed"),
        ("EXEC",),
        ("GET", "auth:discard-guard"),
    ]
    connection.sendall(b"".join(encode(*command) for command in commands))
    replies = [read_reply(stream) for _ in commands]
    if replies[7] != b"new":
        raise RuntimeError(f"completed transaction was replayed: {replies[7]!r}")
    if replies[14] is not None:
        raise RuntimeError(f"discarded transaction was replayed: {replies[14]!r}")
PY
}

assert_storage_survived_restart() {
  port=$(mapped_port "$railway_container")
  python3 - "$port" "$storage_accounts" <<'PY'
import socket
import sys

port = int(sys.argv[1])
accounts = int(sys.argv[2])

def encode(*parts):
    result = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        if isinstance(part, str):
            part = part.encode()
        result.extend((f"${len(part)}\r\n".encode(), part, b"\r\n"))
    return b"".join(result)

def read_reply(stream):
    marker = stream.read(1)
    if marker == b"$":
        size = int(stream.readline())
        if size == -1:
            return None
        payload = stream.read(size)
        if len(payload) != size or stream.read(2) != b"\r\n":
            raise RuntimeError("truncated Redis bulk response")
        return payload
    raise RuntimeError(f"unexpected Redis response marker {marker!r}")

last = accounts - 1
checks = {
    "auth:user:0:5": b"x" * 1024,
    f"auth:user:{last}:5": b"x" * 1024,
    "auth:session:0": b"x" * 1024,
    f"auth:session:{last}": b"x" * 1024,
    "auth:event:0": b"x" * 1024,
    f"auth:event:{last}": b"x" * 1024,
    "auth:event-sequence": str(last).encode(),
    "auth:replay-guard": b"new",
    "auth:replay-companion": b"committed",
    "auth:discard-guard": None,
    "auth:discard-companion": b"committed",
}
with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
    connection.settimeout(5)
    stream = connection.makefile("rb")
    connection.sendall(b"".join(encode("GET", key) for key in checks))
    for key, expected in checks.items():
        actual = read_reply(stream)
        if actual != expected:
            raise SystemExit(
                f"unexpected persisted value for {key!r}: {actual!r} != {expected!r}"
            )
PY
}

assert_bounded_volume_usage() {
  size=$(docker system df -v | awk -v name="$railway_volume" '$1 == name { print $3 }')
  python3 - "$size" "$maximum_storage_mb" <<'PY'
import re
import sys

value = sys.argv[1]
maximum_mb = float(sys.argv[2])
match = re.fullmatch(r"([0-9.]+)([kMGT]?B)", value)
if match is None:
    raise SystemExit(f"could not parse Docker volume size {value!r}")
number = float(match.group(1))
unit = match.group(2)
scale = {"B": 1 / 1_000_000, "kB": 1 / 1_000, "MB": 1, "GB": 1_000, "TB": 1_000_000}[unit]
actual_mb = number * scale
if actual_mb > maximum_mb:
    raise SystemExit(
        f"SableDB transaction smoke used {actual_mb:.2f} MB; ceiling is {maximum_mb:.2f} MB"
    )
print(f"SableDB transaction smoke used {actual_mb:.2f} MB (ceiling {maximum_mb:.2f} MB)")
PY
}

docker image inspect "$image" >/dev/null
docker volume create "$railway_volume" >/dev/null
docker run -d --name "$railway_container" \
  -p 127.0.0.1::6379 \
  --read-only \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --cap-add SETGID \
  --cap-add SETUID \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount "type=volume,src=$railway_volume,dst=/var/lib/sabledb" \
  "$image" >/dev/null

# First boot exercises the root-owned empty volume supplied by Railway. Restart
# exercises the now-private 10002:10002 directory without discarding its data.
wait_until_ready "$railway_container"
assert_unprivileged_database "$railway_container"
exercise_transaction_storage
docker restart "$railway_container" >/dev/null
wait_until_ready "$railway_container"
assert_unprivileged_database "$railway_container"
assert_storage_survived_restart
assert_bounded_volume_usage

logs=$(docker logs "$railway_container" 2>&1)
[[ $(printf '%s' "$logs" | grep -c 'Server started on port address') -ge 2 ]]
[[ $(printf '%s' "$logs" | grep -c 'wal_ttl_seconds: 0') -ge 2 ]]
if printf '%s' "$logs" | grep -Eqi 'permission denied|sabledb-entrypoint:'; then
  echo "SableDB volume bootstrap failure found in logs" >&2
  exit 1
fi

# Kubernetes supplies fsGroup ownership and overrides the image user from the
# pod security context. That path must need no bootstrap capabilities at all.
docker volume create "$kubernetes_volume" >/dev/null
docker run -d --name "$kubernetes_container" \
  --user 10002:10002 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount "type=volume,src=$kubernetes_volume,dst=/var/lib/sabledb" \
  "$image" >/dev/null
wait_until_ready "$kubernetes_container"
assert_unprivileged_database "$kubernetes_container"
docker restart "$kubernetes_container" >/dev/null
wait_until_ready "$kubernetes_container"
assert_unprivileged_database "$kubernetes_container"

logs=$(docker logs "$kubernetes_container" 2>&1)
[[ $(printf '%s' "$logs" | grep -c 'Server started on port address') -ge 2 ]]
if printf '%s' "$logs" | grep -Eqi 'permission denied|sabledb-entrypoint:'; then
  echo "SableDB fsGroup startup failure found in logs" >&2
  exit 1
fi

printf 'SableDB Railway-volume and Kubernetes-fsGroup qualification passed\n'
