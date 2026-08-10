#!/usr/bin/env bash
set -euo pipefail

image=${RUSTYAUTH_SMOKE_SABLEDB_IMAGE:-rustyauth-sabledb:ci}
run_id=$$
railway_volume="rustyauth-sable-volume-${run_id}"
railway_container="rustyauth-sable-volume-${run_id}"
kubernetes_volume="rustyauth-sable-fsgroup-${run_id}"
kubernetes_container="rustyauth-sable-fsgroup-${run_id}"

cleanup() {
  exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    docker logs --tail 200 "$railway_container" 2>&1 || true
    docker logs --tail 200 "$kubernetes_container" 2>&1 || true
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

docker image inspect "$image" >/dev/null
docker volume create "$railway_volume" >/dev/null
docker run -d --name "$railway_container" \
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
docker restart "$railway_container" >/dev/null
wait_until_ready "$railway_container"
assert_unprivileged_database "$railway_container"

logs=$(docker logs "$railway_container" 2>&1)
[[ $(printf '%s' "$logs" | grep -c 'Server started on port address') -ge 2 ]]
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
