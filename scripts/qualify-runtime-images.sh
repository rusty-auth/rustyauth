#!/usr/bin/env bash
set -euo pipefail

api_image=${RUSTYAUTH_SMOKE_API_IMAGE:-rustyauth:release-candidate}
dashboard_image=${RUSTYAUTH_SMOKE_DASHBOARD_IMAGE:-rustyauth-dashboard:release-candidate}
sabledb_image=${RUSTYAUTH_SMOKE_SABLEDB_IMAGE:-rustyauth-sabledb:ci}
dashboard_port=${RUSTYAUTH_SMOKE_PORT:-18081}
run_id=$$

private_network="rustyauth-smoke-private-${run_id}"
edge_network="rustyauth-smoke-edge-${run_id}"
data_volume="rustyauth-smoke-sable-${run_id}"
sable_container="rustyauth-smoke-sable-${run_id}"
api_container="rustyauth-smoke-api-${run_id}"
dashboard_container="rustyauth-smoke-dashboard-${run_id}"

cleanup() {
  exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    docker logs --tail 200 "$sable_container" 2>&1 || true
    docker logs --tail 200 "$api_container" 2>&1 || true
    docker logs --tail 200 "$dashboard_container" 2>&1 || true
  fi
  docker rm -f "$dashboard_container" "$api_container" "$sable_container" >/dev/null 2>&1 || true
  docker network rm "$edge_network" "$private_network" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" >/dev/null 2>&1 || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

docker image inspect "$api_image" "$dashboard_image" "$sabledb_image" >/dev/null
docker network create --internal "$private_network" >/dev/null
docker network create "$edge_network" >/dev/null
docker volume create "$data_volume" >/dev/null

common_args=(
  --read-only
  --init
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 256
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m
)

docker run -d --name "$sable_container" \
  "${common_args[@]}" \
  --network "$private_network" --network-alias sabledb \
  --mount "type=volume,src=$data_volume,dst=/var/lib/sabledb" \
  "$sabledb_image" >/dev/null

for attempt in $(seq 1 60); do
  if docker exec "$sable_container" /usr/local/bin/container-healthcheck redis 127.0.0.1:6379 >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 60 ]]; then
    echo "SableDB did not become ready" >&2
    exit 1
  fi
  sleep 1
done

master_key=$(openssl rand -hex 32)
bootstrap_token=$(openssl rand -hex 32)
event_token=$(openssl rand -hex 32)
identity_token=$(openssl rand -hex 32)
config_yaml=$(printf '%s\n' \
  'apiVersion: rustyauth.dev/v1alpha1' \
  'kind: Realm' \
  '' \
  'metadata:' \
  '  tenantId: release-smoke' \
  '  realmId: release-smoke-development' \
  '' \
  'spec:' \
  '  environment: development' \
  '  server:' \
  '    bind: 0.0.0.0' \
  '    port: 8080' \
  "    publicIssuer: http://localhost:${dashboard_port}" \
  '    trustedProxyHops: 0' \
  '  datastore:' \
  '    endpoint: redis://sabledb:6379' \
  '  relyingParty:' \
  '    id: localhost' \
  "    origin: http://localhost:${dashboard_port}" \
  '    name: RustyAuth release smoke' \
  '  tokens:' \
  '    audience: rustyauth-release-smoke' \
  '    accessTtl: 5m' \
  '  sessions:' \
  '    idleTimeout: 30m' \
  '    absoluteTimeout: 7d' \
  '  events:' \
  '    retention: 90d' \
  '  signingKeys:' \
  '    rotateEvery: 30d' \
  '    prepublishFor: 10m' \
  '    overlapFor: 10m' \
  '    maintenanceInterval: 5s' \
  '  operators:' \
  '    bootstrapEmails: [release-smoke@example.test]' \
  '  backups:' \
  '    enabled: false')

docker run -d --name "$api_container" \
  "${common_args[@]}" \
  --network "$private_network" \
  -e "RUSTYAUTH_CONFIG_YAML=$config_yaml" \
  -e "AUTH_MASTER_KEY_HEX=$master_key" \
  -e "BOOTSTRAP_TOKEN=$bootstrap_token" \
  -e "AUTH_EVENT_RPC_TOKEN=$event_token" \
  -e "AUTH_IDENTITY_RPC_TOKEN=$identity_token" \
  -e RUST_LOG=rustyauth=info \
  "$api_image" >/dev/null

for attempt in $(seq 1 60); do
  if docker exec "$api_container" /usr/local/bin/rustyauth --healthcheck >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 60 ]]; then
    echo "RustyAuth API did not become ready" >&2
    exit 1
  fi
  sleep 1
done

docker run -d --name "$dashboard_container" \
  "${common_args[@]}" \
  --network "$private_network" \
  -p "127.0.0.1:${dashboard_port}:8080" \
  -e PORT=8080 \
  -e "RUSTYAUTH_API_UPSTREAM=http://${api_container}:8080" \
  "$dashboard_image" >/dev/null
docker network connect "$edge_network" "$dashboard_container"

for attempt in $(seq 1 60); do
  if docker exec "$dashboard_container" /usr/local/bin/container-healthcheck http 127.0.0.1:8080 /healthz >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 60 ]]; then
    echo "dashboard did not become ready" >&2
    exit 1
  fi
  sleep 1
done

for spec in \
  "$sable_container|10002:10002|$private_network|1" \
  "$api_container|10001:10001|$private_network|1" \
  "$dashboard_container|10001:10001|$private_network,$edge_network|2"
do
  name=${spec%%|*}
  rest=${spec#*|}
  expected_user=${rest%%|*}
  rest=${rest#*|}
  expected_networks=${rest%%|*}
  expected_network_count=${rest##*|}
  docker inspect "$name" | jq -e \
    --arg user "$expected_user" \
    --arg networks "$expected_networks" \
    --argjson network_count "$expected_network_count" \
    '.[0]
     | .Config.User == $user
       and .HostConfig.ReadonlyRootfs
       and .HostConfig.Init
       and (.HostConfig.CapDrop == ["ALL"])
       and (.HostConfig.SecurityOpt | index("no-new-privileges") != null)
       and .HostConfig.PidsLimit == 256
       and (.HostConfig.Tmpfs["/tmp"] | contains("noexec"))
       and ((.NetworkSettings.Networks | keys | length) == $network_count)
       and (($networks | split(",")) - (.NetworkSettings.Networks | keys) | length == 0)' >/dev/null
  if docker exec "$name" /bin/sh -c true >/dev/null 2>&1; then
    echo "$name unexpectedly contains /bin/sh" >&2
    exit 1
  fi
done

docker inspect "$sable_container" | jq -e '.[0].HostConfig.PortBindings == {} or .[0].HostConfig.PortBindings == null' >/dev/null
docker inspect "$api_container" | jq -e '.[0].HostConfig.PortBindings == {} or .[0].HostConfig.PortBindings == null' >/dev/null
docker inspect "$dashboard_container" | jq -e \
  --arg port "$dashboard_port" \
  '.[0].HostConfig.PortBindings["8080/tcp"][0].HostIp == "127.0.0.1"
   and .[0].HostConfig.PortBindings["8080/tcp"][0].HostPort == $port' >/dev/null

base_url="http://127.0.0.1:${dashboard_port}"
[[ $(curl -fsS "$base_url/healthz") == '{"status":"ok"}' ]]
curl -fsS "$base_url/readyz" | jq -e '.status == "ready"' >/dev/null
curl -fsS "$base_url/.well-known/openid-configuration" | jq -e \
  --arg issuer "http://localhost:${dashboard_port}" '.issuer == $issuer' >/dev/null
curl -fsS "$base_url/.well-known/passkey-auth" | jq -e \
  '.passkeys == true and .deployment_role == "realm"' >/dev/null

headers=$(curl -fsSI "$base_url/")
printf '%s' "$headers" | tr -d '\r' | grep -Fi \
  "content-security-policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';" >/dev/null
if printf '%s' "$headers" | grep -qi 'unsafe-inline'; then
  echo "CSP unexpectedly permits unsafe-inline" >&2
  exit 1
fi
printf '%s' "$headers" | tr -d '\r' | grep -Fi 'x-frame-options: DENY' >/dev/null
printf '%s' "$headers" | tr -d '\r' | grep -Fi 'x-content-type-options: nosniff' >/dev/null

index_body=$(curl -fsS "$base_url/")
printf '%s' "$index_body" | grep -F '<!DOCTYPE html>' >/dev/null
asset_count=0
while IFS= read -r asset; do
  [[ -n $asset ]] || continue
  asset_count=$((asset_count + 1))
  asset_headers=$(curl -fsSI "$base_url$asset")
  case "$asset" in
    *.css) printf '%s' "$asset_headers" | grep -qi 'content-type: text/css' ;;
    *.js) printf '%s' "$asset_headers" | grep -Eqi 'content-type: (text|application)/javascript' ;;
    *.wasm) printf '%s' "$asset_headers" | grep -qi 'content-type: application/wasm' ;;
  esac
done < <(docker export "$dashboard_container" | tar -tf - | sed -n 's#^srv\(/assets/.*\)#\1#p' | grep -E '\.(css|js|wasm)$' | sort -u)
[[ $asset_count -ge 3 ]]
wasm_asset=$(docker export "$dashboard_container" | tar -tf - | sed -n 's#^srv\(/assets/.*\.wasm\)$#\1#p')
[[ -n $wasm_asset ]]
docker export "$dashboard_container" | tar -xOf - "srv$wasm_asset" | strings | grep -F '.dep-v0' >/dev/null

curl -fsSI "$base_url/v1/token" | grep -qi 'content-type: text/html'

# Cross more than one five-second signing-maintenance interval and multiple
# writer-lease renewals before the final health/log assertions.
sleep 25
docker exec "$api_container" /usr/local/bin/rustyauth --healthcheck >/dev/null
docker exec "$sable_container" /usr/local/bin/container-healthcheck redis 127.0.0.1:6379 >/dev/null
docker exec "$dashboard_container" /usr/local/bin/container-healthcheck http 127.0.0.1:8080 /readyz >/dev/null

combined_logs=$(docker logs "$sable_container" 2>&1; docker logs "$api_container" 2>&1; docker logs "$dashboard_container" 2>&1)
if printf '%s' "$combined_logs" | grep -Eqi '(^|[^a-z])(fatal|panic|lost writer lease)([^a-z]|$)'; then
  echo "fatal runtime signal found in logs" >&2
  exit 1
fi

printf 'hardened scratch-runtime smoke passed (%s assets)\n' "$asset_count"
