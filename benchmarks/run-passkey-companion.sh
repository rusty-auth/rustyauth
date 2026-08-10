#!/bin/sh
set -eu

: "${RUN_ID:?RUN_ID is required}"
: "${TARGET_URL:?TARGET_URL is required}"
: "${WEBAUTHN_RP_ORIGIN:?WEBAUTHN_RP_ORIGIN is required}"

run_dir="/data/runs/${RUN_ID}"
script_path="${BENCHMARK_SCRIPT_PATH:-/opt/rustyauth/benchmarks/k6/single-realm.js}"
mkdir -p "${run_dir}"

/usr/local/bin/rustyauth-benchmark count > "${run_dir}/dataset.json"

set +e
MODE=signin \
ARRIVAL_RATE="${SIGNIN_RATE:-6}" \
TIME_UNIT=1m \
DURATION="${SIGNIN_DURATION:-5m}" \
FIXTURES_PATH="${BENCHMARK_FIXTURES_PATH:-/data/fixtures.jsonl}" \
RP_ORIGIN="${WEBAUTHN_RP_ORIGIN}" \
TARGET_URL="${TARGET_URL}" \
  k6 run \
    --summary-export "${run_dir}/signin-0.1rps.json" \
    "${script_path}" \
    > "${run_dir}/signin-0.1rps.txt" 2>&1
status="$?"
set -e
printf '%s\n' "${status}" > "${run_dir}/signin-0.1rps.exit-code"

(cd "${run_dir}" && sha256sum ./*.json ./*.txt ./*.exit-code > SHA256SUMS)
printf '%s\n' "${run_dir}"
exit "${status}"
