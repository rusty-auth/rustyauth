#!/bin/sh
set -eu

: "${RUN_ID:?RUN_ID is required}"
: "${TARGET_URL:?TARGET_URL is required}"
: "${WEBAUTHN_RP_ORIGIN:?WEBAUTHN_RP_ORIGIN is required}"
: "${BENCHMARK_TIMING_ROOT_SECRET:?BENCHMARK_TIMING_ROOT_SECRET is required}"

run_dir="/data/runs/${RUN_ID}"
mkdir -p "${run_dir}"

/usr/local/bin/rustyauth-benchmark refresh-sessions > "${run_dir}/session-refresh.json"
/usr/local/bin/rustyauth-benchmark count > "${run_dir}/dataset.json"

run_profile() {
  profile="$1"
  label="$2"
  set +e
  PROFILE="${profile}" \
  FIXTURES_PATH="${BENCHMARK_FIXTURES_PATH:-/data/fixtures.jsonl}" \
  RP_ORIGIN="${WEBAUTHN_RP_ORIGIN}" \
  TARGET_URL="${TARGET_URL}" \
  BENCHMARK_TIMING_ROOT_SECRET="${BENCHMARK_TIMING_ROOT_SECRET}" \
  SOAK_RATE="${SOAK_RATE:-560}" \
  SOAK_DURATION="${SOAK_DURATION:-1h}" \
    k6 run \
      --summary-export "${run_dir}/${label}.json" \
      /opt/rustyauth/benchmarks/k6/enterprise-realm.js \
      > "${run_dir}/${label}.txt" 2>&1
  status="$?"
  set -e
  printf '%s\n' "${status}" > "${run_dir}/${label}.exit-code"
}

run_profile smoke enterprise-smoke
if [ "$(cat "${run_dir}/enterprise-smoke.exit-code")" -ne 0 ]; then
  sha256sum "${run_dir}"/*.json "${run_dir}"/*.txt > "${run_dir}/SHA256SUMS"
  printf '%s\n' "${run_dir}"
  exit 1
fi

run_profile "${PROFILE:-enterprise}" "${PROFILE:-enterprise}"
sha256sum "${run_dir}"/*.json "${run_dir}"/*.txt > "${run_dir}/SHA256SUMS"
printf '%s\n' "${run_dir}"
