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

# Rewriting every fixture TTL intentionally creates a short burst of durable
# datastore work. Keep preparation outside the measured window and let
# compaction settle; the following smoke profile remains the fail-closed proof
# that the realm is quiet enough to measure.
settle_seconds="${BENCHMARK_SETTLE_SECONDS:-60}"
case "${settle_seconds}" in
  ''|*[!0-9]*)
    printf '%s\n' "BENCHMARK_SETTLE_SECONDS must be a non-negative integer" >&2
    exit 2
    ;;
esac
sleep "${settle_seconds}"

run_profile() {
  profile="$1"
  label="$2"
  script_path="${BENCHMARK_SCRIPT_PATH:-/opt/rustyauth/benchmarks/k6/enterprise-realm.js}"
  set +e
  PROFILE="${profile}" \
  FIXTURES_PATH="${BENCHMARK_FIXTURES_PATH:-/data/fixtures.jsonl}" \
  RP_ORIGIN="${WEBAUTHN_RP_ORIGIN}" \
  TARGET_URL="${TARGET_URL}" \
  BENCHMARK_TIMING_ROOT_SECRET="${BENCHMARK_TIMING_ROOT_SECRET}" \
  SOAK_RATE="${SOAK_RATE:-560}" \
  SOAK_DURATION="${SOAK_DURATION:-1h}" \
  TARGET_RATE="${TARGET_RATE:-250}" \
  TARGET_DURATION="${TARGET_DURATION:-2m}" \
  WARMUP_DURATION="${WARMUP_DURATION:-1m}" \
  PHASE_NAME="${PHASE_NAME:-qualification}" \
    k6 run \
      --summary-export "${run_dir}/${label}.json" \
      "${script_path}" \
      > "${run_dir}/${label}.txt" 2>&1
  status="$?"
  set -e
  printf '%s\n' "${status}" > "${run_dir}/${label}.exit-code"
}

run_profile smoke enterprise-smoke
if [ "$(cat "${run_dir}/enterprise-smoke.exit-code")" -ne 0 ]; then
  (cd "${run_dir}" && sha256sum ./*.json ./*.txt > SHA256SUMS)
  printf '%s\n' "${run_dir}"
  exit 1
fi

run_profile "${PROFILE:-enterprise}" "${PROFILE:-enterprise}"
(cd "${run_dir}" && sha256sum ./*.json ./*.txt > SHA256SUMS)
printf '%s\n' "${run_dir}"
exit "$(cat "${run_dir}/${PROFILE:-enterprise}.exit-code")"
