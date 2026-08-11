#!/bin/sh
set -eu

: "${RUN_ID:?RUN_ID is required}"
: "${TARGET_URL:?TARGET_URL is required}"
: "${WEBAUTHN_RP_ORIGIN:?WEBAUTHN_RP_ORIGIN is required}"
: "${BENCHMARK_TIMING_ROOT_SECRET:?BENCHMARK_TIMING_ROOT_SECRET is required}"

run_dir="/data/runs/${RUN_ID}"
mkdir -p "${run_dir}"

refresh_sessions="${BENCHMARK_REFRESH_SESSIONS:-true}"
case "${refresh_sessions}" in
  true)
    default_settle_seconds=60
    ;;
  false)
    default_settle_seconds=0
    ;;
  *)
    printf '%s\n' "BENCHMARK_REFRESH_SESSIONS must be true or false" >&2
    exit 2
    ;;
esac
settle_seconds="${BENCHMARK_SETTLE_SECONDS:-${default_settle_seconds}}"
case "${settle_seconds}" in
  ''|*[!0-9]*)
    printf '%s\n' "BENCHMARK_SETTLE_SECONDS must be a non-negative integer" >&2
    exit 2
    ;;
esac

case "${refresh_sessions}" in
  true)
    BENCHMARK_SETTLE_SECONDS="${settle_seconds}" \
      /usr/local/bin/rustyauth-benchmark refresh-sessions > "${run_dir}/session-refresh.json"
    ;;
  false)
    printf '%s\n' '{"skipped":true,"reason":"existing fixture sessions retained for an adjacent capacity step"}' \
      > "${run_dir}/session-refresh.json"
    ;;
esac
/usr/local/bin/rustyauth-benchmark count > "${run_dir}/dataset.json"

# Rewriting every fixture TTL intentionally creates a short burst of durable
# datastore work. Keep preparation outside the measured window and let
# compaction settle; the refresh staggers the production session-touch cadence
# after this interval so preparation cannot manufacture a write thundering
# herd. The following smoke profile remains the fail-closed proof that the realm
# is quiet enough to measure.
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

# A refreshed dataset has just rewritten every session TTL and may need a
# bounded compaction/recovery retry. An adjacent step that explicitly reuses
# sessions has no preparation work to settle; retrying an expired/invalid
# fixture set only hides the cause and wastes five minutes.
if [ "${refresh_sessions}" = true ]; then
  default_smoke_attempt_limit=10
else
  default_smoke_attempt_limit=1
fi
smoke_attempt_limit="${BENCHMARK_SMOKE_ATTEMPTS:-${default_smoke_attempt_limit}}"
smoke_retry_seconds="${BENCHMARK_SMOKE_RETRY_SECONDS:-30}"
validate_non_negative_integer() {
  value="$1"
  value_name="$2"
  case "${value}" in
    ''|*[!0-9]*)
      printf '%s must be a non-negative integer\n' "${value_name}" >&2
      exit 2
      ;;
  esac
}
validate_non_negative_integer "${smoke_attempt_limit}" BENCHMARK_SMOKE_ATTEMPTS
validate_non_negative_integer "${smoke_retry_seconds}" BENCHMARK_SMOKE_RETRY_SECONDS
if [ "${smoke_attempt_limit}" -lt 1 ]; then
  printf '%s\n' "smoke_attempt_limit must be at least one" >&2
  exit 2
fi

smoke_attempt=1
while :; do
  run_profile smoke enterprise-smoke
  if [ "$(cat "${run_dir}/enterprise-smoke.exit-code")" -eq 0 ]; then
    break
  fi
  if [ ! -s "${run_dir}/enterprise-smoke.json" ]; then
    (cd "${run_dir}" && sha256sum ./*.json ./*.txt ./*.exit-code > SHA256SUMS)
    printf '%s\n' "${run_dir}"
    exit 1
  fi
  cp "${run_dir}/enterprise-smoke.json" "${run_dir}/enterprise-smoke-attempt-${smoke_attempt}.json"
  cp "${run_dir}/enterprise-smoke.txt" "${run_dir}/enterprise-smoke-attempt-${smoke_attempt}.txt"
  cp "${run_dir}/enterprise-smoke.exit-code" "${run_dir}/enterprise-smoke-attempt-${smoke_attempt}.exit-code"
  if [ "${smoke_attempt}" -ge "${smoke_attempt_limit}" ]; then
    (cd "${run_dir}" && sha256sum ./*.json ./*.txt ./*.exit-code > SHA256SUMS)
    printf '%s\n' "${run_dir}"
    exit 1
  fi
  sleep "${smoke_retry_seconds}"
  smoke_attempt=$((smoke_attempt + 1))
done

run_profile "${PROFILE:-enterprise}" "${PROFILE:-enterprise}"
(cd "${run_dir}" && sha256sum ./*.json ./*.txt ./*.exit-code > SHA256SUMS)
printf '%s\n' "${run_dir}"
exit "$(cat "${run_dir}/${PROFILE:-enterprise}.exit-code")"
