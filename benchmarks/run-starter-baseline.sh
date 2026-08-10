#!/bin/sh
set -eu

: "${RUN_ID:?RUN_ID is required}"
: "${TARGET_URL:?TARGET_URL is required}"
: "${WEBAUTHN_RP_ORIGIN:?WEBAUTHN_RP_ORIGIN is required}"

run_dir="/data/runs/${RUN_ID}"
mkdir -p "${run_dir}"

/usr/local/bin/rustyauth-benchmark refresh-sessions > "${run_dir}/session-refresh.json"
/usr/local/bin/rustyauth-benchmark count > "${run_dir}/dataset.json"

run_k6() {
  mode="$1"
  rate="$2"
  duration="$3"
  label="$4"
  time_unit="$5"
  set +e
  MODE="${mode}" \
  ARRIVAL_RATE="${rate}" \
  TIME_UNIT="${time_unit}" \
  DURATION="${duration}" \
  FIXTURES_PATH="${BENCHMARK_FIXTURES_PATH:-/data/fixtures.jsonl}" \
  RP_ORIGIN="${WEBAUTHN_RP_ORIGIN}" \
  TARGET_URL="${TARGET_URL}" \
    k6 run \
      --summary-export "${run_dir}/${label}.json" \
      /opt/rustyauth/benchmarks/k6/single-realm.js \
      > "${run_dir}/${label}.txt" 2>&1
  status="$?"
  set -e
  printf '%s\n' "${status}" > "${run_dir}/${label}.exit-code"
}

# A short preflight catches fixture, routing and cookie errors before spending
# minutes on a capacity ladder.
run_k6 read 1 10s read-smoke-1rps 1s
if [ "$(cat "${run_dir}/read-smoke-1rps.exit-code")" -ne 0 ]; then
  sha256sum "${run_dir}"/*.json "${run_dir}"/*.txt > "${run_dir}/SHA256SUMS"
  printf '%s\n' "${run_dir}"
  exit 1
fi

for rate in 25 50 100 200 400 800; do
  run_k6 read "${rate}" "${READ_DURATION:-90s}" "read-${rate}rps" 1s
  # The fixed ladder is monotonic. Once a step breaches a gate, higher rates
  # cannot establish a sustainable lower tier and would only consume CI/runtime
  # minutes. Preserve the first failed step and continue to the independent
  # passkey sign-in measurement.
  if [ "$(cat "${run_dir}/read-${rate}rps.exit-code")" -ne 0 ]; then
    break
  fi
done

# Six sign-ins a minute stays below the product's intentional ten identifier
# probes per source-address minute. The result therefore measures real WebAuthn
# user experience without weakening or bypassing production brute-force policy.
run_k6 signin 6 "${SIGNIN_DURATION:-5m}" signin-0.1rps 1m

sha256sum "${run_dir}"/*.json "${run_dir}"/*.txt > "${run_dir}/SHA256SUMS"
printf '%s\n' "${run_dir}"
