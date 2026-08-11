#!/usr/bin/env bash
set -euo pipefail

: "${BENCHMARK_SEED:?BENCHMARK_SEED is required}"

host="${SABLEDB_DIAGNOSTIC_HOST:-SableDB.railway.internal}"
port="${SABLEDB_DIAGNOSTIC_PORT:-6379}"
fixtures="${BENCHMARK_FIXTURES_PATH:-/data/fixtures.jsonl}"
fixture_index="${SABLEDB_DIAGNOSTIC_FIXTURE_INDEX:-2000}"
iterations="${SABLEDB_DIAGNOSTIC_ITERATIONS:-200}"
mode="${SABLEDB_DIAGNOSTIC_MODE:-mget}"

case "${fixture_index}:${iterations}" in
  *[!0-9:]* | :* | *:)
    echo "fixture index and iterations must be non-negative integers" >&2
    exit 2
    ;;
esac
if ((iterations < 1 || iterations > 10000)); then
  echo "iterations must be between 1 and 10000" >&2
  exit 2
fi
case "${mode}" in
  sequential | pipeline | mget | combined) ;;
  *)
    echo "diagnostic mode must be sequential, pipeline, mget or combined" >&2
    exit 2
    ;;
esac

fixture="$(sed -n "$((fixture_index + 1))p" "${fixtures}")"
session_token="$(printf '%s\n' "${fixture}" | sed -E 's/.*"sessionToken":"([^"]+)".*/\1/')"
if [[ -z "${session_token}" || "${session_token}" == "${fixture}" ]]; then
  echo "fixture does not contain a session token" >&2
  exit 1
fi

session_digest="$(printf '%s' "${session_token}" | sha256sum | awk '{print $1}')"
session_key="auth:session:${session_digest}"
activity_key="auth:session-activity:${session_digest}"

user_digest="$(
  printf 'rustyauth-benchmark-user\0%s\0%s' "${BENCHMARK_SEED}" "${fixture_index}" |
    sha256sum |
    awk '{print $1}'
)"
user_hex="${user_digest:0:32}"
byte6=$((16#${user_hex:12:2}))
byte8=$((16#${user_hex:16:2}))
printf -v byte6 '%02x' "$(((byte6 & 0x0f) | 0x40))"
printf -v byte8 '%02x' "$(((byte8 & 0x3f) | 0x80))"
user_hex="${user_hex:0:12}${byte6}${user_hex:14:2}${byte8}${user_hex:18}"
user_id="${user_hex:0:8}-${user_hex:8:4}-${user_hex:12:4}-${user_hex:16:4}-${user_hex:20:12}"
user_key="auth:user:${user_id}"

read_bulk_string() {
  local header
  IFS= read -r header <&3
  header="${header%$'\r'}"
  if [[ "${header}" == '$-1' ]]; then
    return
  fi
  if [[ ! "${header}" =~ ^\$[0-9]+$ ]]; then
    echo "unexpected SableDB response" >&2
    exit 1
  fi
  IFS= read -r _value <&3
}

read_mget_pair() {
  local header
  IFS= read -r header <&3
  header="${header%$'\r'}"
  if [[ "${header}" != '*2' ]]; then
    echo "unexpected SableDB MGET response" >&2
    exit 1
  fi
  read_bulk_string
  read_bulk_string
}

exec 3<>"/dev/tcp/${host}/${port}"
for ((iteration = 0; iteration < iterations; iteration += 1)); do
  started="${EPOCHREALTIME/./}"
  case "${mode}" in
    combined)
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#session_key}" "${session_key}" >&3
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#activity_key}" "${activity_key}" >&3
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#user_key}" "${user_key}" >&3
      read_bulk_string
      read_bulk_string
      read_bulk_string
      ;;
    sequential)
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#session_key}" "${session_key}" >&3
      read_bulk_string
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#activity_key}" "${activity_key}" >&3
      read_bulk_string
      ;;
    pipeline)
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#session_key}" "${session_key}" >&3
      printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#activity_key}" "${activity_key}" >&3
      read_bulk_string
      read_bulk_string
      ;;
    mget)
      printf '*3\r\n$4\r\nMGET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n' \
        "${#session_key}" "${session_key}" "${#activity_key}" "${activity_key}" >&3
      read_mget_pair
      ;;
  esac
  if [[ "${mode}" != combined ]]; then
    printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#user_key}" "${user_key}" >&3
    read_bulk_string
  fi
  ended="${EPOCHREALTIME/./}"
  printf '%s\n' "$((10#${ended} - 10#${started}))"
done
