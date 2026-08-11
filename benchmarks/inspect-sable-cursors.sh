#!/usr/bin/env bash
set -euo pipefail

host="${SABLEDB_DIAGNOSTIC_HOST:-SableDB.railway.internal}"
port="${SABLEDB_DIAGNOSTIC_PORT:-6379}"

read_integer_value() {
  local header value
  IFS= read -r header <&3
  header="${header%$'\r'}"
  if [[ "${header}" == '$-1' ]]; then
    return
  fi
  if [[ ! "${header}" =~ ^\$[0-9]+$ ]]; then
    echo "unexpected SableDB response" >&2
    exit 1
  fi
  IFS= read -r value <&3
  value="${value%$'\r'}"
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    echo "SableDB cursor value is not an unsigned integer" >&2
    exit 1
  fi
  printf '%s' "${value}"
}

get_integer() {
  local key="$1"
  printf '*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n' "${#key}" "${key}" >&3
  read_integer_value
}

exec 3<>"/dev/tcp/${host}/${port}"
event_sequence="$(get_integer auth:event-sequence)"
projector_cursor="$(get_integer analytics:projector-cursor)"
minimum_sequence="$(get_integer auth:event-min-sequence)"
minimum_sequence="${minimum_sequence:-1}"
if [[ -z "${event_sequence}" || -z "${projector_cursor}" ]]; then
  echo "SableDB event sequence or analytics cursor is missing" >&2
  exit 1
fi
if ((projector_cursor > event_sequence)); then
  echo "analytics projector cursor is ahead of the event log" >&2
  exit 1
fi

printf '{"eventSequence":%s,"projectorCursor":%s,"projectorLag":%s,"minimumSequence":%s}\n' \
  "${event_sequence}" \
  "${projector_cursor}" \
  "$((event_sequence - projector_cursor))" \
  "${minimum_sequence}"
