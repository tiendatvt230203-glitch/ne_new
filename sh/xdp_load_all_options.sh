#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db_env.sh"
network_encryptor_load_db_env

SQL_DIR="${NETWORK_ENCRYPTOR_ROOT}/sql_options"
LOAD_ONE="${SCRIPT_DIR}/xdp_load_option.sh"

if [ ! -d "${SQL_DIR}" ]; then
  echo "[FATAL] missing ${SQL_DIR}" >&2
  exit 1
fi

shopt -s nullglob
SQL_FILES=("${SQL_DIR}"/*.sql)
shopt -u nullglob

if [ "${#SQL_FILES[@]}" -eq 0 ]; then
  echo "[FATAL] no *.sql in ${SQL_DIR}" >&2
  exit 1
fi

declare -A IDS=()
for sql_file in "${SQL_FILES[@]}"; do
  base="$(basename "${sql_file}")"
  if [[ "${base}" == *_peer.sql ]]; then
    continue
  fi
  if [[ "${base}" =~ ^([0-9]+)_.*\.sql$ ]]; then
    id="${BASH_REMATCH[1]}"
    id=$((10#${id}))
    IDS["${id}"]=1
  fi
done

if [ "${#IDS[@]}" -eq 0 ]; then
  echo "[FATAL] no files matching <NN>_*.sql in ${SQL_DIR}" >&2
  exit 1
fi

echo "=== xdp_load_all_options ==="
echo "sql_options: ${SQL_DIR}"
mapfile -t SORTED_IDS < <(printf '%s\n' "${!IDS[@]}" | sort -n)

for id in "${SORTED_IDS[@]}"; do
  echo ">>> load config_id=${id}"
  bash "${LOAD_ONE}" "${id}"
done

echo "OK ids: ${SORTED_IDS[*]}  (skipped *_peer.sql — load peer with: xdp_load_option.sh <id> <NN>_..._peer.sql)"
