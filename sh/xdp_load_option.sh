#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db_env.sh"
network_encryptor_load_db_env

SQL_DIR="${NETWORK_ENCRYPTOR_ROOT}/sql_options"

usage() {
  echo "Usage: $0 <config_id>"
  echo "  Loads one file from ${SQL_DIR}/<NN>_*.sql (NN = zero-padded id)."
  echo "  If several match, set NETWORK_ENCRYPTOR_SQL_FILE to the path to load."
}

if [ "$#" -ne 1 ]; then
  usage
  exit 1
fi

CONFIG_ID="$1"
if ! [[ "${CONFIG_ID}" =~ ^[0-9]+$ ]]; then
  echo "config_id must be a non-negative integer" >&2
  exit 1
fi

if [ -n "${NETWORK_ENCRYPTOR_SQL_FILE:-}" ]; then
  SQL_FILE="${NETWORK_ENCRYPTOR_SQL_FILE}"
  if [ ! -f "${SQL_FILE}" ]; then
    echo "NETWORK_ENCRYPTOR_SQL_FILE not found: ${SQL_FILE}" >&2
    exit 1
  fi
else
  ID_PADDED=$(printf "%02d" "$((10#${CONFIG_ID}))")
  SQL_FILE_GLOB="${SQL_DIR}/${ID_PADDED}_*.sql"

  shopt -s nullglob
  SQL_FILES=( ${SQL_FILE_GLOB} )
  shopt -u nullglob

  if [ "${#SQL_FILES[@]}" -eq 0 ]; then
    echo "No SQL for config_id=${CONFIG_ID} (glob ${SQL_FILE_GLOB})" >&2
    exit 1
  fi

  IFS=$'\n' SQL_FILES_SORTED=($(printf '%s\n' "${SQL_FILES[@]}" | sort))
  unset IFS

  if [ "${#SQL_FILES_SORTED[@]}" -gt 1 ]; then
    echo "Multiple SQL files match ${SQL_FILE_GLOB}:" >&2
    printf '  %s\n' "${SQL_FILES_SORTED[@]}" >&2
    echo "Set NETWORK_ENCRYPTOR_SQL_FILE to the file to load, or keep a single file per id." >&2
    exit 1
  fi
  SQL_FILE="${SQL_FILES_SORTED[0]}"
fi

echo "=== xdp_load_option ==="
echo "config_id=${CONFIG_ID}  file=${SQL_FILE}"

echo "[1/3] psql -f ..."
psql -v ON_ERROR_STOP=1 -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f "${SQL_FILE}"

echo "[2/3] profile_default only if config has no profiles yet (schema.sql tables)"
psql -v ON_ERROR_STOP=1 -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<SQL
BEGIN;

DO \$\$
DECLARE
    wan_cnt INTEGER;
BEGIN
    IF EXISTS (
        SELECT 1 FROM xdp_profiles WHERE config_id = ${CONFIG_ID} LIMIT 1
    ) THEN
        NULL;
    ELSE
        INSERT INTO xdp_profiles (
          config_id, profile_name, enabled, description
        ) VALUES (
          ${CONFIG_ID}, 'profile_default', 1, ''
        );

        INSERT INTO xdp_profile_locals (profile_id, ifname)
        SELECT p.id, l.ifname
        FROM xdp_profiles p
        JOIN xdp_local_configs l ON l.config_id = p.config_id
        WHERE p.config_id = ${CONFIG_ID};

        SELECT COUNT(*)::int INTO wan_cnt FROM xdp_wan_configs WHERE config_id = ${CONFIG_ID};

        INSERT INTO xdp_profile_wans (profile_id, ifname, bandwidth_weight_percent)
        SELECT p.id, w.ifname,
               CASE
                 WHEN wan_cnt <= 0 THEN 0
                 WHEN wan_cnt = 1 THEN 100
                 ELSE (100 / wan_cnt)
               END
        FROM xdp_profiles p
        CROSS JOIN xdp_wan_configs w
        WHERE p.config_id = ${CONFIG_ID}
          AND w.config_id = ${CONFIG_ID}
          AND p.profile_name = 'profile_default';
    END IF;
END \$\$;

COMMIT;
SQL

echo "[3/3] pg_notify('xdp_start', '${CONFIG_ID}')"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "SELECT pg_notify('xdp_start', '${CONFIG_ID}');"

echo "OK config_id=${CONFIG_ID}"
