#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db_env.sh"
network_encryptor_load_db_env

SCHEMA_FILE="${NETWORK_ENCRYPTOR_ROOT}/schema.sql"
if [ ! -f "${SCHEMA_FILE}" ]; then
  echo "[FATAL] schema not found: ${SCHEMA_FILE}" >&2
  exit 1
fi

force_drop_database() {
  local db_name="$1"
  if psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
      -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${db_name} WITH (FORCE);" >/dev/null 2>&1; then
    return 0
  fi
  psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -v ON_ERROR_STOP=1 <<SQL
ALTER DATABASE ${db_name} WITH ALLOW_CONNECTIONS = false;
REVOKE CONNECT ON DATABASE ${db_name} FROM PUBLIC;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '${db_name}'
  AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${db_name};
SQL
}

echo "=== xdp_init_db: schema + empty tables ==="
echo "Host: ${DB_HOST}  DB: ${DB_NAME}  User: ${DB_USER}"
echo "Root: ${NETWORK_ENCRYPTOR_ROOT}"
echo

echo "[1/3] DROP DATABASE IF EXISTS ${DB_NAME}"
force_drop_database "${DB_NAME}"

echo "[2/3] CREATE DATABASE ${DB_NAME}"
createdb -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "${DB_NAME}"

echo "[3/3] psql -f ${SCHEMA_FILE}"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 -f "${SCHEMA_FILE}"

echo "OK: ${DB_NAME} ready. Load test data: sh/xdp_load_option.sh <id> or sh/xdp_load_all_options.sh"
