_sh_db_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NETWORK_ENCRYPTOR_ROOT="$(cd "${_sh_db_env_dir}/.." && pwd)"

network_encryptor_load_db_env() {
  if [ -n "${DB_ENV_FILE:-}" ] && [ -f "${DB_ENV_FILE}" ]; then
    . "${DB_ENV_FILE}"
  elif [ -f "${NETWORK_ENCRYPTOR_ROOT}/.db.env" ]; then
    . "${NETWORK_ENCRYPTOR_ROOT}/.db.env"
  elif [ -f "/opt/db.env" ]; then
    . "/opt/db.env"
  else
    echo "[FATAL] DB env not found. Use one of: DB_ENV_FILE=path, ${NETWORK_ENCRYPTOR_ROOT}/.db.env, /opt/db.env" >&2
    return 1
  fi

  : "${DB_HOST:?DB_HOST is required}"
  : "${DB_PORT:?DB_PORT is required}"
  : "${DB_USER:?DB_USER is required}"
  : "${DB_NAME:?DB_NAME is required}"
  : "${DB_PASS:?DB_PASS is required}"
  export PGPASSWORD="${DB_PASS}"
  return 0
}
