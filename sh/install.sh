#!/usr/bin/env bash
set -euo pipefail

echo "=== install build deps (network-encryptor) ==="

sudo apt update
sudo apt install -y build-essential clang llvm pkg-config
sudo apt install -y \
  libelf-dev \
  libbpf-dev \
  libxdp-dev \
  libssl-dev \
  libpq-dev \
  postgresql-server-dev-all
sudo apt install -y "linux-headers-$(uname -r)"

if command -v pg_config >/dev/null 2>&1; then
  echo "pg_config: $(pg_config --includedir)"
else
  echo "[WARN] pg_config missing; check libpq-dev" >&2
fi

mkdir -p bin
echo "Done. Run: make all"
