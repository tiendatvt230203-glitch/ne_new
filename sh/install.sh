#!/usr/bin/env bash
set -euo pipefail

echo "=== install build deps (network-encryptor) ==="

sudo apt update
sudo apt install -y build-essential clang llvm pkg-config git curl ca-certificates
sudo apt install -y \
  libelf-dev \
  zlib1g-dev \
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

libbpf_so_has_xdp_attach() {
  local f
  for f in /usr/local/lib/libbpf.so* /usr/local/lib/x86_64-linux-gnu/libbpf.so* \
           /usr/lib/x86_64-linux-gnu/libbpf.so* /usr/lib64/libbpf.so*; do
    [ -f "$f" ] || continue
    if nm -D "$f" 2>/dev/null | grep -q ' bpf_xdp_attach'; then
      return 0
    fi
  done
  return 1
}

install_libbpf_from_upstream() {
  local tag="${LIBBPF_TAG:-v1.3.5}"
  local work
  work="$(mktemp -d)"
  echo "=== libbpf $tag (bpf_xdp_attach / bpf_xdp_detach) -> /usr/local ==="
  git clone --depth 1 --branch "$tag" https://github.com/libbpf/libbpf.git "$work/libbpf"
  make -C "$work/libbpf/src" -j"$(nproc)"
  sudo make -C "$work/libbpf/src" install PREFIX=/usr/local LIBDIR=/usr/local/lib
  sudo ldconfig
  rm -rf "$work"
}

if libbpf_so_has_xdp_attach; then
  echo "libbpf: bpf_xdp_attach present — OK"
else
  echo "[WARN] system libbpf has no bpf_xdp_attach (Ubuntu 22.04 / old Debian apt is common)."
  echo "       Installing libbpf from upstream into /usr/local (headers + .so)."
  install_libbpf_from_upstream
fi

if ! libbpf_so_has_xdp_attach; then
  echo "[FATAL] bpf_xdp_attach still missing after upstream install; check LIBBPF_TAG / linker paths." >&2
  exit 1
fi

mkdir -p bin
echo "Done. Build with: make clean && make"
echo "Hint: Makefile uses -I/usr/local/include -L/usr/local/lib first so /usr/local wins over distro libbpf."
