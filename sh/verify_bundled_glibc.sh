#!/usr/bin/env bash
# Run on the deploy host (e.g. NE1). Exits 1 if bundled libxdp needs newer glibc than this OS.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SO="${ROOT}/libs/lib/libxdp.so.1"
if [[ ! -f "$SO" ]]; then
  echo "[verify] missing $SO — run make (or copy libs/ from a 22.04 build)." >&2
  exit 1
fi
host_ver="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)"
if [[ -z "${host_ver}" ]]; then
  echo "[verify] could not read host glibc (getconf)." >&2
  exit 1
fi
max_need="$(strings "$SO" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -uV | tail -1)"
if [[ -z "${max_need}" ]]; then
  echo "[verify] could not parse GLIBC_* from bundled libxdp." >&2
  exit 1
fi
# bundled OK iff max_need <= host_ver (as sort -V)
if [[ "$(printf '%s\n' "$max_need" "$host_ver" | sort -V | tail -1)" == "$host_ver" ]]; then
  echo "[verify] OK: bundled libxdp needs glibc <= ${max_need}, host has ${host_ver}."
  exit 0
fi
echo "[verify] FAIL: bundled libxdp needs glibc ${max_need}, this host has ${host_ver}." >&2
if [[ -f "${ROOT}/libs/.sync_host_glibc.txt" ]]; then
  echo "[verify] Note: libs were synced on a host that reported: $(tr -d '\n' <"${ROOT}/libs/.sync_host_glibc.txt")" >&2
fi
echo "[verify] This is NOT a missing package on NE1 — libs/lib is from a newer Ubuntu. Replace it." >&2
echo "[verify] --- Option A: rebuild libs ON this machine (Ubuntu 22.04) ---" >&2
echo "  sudo apt-get install -y build-essential clang llvm libbpf-dev libxdp-dev libssl-dev libpq-dev" >&2
echo "  cd ${ROOT} && make libs-clean && make" >&2
echo "[verify] --- Option B: copy bin/ + libs/ from a real 22.04 build or from: make build-on-2204 (Docker) ---" >&2
exit 1
