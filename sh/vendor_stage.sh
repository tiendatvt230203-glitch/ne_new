#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INC="${ROOT}/vendor/include"
LIB="${ROOT}/vendor/lib"
mkdir -p "${INC}" "${LIB}"

copy_tree() {
  local src="$1" dst="$2"
  [ -d "$src" ] || return 0
  mkdir -p "$dst"
  cp -R "${src}/." "${dst}/"
}

echo "=== vendor_stage: bpf + xdp headers only ==="
for bpf in /usr/local/include/bpf /usr/include/bpf; do
  if [ -d "$bpf" ]; then
    copy_tree "$bpf" "${INC}/bpf"
    break
  fi
done
for xdp in /usr/local/include/xdp /usr/include/xdp; do
  if [ -d "$xdp" ]; then
    copy_tree "$xdp" "${INC}/xdp"
    break
  fi
done
if [ ! -d "${INC}/bpf" ] || [ ! -d "${INC}/xdp" ]; then
  echo "[FATAL] bpf or xdp headers not found (libbpf-dev / libxdp-dev)" >&2
  exit 1
fi

echo "=== vendor_stage: libbpf + libxdp .so (and their ldd closure only) ==="
declare -A seen
skip_system_lib() {
  local base="$1"
  case "$base" in
    ld-linux-*.so*|linux-vdso.so*|libc.so*|libm.so*|libdl.so*|libpthread.so*|librt.so*|libresolv.so*|libnss_*.so*|libthread_db.so*|libutil.so*|libanl.so*|libBrokenLocale.so*)
      return 0
      ;;
  esac
  return 1
}

skip_db_stack() {
  local base="$1"
  case "$base" in
    libpq.so*|libssl.so*|libcrypto.so*|libldap*.so*|liblber*.so*|libsasl2*.so*|libkrb5*.so*|libgssapi*.so*|libk5crypto*.so*|libcom_err*.so*|libkrb5support*.so*|libgnutls*.so*|libgcrypt*.so*|libp11-kit*.so*|libtasn1*.so*|libnettle*.so*|libhogweed*.so*|libgmp*.so*|libidn2*.so*|libunistring*.so*|libkeyutils*.so*)
      return 0
      ;;
  esac
  return 1
}

stage_one() {
  local f="$1"
  [ -n "${f:-}" ] || return 0
  [ -f "$f" ] || return 0
  local real
  real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
  [ -f "$real" ] || return 0
  local base
  base="$(basename "$real")"
  [[ "$base" == ld-linux-*.so.* ]] && return 0
  skip_system_lib "$base" && return 0
  skip_db_stack "$base" && return 0
  [[ -n "${seen[$real]:-}" ]] && return 0
  seen[$real]=1
  local dst="${LIB}/${base}"
  if [ ! -e "$dst" ]; then
    cp -L "$real" "$dst"
    local sz
    sz="$(stat -c%s "$dst" 2>/dev/null || echo 0)"
    if [ "${sz:-0}" -lt 4096 ]; then
      echo "[FATAL] copy too small (${sz}b): $dst <- $real" >&2
      exit 1
    fi
    if ! file -b "$dst" | grep -q ELF; then
      echo "[FATAL] not ELF after copy: $dst ($(file -b "$dst"))" >&2
      exit 1
    fi
    echo "  lib: ${base}"
  fi
}

for name in libbpf.so libxdp.so; do
  p="$(cc -print-file-name="${name}" 2>/dev/null || true)"
  if [ -n "$p" ] && [ -f "$p" ]; then
    stage_one "$p"
  else
    echo "[FATAL] ${name} not found (install libbpf-dev libxdp-dev)" >&2
    exit 1
  fi
done

for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  before="${#seen[@]}"
  shopt -s nullglob
  for so in "${LIB}"/*.so*; do
    [ -f "$so" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      f="$(echo "$line" | sed -n 's/.* => \(.*\) (0x.*/\1/p')"
      [ -n "$f" ] || continue
      stage_one "$f"
    done < <(ldd "$so" 2>/dev/null || true)
  done
  shopt -u nullglob
  after="${#seen[@]}"
  [ "$after" = "$before" ] && break
done

if command -v patchelf >/dev/null 2>&1; then
  echo "=== vendor_stage: patchelf RPATH \$ORIGIN ==="
  shopt -s nullglob
  for f in "${LIB}"/*.so*; do
    [ -L "$f" ] && continue
    [ -f "$f" ] || continue
    file -b "$f" | grep -q 'ELF' || continue
    patchelf --set-rpath '$ORIGIN' "$f" 2>/dev/null || true
  done
  shopt -u nullglob
else
  echo "[WARN] patchelf not installed; apt install patchelf" >&2
fi

echo "=== vendor_stage: SONAME symlinks ==="
shopt -s nullglob
for f in "${LIB}"/lib*.so*; do
  [ -f "$f" ] || continue
  bn="$(basename "$f")"
  if [[ "$bn" =~ \.so\.[0-9] ]] || [[ "$bn" =~ -[0-9]+\.[0-9]+\.so$ ]]; then
    :
  else
    continue
  fi
  soname="$(objdump -p "$f" 2>/dev/null | awk '/SONAME/ {print $2; exit}')"
  [ -n "$soname" ] || continue
  [ "$soname" = "$bn" ] && continue
  ln -sf "$bn" "${LIB}/${soname}"
done
shopt -u nullglob

echo "=== vendor_stage: verify ==="
for need in libxdp.so.1 libbpf.so.1; do
  p="${LIB}/${need}"
  if [ ! -e "$p" ]; then
    echo "[FATAL] missing ${need} under ${LIB}" >&2
    exit 1
  fi
  rp="$(readlink -f "$p" 2>/dev/null || true)"
  [ -n "$rp" ] && [ -f "$rp" ] || { echo "[FATAL] broken or missing target for ${p}" >&2; exit 1; }
  sz="$(stat -c%s "$rp" 2>/dev/null || echo 0)"
  if [ "${sz:-0}" -lt 4096 ]; then
    echo "[FATAL] ${need} resolves to short file ${rp} (${sz}b) — redo: make vendor-clean && make" >&2
    exit 1
  fi
  if ! file -b "$rp" | grep -q ELF; then
    echo "[FATAL] ${need} -> ${rp} is not ELF" >&2
    exit 1
  fi
done

: >"${ROOT}/vendor/.use_vendor"
nlib="$(find "${LIB}" -maxdepth 1 \( -name '*.so' -o -name '*.so.*' \) 2>/dev/null | wc -l)"
echo "OK vendor (bpf/xdp only): ${nlib} libs under ${LIB}"
