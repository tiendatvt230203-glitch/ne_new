#!/usr/bin/env bash
# Copy libbpf/libxdp headers + minimal .so closure from this machine into libs/.
# Run automatically via Makefile when not SKIP_LIBS=1.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INC="${ROOT}/libs/include"
LIB="${ROOT}/libs/lib"
mkdir -p "${INC}" "${LIB}"

is_elf() {
  case "$(file -b "$1" 2>/dev/null)" in *ELF*) return 0;; *) return 1;; esac
}

deb_lib_dirs() {
  local m d
  m="$(cc -print-multiarch 2>/dev/null || true)"
  [[ -n "${m:-}" && -d "/usr/lib/${m}" ]] && echo "/usr/lib/${m}"
  for d in /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib/riscv64-linux-gnu \
           /usr/lib/s390x-linux-gnu /usr/local/lib /usr/lib; do
    [[ -d "$d" ]] && echo "$d"
  done
}

# Print absolute path to libbpf.so / libxdp.so (or .so.1) for staging.
resolve_packaged_so() {
  local want="$1" p d stem cand
  p="$(cc -print-file-name="$want" 2>/dev/null || true)"
  if [[ -n "${p:-}" && "$p" == /* && -f "$p" ]]; then
    readlink -f "$p"
    return 0
  fi
  stem="${want%.so}"
  while IFS= read -r d; do
    [[ -d "$d" ]] || continue
    for cand in "$d/$want" "$d/${stem}.so.1" "$d/${stem}.so.0"; do
      [[ -f "$cand" ]] || continue
      readlink -f "$cand"
      return 0
    done
  done < <(deb_lib_dirs | sort -u)
  return 1
}

fatal_headers() {
  echo "[FATAL] Missing /usr/include/bpf and/or /usr/include/xdp (need dev headers)." >&2
  echo "  Ubuntu 22.04+:  sudo apt-get update && sudo apt-get install -y libbpf-dev libxdp-dev" >&2
  echo "  If 'libxdp-dev' not found:  sudo apt-add-repository universe && sudo apt-get update && sudo apt-get install -y libxdp-dev libbpf-dev" >&2
  echo "  (Also: sudo apt-get install -y build-essential clang libssl-dev libpq-dev)" >&2
  echo "  Debian: sudo apt-get install -y libbpf-dev libxdp-dev" >&2
  exit 1
}

fatal_so() {
  local name="$1"
  echo "[FATAL] Cannot find ${name} under /usr/lib (and gcc does not resolve it)." >&2
  echo "  Install runtime + dev, e.g. Ubuntu:" >&2
  echo "    sudo apt-get install -y libbpf1 libbpf-dev libxdp1 libxdp-dev" >&2
  echo "  If libxdp-dev is missing, enable universe then apt-get update (see fatal_headers)." >&2
  exit 1
}

copy_tree() {
  [ -d "$1" ] || return 0
  mkdir -p "$2"
  cp -R "$1/." "$2/"
}

for bpf in /usr/local/include/bpf /usr/include/bpf; do
  [ -d "$bpf" ] && { copy_tree "$bpf" "${INC}/bpf"; break; }
done
for xdp in /usr/local/include/xdp /usr/include/xdp; do
  [ -d "$xdp" ] && { copy_tree "$xdp" "${INC}/xdp"; break; }
done
[ -d "${INC}/bpf" ] && [ -d "${INC}/xdp" ] || fatal_headers

declare -A seen
skip_sys() {
  case "$1" in
    ld-linux-*.so*|linux-vdso.so*|libc.so*|libm.so*|libdl.so*|libpthread.so*|librt.so*|libresolv.so*|libnss_*.so*|libthread_db.so*|libutil.so*|libanl.so*|libBrokenLocale.so*) return 0 ;;
  esac
  return 1
}
skip_db() {
  case "$1" in
    libpq.so*|libssl.so*|libcrypto.so*|libldap*.so*|liblber*.so*|libsasl2*.so*|libkrb5*.so*|libgssapi*.so*|libk5crypto*.so*|libcom_err*.so*|libkrb5support*.so*|libgnutls*.so*|libgcrypt*.so*|libp11-kit*.so*|libtasn1*.so*|libnettle*.so*|libhogweed*.so*|libgmp*.so*|libidn2*.so*|libunistring*.so*|libkeyutils*.so*) return 0 ;;
  esac
  return 1
}
stage() {
  local f="$1" real base dst sz
  [ -n "${f:-}" ] && [ -f "$f" ] || return 0
  real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
  [ -f "$real" ] || return 0
  base="$(basename "$real")"
  [[ "$base" == ld-linux-*.so.* ]] && return 0
  skip_sys "$base" && return 0
  skip_db "$base" && return 0
  [[ -n "${seen[$real]:-}" ]] && return 0
  seen[$real]=1
  dst="${LIB}/${base}"
  [ -e "$dst" ] && return 0
  cp -L "$real" "$dst"
  sz="$(stat -c%s "$dst" 2>/dev/null || echo 0)"
  [ "${sz:-0}" -ge 4096 ] || { echo "[FATAL] bad copy $dst (size ${sz})" >&2; exit 1; }
  is_elf "$dst" || { echo "[FATAL] bad copy $dst (not ELF)" >&2; exit 1; }
}

for name in libbpf.so libxdp.so; do
  p="$(resolve_packaged_so "$name" || true)"
  [[ -n "${p:-}" ]] || fatal_so "$name"
  stage "$p"
done

for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  n="${#seen[@]}"
  shopt -s nullglob
  for so in "${LIB}"/*.so*; do
    [ -f "$so" ] || continue
    while IFS= read -r line; do
      f="$(echo "$line" | sed -n 's/.* => \(.*\) (0x.*/\1/p')"
      [ -n "$f" ] && stage "$f"
    done < <(ldd "$so" 2>/dev/null || true)
  done
  shopt -u nullglob
  [ "${#seen[@]}" = "$n" ] && break
done

if [ -n "${LIBS_PATCHELF:-}" ] && command -v patchelf >/dev/null 2>&1; then
  shopt -s nullglob
  for f in "${LIB}"/*.so*; do
    [ -L "$f" ] && continue
    [ -f "$f" ] || continue
    is_elf "$f" || continue
    patchelf --set-rpath '$ORIGIN' "$f" 2>/dev/null || true
  done
  shopt -u nullglob
fi

shopt -s nullglob
for f in "${LIB}"/lib*.so*; do
  [ -f "$f" ] || continue
  bn="$(basename "$f")"
  [[ "$bn" =~ \.so\.[0-9] ]] || [[ "$bn" =~ -[0-9]+\.[0-9]+\.so$ ]] || continue
  sn="$(objdump -p "$f" 2>/dev/null | awk '/SONAME/ {print $2; exit}')"
  [ -n "$sn" ] && [ "$sn" != "$bn" ] && cp -fL "$f" "${LIB}/${sn}"
done
shopt -u nullglob

for need in libxdp.so.1 libbpf.so.1; do
  p="${LIB}/${need}"
  [ -f "$p" ] || { echo "[FATAL] missing $need" >&2; exit 1; }
  sz="$(stat -c%s "$p" 2>/dev/null || echo 0)"
  [ "${sz:-0}" -ge 4096 ] || { echo "[FATAL] $need invalid (size ${sz})" >&2; exit 1; }
  is_elf "$p" || { echo "[FATAL] $need invalid (not ELF)" >&2; exit 1; }
done

getconf GNU_LIBC_VERSION 2>/dev/null >"${ROOT}/libs/.sync_host_glibc.txt" || true

: >"${ROOT}/libs/.ready"
