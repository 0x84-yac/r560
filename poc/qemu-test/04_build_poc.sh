#!/usr/bin/env bash
# 04_build_poc.sh — build the PoC for the target arch.
#   ARCH=aarch64 (default) | x86_64
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ARCH="${ARCH:-aarch64}"
case "$ARCH" in
    aarch64) CC=aarch64-linux-gnu-gcc -static ;;
    x86_64)  CC=gcc ;;
    *) echo "[04] unsupported ARCH=$ARCH"; exit 1 ;;
esac
# shellcheck disable=SC2086
$CC -Wall -O2 -o "$HERE/poc" "$HERE/poc_debugfs_kctx_uaf_debug.c" || true
[ -x "$HERE/poc" ] || { echo "[04] build failed"; exit 1; }
file "$HERE/poc"
echo "[04] built $HERE/poc for $ARCH"
