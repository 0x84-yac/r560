#!/usr/bin/env bash
# 01_fetch_kernel.sh — shallow-clone the Linux tree for the QEMU test build.
#
#   ./01_fetch_kernel.sh [version] [kernel-source-dir]
#
#   version            default 6.6.0 (matches Mali r56p0's tested range)
#   kernel-source-dir  default ./linux (relative to this script's directory)
#
# If the tree already exists and has HEAD, it is left alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
VERSION="${1:-6.6.0}"
SRC="${2:-$HERE/linux}"

if [ -d "$SRC/.git" ] && git -C "$SRC" rev-parse HEAD >/dev/null 2>&1; then
    echo "[01] kernel source already present at $SRC — skipping fetch"
    exit 0
fi

echo "[01] shallow-cloning Linux v${VERSION} -> $SRC ..."
mkdir -p "$SRC"
git init -q "$SRC"
git -C "$SRC" remote add origin https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
# tag is stable/* form; linux.cpp kernel.org tag format is "v$VER"
git -C "$SRC" fetch --depth=1 --quiet origin "refs/tags/v${VERSION}:refs/tags/v${VERSION}" \
    || { echo "failed to fetch tag v${VERSION}"; exit 1; }
git -C "$SRC" -c advice.detachedHead=false checkout --detach "v${VERSION}"
echo "[01] done: $SRC @ $(git -C "$SRC" rev-parse --short HEAD)"
