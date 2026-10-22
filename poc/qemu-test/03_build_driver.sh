#!/usr/bin/env bash
# 03_build_driver.sh — build the Mali r56p0 DDK as an out-of-tree kernel module
# against the QEMU test kernel. Uses the DDK's *own* no-mali/fake-platform mode
# so no hardware is needed: mali_kbase_platform_fake.c registers the platform
# device that the driver binds on and creates /dev/mali0.
#
#   ./03_build_driver.sh [DDK_DIR]    (default = the vendor target tree)
#   KERNEL_SRC=...                    (default $HERE/linux)
#   ARCH=aarch64                      (x86_64 also supported)
#
# Enabled DDK knobs (what the security report instruments on):
#   CONFIG_MALI_DEBUG                 runtime debug/trace + WARN machinery
#   CONFIG_MALI_MIDGARD_ENABLE_TRACE  gator/tracepoint integration
#   CONFIG_MALI_SYSTEM_TRACE          system trace events
#   CONFIG_MALI_NO_MALI (+EXPERT)     the supported QEMU/fake-HW mode
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ARCH="${ARCH:-aarch64}"
KSRC="${KERNEL_SRC:-$HERE/linux}"
DEFAULT_DDK="/home/za0x/Desktop/target/AX504X08X-SW-99002-r56p0-18eac0 (2)/driver/product/kernel"
DDK="${1:-$DEFAULT_DDK}"
JOBS="$(nproc || echo 4)"

[ -f "$DDK/drivers/gpu/arm/midgard/Makefile" ] || { echo "[03] no Mali DDK at $DDK"; exit 1; }
[ -f "$KSRC/Makefile" ] || { echo "[03] no kernel tree at $KSRC — run 01+02 first"; exit 1; }

# The kernel's Kbuild cannot take M= paths containing spaces, so copy the DDK
# into a clean build dir when needed.
BUILD_SRC="$DDK"
if [[ "$DDK" == *" "* ]]; then
    BUILD_SRC="$HERE/ddk"
    echo "[03] DDK path has spaces — staging a clean copy at $BUILD_SRC"
    rm -rf "$BUILD_SRC"
    mkdir -p "$BUILD_SRC"
    cp -a "$DDK/." "$BUILD_SRC/"
fi
MALI_DIR="$BUILD_SRC/drivers/gpu/arm/midgard"

case "$ARCH" in
    aarch64) XCOMPILE="aarch64-linux-gnu-" ;;
    x86_64)  XCOMPILE="" ;;
    *) echo "[03] unsupported ARCH=$ARCH"; exit 1 ;;
esac

mkdir -p "$BUILD_SRC/build"
echo "[03] building module (Kbuild M=$MALI_DIR) ..."
make -C "$KSRC" \
     ARCH="$ARCH" \
     CROSS_COMPILE="$XCOMPILE" \
     M="$MALI_DIR" \
     modules \
     CONFIG_MMU=y \
     CONFIG_MALI_MIDGARD=m \
     CONFIG_MALI_PLATFORM_NAME='"fake"' \
     CONFIG_MALI_CSF_SUPPORT=y \
     CONFIG_MALI_NO_MALI=y \
     CONFIG_MALI_NO_MALI_DEFAULT_GPU='"tMIx"' \
     CONFIG_MALI_EXPERT=y \
     CONFIG_MALI_DEBUG=y \
     CONFIG_MALI_MIDGARD_ENABLE_TRACE=y \
     CONFIG_MALI_SYSTEM_TRACE=y \
     CONFIG_MALI_KUTF=n \
     CONFIG_MALI_TRACE_POWER_GPU_WORK_PERIOD=y \
     CONFIG_MALI_GATOR_SUPPORT=y \
     CONFIG_MALI_DEVFREQ=n \
     CONFIG_MALI_DMA_BUF_MAP_ON_DEMAND=y \
     CONFIG_MALI_DMA_BUF_LEGACY_COMPAT=n \
     -j"$JOBS" 2>&1 | tee "$BUILD_SRC/build/lastbuild.log"

echo "[03] module artifacts:"
MALI_KO="$(find "$MALI_DIR" -maxdepth 3 -name 'mali.ko' -print -quit || true)"
[ -n "$MALI_KO" ] || MALI_KO="$(find "$MALI_DIR" -maxdepth 3 -name '*.ko' -print -quit || true)"
find "$MALI_DIR" -maxdepth 3 -name '*.ko' -print || true
if [ -z "$MALI_KO" ]; then
    echo "[03] no .ko produced — inspect $BUILD_SRC/build/lastbuild.log"
    exit 1
fi
echo "[03] OK: $MALI_KO"
