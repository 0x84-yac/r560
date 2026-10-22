#!/usr/bin/env bash
# 02_build_kernel.sh — defconfig + KASAN/config fragment + build bzImage/Image.
#
#   ARCH=aarch64 ./02_build_kernel.sh     (default) or ARCH=x86_64
#   KERNEL_SRC=path/to/linux              (default $HERE/linux)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ARCH="${ARCH:-aarch64}"
KSRC="${KERNEL_SRC:-$HERE/linux}"
JOBS="$(nproc || echo 4)"

[ -f "$KSRC/Makefile" ] || { echo "[02] no kernel tree at $KSRC — run 01_fetch_kernel.sh"; exit 1; }

case "$ARCH" in
    aarch64) CC=aarch64-linux-gnu-gcc; TARGET="arch/arm64/boot/Image" ;;
    x86_64)  CC=gcc;                   TARGET="arch/x86/boot/bzImage"  ;;
    *) echo "[02] unsupported ARCH=$ARCH"; exit 1 ;;
esac

command -v "$CC" >/dev/null || { echo "[02] missing $CC (apt install cross-toolchain)"; exit 1; }

export PATH="$(dirname "$(command -v "$CC")"):$PATH"

case "$ARCH" in
    aarch64) DEFCONF="arm64_defconfig" ;;
    x86_64)  DEFCONF="x86_64_defconfig" ;;
esac

echo "[02] defconfig for $ARCH ($DEFCONF)"
make -C "$KSRC" -j"$JOBS" O="$KSRC" ARCH="$ARCH" CROSS_COMPILE="$([ "$ARCH" = aarch64 ] && echo aarch64-linux-gnu-)" \
     "$DEFCONF"

echo "[02] merging fragment (scripts/config CLI)"
"$KSRC/scripts/config" "$KSRC/.config" \
    --enable KASAN --enable KASAN_GENERIC \
    --enable DEBUG_FS --set-val FRAME_POINTER y \
    --enable KALLSYMS --enable KALLSYMS_ALL \
    --enable STACKTRACE \
    --enable MODULES --enable MODULE_UNLOAD --enable MODULE_FORCE_LOAD \
    --enable DEBUG_KERNEL --enable DEBUG_MUTEXES --enable LOCKDEP \
    --enable BLK_DEV_INITRD \
    --enable SERIAL_AMBA_PL011 --enable SERIAL_AMBA_PL011_CONSOLE \
    --enable VIRTIO --enable VIRTIO_PCI \
    $([ "$ARCH" = aarch64 ] && echo --enable ARM_GIC) \
    --enable DEVPTS_FS --enable UNIX98_PTYS --enable PROC_FS --enable SYSFS \
    --enable TMPFS --enable OVERLAY_FS --enable EXT4_FS \
    --enable DEVMEM

echo "[02] olddefconfig"
make -C "$KSRC" ARCH="$ARCH" CROSS_COMPILE="$([ "$ARCH" = aarch64 ] && echo aarch64-linux-gnu-)" \
     O="$KSRC" olddefconfig

echo "[02] verifying KASAN is on"
grep -q '^CONFIG_KASAN=y' "$KSRC/.config" || { echo "[02] CONFIG_KASAN missing — refusing to build"; exit 1; }

echo "[02] building $TARGET (this is the long step)..."
JOBS=$((JOBS < 8 ? JOBS : 8)) make -C "$KSRC" -j"$JOBS" ARCH="$ARCH" \
     CROSS_COMPILE="$([ "$ARCH" = aarch64 ] && echo aarch64-linux-gnu-)" O="$KSRC" "$TARGET"

echo "[02] building modules in-tree too (needed for the initramfs)"
make -C "$KSRC" -j"$JOBS$JOBS" ARCH="$ARCH" \
     CROSS_COMPILE="$([ "$ARCH" = aarch64 ] && echo aarch64-linux-gnu-)" O="$KSRC" modules || true

echo "[02] done: $KSRC/$TARGET"
