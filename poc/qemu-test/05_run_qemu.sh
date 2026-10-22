#!/usr/bin/env bash
# 05_run_qemu.sh — build initramfs (busybox), attach the PoC + mali.ko, run QEMU,
# capture the full serial console into logs/. Exit code = detect_kasan.sh verdict.
#
#   ARCH=aarch64 ./05_run_qemu.sh          (default)
#   QEMU=/path/to/qemu-system-aarch64      override emulator
#   KARGS="extra kernel cmdline"           append
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ARCH="${ARCH:-aarch64}"
LOGDIR="$HERE/logs"; mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"

case "$ARCH" in
    aarch64) QEMU="${QEMU:-qemu-system-aarch64}"; MACHINE="virt,highmem=off"; CONSOLE="ttyAMA0"; KERNEL="$HERE/linux/arch/arm64/boot/Image" ;;
    x86_64)  QEMU="${QEMU:-qemu-system-x86_64}";  MACHINE="q35,accel=kvm";    CONSOLE="ttyS0";  KERNEL="$HERE/linux/arch/x86/boot/bzImage" ;;
    *) echo "[05] unsupported ARCH=$ARCH"; exit 1 ;;
esac

ROOTFS_DIR="$(mktemp -d "$LOGDIR/initramfs.$TS.XXXXXX")"
LOG="$LOGDIR/full-$TS.log"

[ -f "$KERNEL" ] || { echo "[05] no kernel image at $KERNEL — run 02 first"; exit 1; }

busybox_bin="${BUSYBOX:-$(readlink -f /bin/busybox)}"
[ -x "$busybox_bin" ] || { echo "[05] no busybox static binary found (apt install busybox-static)"; exit 1; }
file "$busybox_bin" | grep -q "${ARCH:-aarch64}" || echo "[05] NOTE: host busybox arch differs from ARCH=$ARCH; providing it for target arch is your job" >&2

echo "[05] staging initramfs in $ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR/bin" "$ROOTFS_DIR/sbin" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/proc" \
         "$ROOTFS_DIR/dev" "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/mnt"
for applet in sh mount insmod dmesg ls grep tail sleep poweroff mkdir cat stty; do
    ln -s /bin/busybox "$ROOTFS_DIR/bin/$applet" 2>/dev/null || true
done
cp "$busybox_bin" "$ROOTFS_DIR/bin/busybox"

# PoC
cp "$HERE/poc" "$ROOTFS_DIR/mnt/poc" 2>/dev/null || { echo "[05] PoC missing — run 04 first"; exit 1; }
# Mali module (from the DDK default build path)
MALI_KO="$(find "$HERE" /home/za0x/Desktop/target/AX504X08X-SW-99002-r56p0-18eac0*/driver/product/kernel/drivers/gpu/arm/midgard -maxdepth 3 -name 'mali.ko' -print -quit 2>/dev/null | head -1)"
if [ -n "$MALI_KO" ]; then
    cp "$MALI_KO" "$ROOTFS_DIR/mnt/mali.ko"
    echo "[05] module found: $MALI_KO"
else
    echo "[05] WARNING: mali.ko not found — the PoC step 2 ioctl will fail; boot will still capture logs"
fi
# in-VM run script
cp "$HERE/initramfs/run.sh" "$ROOTFS_DIR/init"
chmod +x "$ROOTFS_DIR/init"

echo "[05] creating initramfs.cpio.gz"
cd "$ROOTFS_DIR" && find . | cpio -H newc -o --owner root:root 2> "/dev/null" | gzip -9 > "$LOGDIR/initramfs.cpio.gz"
cd "$HERE"

echo "[05] $QEMU -M $MACHINE -nographic ... (log: $LOG)"
# -no-reboot to catch panics on the first hit; monitor on a socket for clean shutdown
"$QEMU" \
    -M "$MACHINE" \
    -cpu max \
    -m 2G \
    -smp 2 \
    -nographic \
    -no-reboot \
    -kernel "$KERNEL" \
    -initrd "$LOGDIR/initramfs.cpio.gz" \
    -append "console=$CONSOLE root=/dev/ram0 rdinit=/init loglevel=8 panic=-1 nokaslr" \
    $([ "$ARCH" = x86_64 ] && echo -enable-kvm) \
    2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}

echo "[05] qemu exit: $RC — captured $LOG"
# Also save targeted slices
cp "$LOG" "$LOGDIR/poc-$TS.log"
dmesg-out="$LOGDIR/dmesg-delta-$TS.log"
awk '/--- running PoC ---/,/--- done; poweroff ---/' "$LOG" > "$dmesg-out" 2>/dev/null
echo "[05] dmesg-delta slice: $dmesg-out"

"$HERE/detect_kasan.sh" "$LOG"
