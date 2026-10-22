#!/usr/bin/env bash
# initramfs/run.sh — runs INSIDE the QEMU guest as /init (root shell).
# Sequence:
#   1. mount the pseudo-filesystems
#   2. raise kernel loglevel (full Mali debug traces visible)
#   3. insmod the Mali DDK module (mali.ko)
#   4. create /dev/mali0 if devtmpfs did not do it automatically
#   5. mount debugfs
#   6. snapshot dmesg (pre-poc baseline)
#   7. run the PoC (stdout+stderr → /poc.stdout, full log)
#   8. snapshot dmesg again → diff is the KASAN/driver-side evidence window
#   9. poweroff
set -u
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# ── 1. filesystems ────────────────────────────────────────────────────────────
mkdir -p /proc /sys /dev /tmp /mnt
mount -t proc    none /proc        2>/dev/null
mount -t sysfs   none /sys         2>/dev/null
mount -t devtmpfs none /dev        2>/dev/null || true
mount -t tmpfs   none /tmp         2>/dev/null || true
mount -t debugfs none /sys/kernel/debug 2>/dev/null || \
    echo "[run] WARNING: debugfs mount failed — PoC step 4 will fail"

# ── 2. loglevel: whole DEBUG/trace/IRQ etc. ──────────────────────────────────
dmesg -n 8 2>/dev/null || true

echo "[run] ===== mali-uaf qemu harness booting ====="
echo "[run] kernel: $(uname -a)"
echo "[run] cmdline: $(cat /proc/cmdline 2>/dev/null)"

# ── 3. insmod the DDK ────────────────────────────────────────────────────────
echo "[run] --- insmod mali.ko ---"
if insmod /mnt/mali.ko > /insmod.log 2>&1; then
    echo "[run] insmod OK"
else
    echo "[run] insmod FAILED (see /insmod.log):"
    cat /insmod.log
    dmesg | tail -30
fi

echo "[run] mali device nodes:"; ls -l /dev/mali* 2>/dev/null || echo "  (devtmpfs did not create one)"
# The DDK registers via misc_register() with MISC_DYNAMIC_MINOR (mode 0666) and
# name = kbdev->devname (e.g. "mali0"); devtmpfs creates the node automatically.
# /proc/misc shows 'major: name' with major always 10 for misc devices.
grep -i mali /proc/misc 2>/dev/null && echo "[run] misc device registered (major 10)" || echo "[run] no misc entry for mali"

# ── 5. debugfs check ────────────────────────────────────────────────────────
if [ ! -e /sys/kernel/debug ]; then
    echo "[run] /sys/kernel/debug does not exist — debugfs not compiled in kernel"
fi

# ── 6. baseline dmesg snapshot ───────────────────────────────────────────────
dmesg > /mnt/dmesg-pre-poc.log 2>/dev/null || true

# ── 7. run the PoC with full logs ────────────────────────────────────────────
echo "[run] --- running PoC ---"
if [ -x /mnt/poc ]; then
    /mnt/poc --wait-crash --log /poc.log > /poc.stdout 2>&1
    echo "[run] poc exit: $?"
else
    echo "[run] /mnt/poc missing!"
fi

# ── 8. post-run dmesg snapshot + delta ───────────────────────────────────────
dmesg > /mnt/dmesg-post-poc.log 2>/dev/null || true
echo "[run] --- printing dmesg tail (visible on serial console so it lands in the host log) ---"
dmesg | tail -n 300
echo "[run] --- matching UAF/KASAN evidence ---"
grep -aE -i "KASAN|use-after-free|BUG|slab|kbasep_mem_profile|kbase_release|debugfs|refcount" \
    /mnt/dmesg-post-poc.log | tail -50 || true

echo "[run] --- done; poweroff ---"
sync
# busybox 'poweroff' falls through to kernel halt when no init scripts exist
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger 2>/dev/null || true
sleep 5
