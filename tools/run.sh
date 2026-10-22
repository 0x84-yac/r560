#!/bin/sh
# run.sh - runs UAF PoCs automatically after kernel boot
DIR="${0%/*}"

echo "=== Starting UAF Tests ==="
echo "DIR is: $DIR"
echo "UID: $(id)"

# Use /tmp for intermediate files
WORK_DIR="/tmp/uaf_tests"
mkdir -p "$WORK_DIR"

# --- Debug: enumerate Mali debugfs structure ---
echo "=== Debugfs Enumeration ==="
ls -laR /sys/kernel/debug/mali*/ 2>/dev/null || echo "No mali debugfs dirs"
echo ""
echo "=== Debugfs ctx dirs ==="
find /sys/kernel/debug -name 'ctx' -type d 2>/dev/null | while read d; do
    echo "ctx dir: $d"
    ls -la "$d" 2>/dev/null
done
echo ""

# --- Test 1: mm_struct UAF (poc) ---
echo "=== Test 1: mm_struct UAF (poc) ==="
echo "Timestamp: $(date)"
if [ -x "$DIR/poc" ]; then
    "$DIR/poc" > "$WORK_DIR/test1.log" 2>&1
    rc=$?
    echo "=== Test 1 output (exit code: $rc) ==="
    cat "$WORK_DIR/test1.log"
    sleep 3
else
    echo "Error: poc not found"
fi

# --- Test 2: debugfs kctx UAF (needs root for debugfs) ---
echo "=== Test 2: debugfs kctx UAF (poc_debugfs_kctx_uaf) ==="
echo "Timestamp: $(date)"
if [ -x "$DIR/poc_debugfs_kctx_uaf" ]; then
    # Run as root for debugfs access
    "$DIR/poc_debugfs_kctx_uaf" > "$WORK_DIR/test2_default.log" 2>&1
    rc=$?
    echo "=== Test 2 (default) output (exit code: $rc) ==="
    cat "$WORK_DIR/test2_default.log"
    sleep 2
    
    # Test all variants
    for variant in mem_profile mem_jit_count mem_jit_vm mem_jit_phys mem_jit_used mem_jit_trim; do
        echo "=== Variant: $variant ==="
        "$DIR/poc_debugfs_kctx_uaf" --file "$variant" > "$WORK_DIR/test2_${variant}.log" 2>&1
        rc=$?
        cat "$WORK_DIR/test2_${variant}.log"
        sleep 1
    done
else
    echo "Error: poc_debugfs_kctx_uaf not found"
fi

# --- Capture KASAN reports ---
echo "=== Capturing KASAN reports ==="
dmesg | grep -B 10 -A 40 'KASAN' > "$WORK_DIR/kasan_reports.txt" 2>/dev/null || true
if [ -s "$WORK_DIR/kasan_reports.txt" ]; then
    echo "=== KASAN reports found ==="
    cat "$WORK_DIR/kasan_reports.txt" | head -120
else
    echo "(no KASAN reports found)"
fi

# --- Save results ---
cp "$WORK_DIR"/*.log /host/mali/ 2>/dev/null || echo "Saved logs only to $WORK_DIR/"

# --- Summary ---
echo "=== Test Summary ==="
if grep -q 'KASAN: use-after-free' "$WORK_DIR/kasan_reports.txt" 2>/dev/null; then
    echo "TEST 1 (mm_struct UAF): VULNERABILITY CONFIRMED"
else
    echo "TEST 1 (mm_struct UAF): No KASAN report"
fi
if grep -q 'slab-use-after-free' "$WORK_DIR/kasan_reports.txt" 2>/dev/null; then
    echo "TEST 2 (debugfs kctx UAF): VULNERABILITY CONFIRMED"
else
    echo "TEST 2 (debugfs kctx UAF): No KASAN report"
fi
echo "=== Done ==="