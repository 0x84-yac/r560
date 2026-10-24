#!/bin/sh
# run.sh - runs smoke test and UAF PoCs automatically after kernel boot
DIR="${0%/*}"

echo "=== Starting 5gen Smoke Tests ==="
echo "DIR is: $DIR"

WORK_DIR="/tmp/uaf_tests"
mkdir -p "$WORK_DIR"

# --- Smoke test: verify driver initialization ---
echo ""
echo "=== Test 0: 5gen Smoke Test ==="
if [ -x "$DIR/smoke_test_5gen" ]; then
    "$DIR/smoke_test_5gen"
    SMOKE_RC=$?
    echo "smoke_test_rc=$SMOKE_RC"
else
    echo "Error: smoke_test_5gen not found"
fi

# --- Debug: enumerate Mali debugfs structure ---
echo ""
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

# --- Test 2: debugfs kctx UAF ---
echo ""
echo "=== Test 2: debugfs kctx UAF (poc_debugfs_kctx_uaf) ==="
echo "Timestamp: $(date)"
if [ -x "$DIR/poc_debugfs_kctx_uaf" ]; then
    "$DIR/poc_debugfs_kctx_uaf" > "$WORK_DIR/test2_default.log" 2>&1
    rc=$?
    echo "=== Test 2 (default) output (exit code: $rc) ==="
    cat "$WORK_DIR/test2_default.log"
    sleep 2

    for variant in mem_jit_count mem_jit_vm mem_jit_phys mem_jit_used mem_jit_trim; do
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
echo ""
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
echo ""
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

# --- Run new UAF tests ---
if [ -x "$DIR/run_new_tests.sh" ]; then
    echo ""
    echo "=== Running New UAF Tests ==="
    "$DIR/run_new_tests.sh"
else
    echo "New UAF test script not found, skipping"
fi
