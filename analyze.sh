#!/bin/bash
# analyze.sh - Comprehensive Mali vulnerability analysis script
# Place in /host/mali/ or /mnt/ and run inside QEMU guest

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/host/analysis_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

log() { echo -e "\033[1;34m==>\033[0m $*"; }
warn() { echo -e "\033[1;33mWARN:\033[0m $*"; }
error() { echo -e "\033[1;31mERROR:\033[0m $*"; }

echo "=== Mali Driver Vulnerability Deep Analysis ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

# 1. System Information
log "Collecting system information..."
{
    echo "=== System Info ==="
    uname -a
    cat /proc/cmdline
    echo ""
    echo "=== Mali Driver ==="
    dmesg | grep -i mali | head -30
    echo ""
    echo "=== KASAN Config ==="
    cat /proc/config.gz 2>/dev/null | gunzip | grep -E 'KASAN|DEBUG' || zcat /proc/config.gz 2>/dev/null | grep -E 'KASAN|DEBUG' || echo "Config not accessible"
} > "$OUTPUT_DIR/system_info.txt" 2>&1

# 2. Test 1: mm_struct UAF
log "Running mm_struct UAF test (poc)..."
if [ -f /host/mali/poc ]; then
    /host/mali/poc 2>&1 | tee "$OUTPUT_DIR/test1_mm_struct_uaf.log"
    sleep 3
    dmesg | grep -B 10 -A 40 'KASAN: use-after-free' > "$OUTPUT_DIR/test1_kasan.txt" 2>&1 || true
else
    warn "poc binary not found"
fi

# 3. Test 2: debugfs kctx UAF
log "Running debugfs kctx UAF test (poc_debugfs_kctx_uaf)..."
if [ -f /host/mali/poc_debugfs_kctx_uaf ]; then
    # Default test (mem_profile)
    /host/mali/poc_debugfs_kctx_uaf 2>&1 | tee "$OUTPUT_DIR/test2_debugfs_uaf_default.log"
    sleep 2
    dmesg | grep -B 10 -A 40 'slab-use-after-free' > "$OUTPUT_DIR/test2_kasan.txt" 2>&1 || true
    
    # Test all variants
    for variant in mem_jit_count mem_jit_vm mem_jit_phys mem_jit_used mem_jit_trim; do
        log "Testing variant: $variant"
        /host/mali/poc_debugfs_kctx_uaf --file "$variant" 2>&1 | tee "$OUTPUT_DIR/test2_${variant}.log"
        sleep 1
    done
else
    warn "poc_debugfs_kctx_uaf binary not found"
fi

# 4. Mali smoke test
log "Running Mali smoke test..."
if [ -f /host/mali/mali_smoke ]; then
    /host/mali/mali_smoke 2>&1 | tee "$OUTPUT_DIR/mali_smoke.log"
else
    warn "mali_smoke binary not found"
fi

# 5. Memory analysis
log "Collecting memory analysis..."
{
    echo "=== slabinfo (mm_struct) ==="
    cat /proc/slabinfo | grep -E 'mm_struct|kbase'
    echo ""
    echo "=== meminfo ==="
    cat /proc/meminfo
    echo ""
    echo "=== vmallocinfo ==="
    cat /proc/vmallocinfo | grep -i mali | head -20
    echo ""
    echo "=== KASAN status ==="
    cat /sys/kernel/debug/kasan/report_mode 2>/dev/null || echo "KASAN debugfs not available"
} > "$OUTPUT_DIR/memory_analysis.txt" 2>&1

# 6. Extract all KASAN reports
log "Extracting all KASAN reports..."
dmesg -T | grep -B 15 -A 40 -E 'KASAN:|slab-use-after-free|use-after-free' > "$OUTPUT_DIR/all_kasan_reports.txt" 2>&1 || true

# 7. Specific vulnerability traces
log "Extracting specific vulnerability traces..."
dmesg -T | grep -B 5 -A 30 'kbasep_add_mm_counter' > "$OUTPUT_DIR/trace_mm_struct.txt" 2>&1 || true
dmesg -T | grep -B 5 -A 30 'kbasep_mem_profile_seq_show' > "$OUTPUT_DIR/trace_debugfs.txt" 2>&1 || true
dmesg -T | grep -B 5 -A 30 'kbase_special_vm_close' > "$OUTPUT_DIR/trace_vm_close.txt" 2>&1 || true
dmesg -T | grep -B 5 -A 30 'kbasep_os_process_page_usage_drain' > "$OUTPUT_DIR/trace_drain.txt" 2>&in || true

# 8. Debugfs enumeration
log "Enumerating debugfs..."
{
    echo "=== Mali debugfs structure ==="
    find /sys/kernel/debug -name '*mali*' -type d 2>/dev/null | sort
    echo ""
    for dir in /sys/kernel/debug/mali*/ctx/*/; do
        if [ -d "$dir" ]; then
            echo "Context dir: $dir"
            ls -la "$dir"
            echo ""
        fi
    done
} > "$OUTPUT_DIR/debugfs_enum.txt" 2>&in

# 9. Module info
log "Collecting module information..."
{
    echo "=== Module info ==="
    modinfo /host/mali/mali_kbase.ko
    echo ""
    echo "=== Loaded modules ==="
    lsmod | grep -i mali
    echo ""
    echo "=== Module parameters ==="
    cat /sys/module/mali_kbase/parameters/* 2>/dev/null || true
} > "$OUTPUT_DIR/module_info.txt" 2>&in

# 10. Summary
log "Generating summary..."
{
    echo "=== Analysis Summary ==="
    echo "Timestamp: $(date)"
    echo "Kernel: $(uname -r)"
    echo ""
    echo "=== Test 1: mm_struct UAF ==="
    if grep -q 'KASAN: use-after-free' "$OUTPUT_DIR/test1_kasan.txt" 2>/dev/null; then
        echo "STATUS: VULNERABILITY CONFIRMED"
        grep -c 'KASAN: use-after-free' "$OUTPUT_DIR/test1_kasan.txt" | xargs echo "Occurrences:"
    else
        echo "STATUS: NOT DETECTED (or clean)"
    fi
    echo ""
    echo "=== Test 2: debugfs kctx UAF ==="
    if grep -q 'slab-use-after-free' "$OUTPUT_DIR/test2_kasan.txt" 2>/dev/null; then
        echo "STATUS: VULNERABILITY CONFIRMED"
        grep -c 'slab-use-after-free' "$OUTPUT_DIR/test2_kasan.txt" | xargs echo "Occurrences:"
    else
        echo "STATUS: NOT DETECTED (or clean)"
    fi
    echo ""
    echo "=== Files generated ==="
    ls -la "$OUTPUT_DIR/"
} > "$OUTPUT_DIR/SUMMARY.txt"

cat "$OUTPUT_DIR/SUMMARY.txt"

log "Analysis complete! Results in: $OUTPUT_DIR"
echo "Copy results back to host with: ./disk.sh get $OUTPUT_DIR /home/user/analysis_results"