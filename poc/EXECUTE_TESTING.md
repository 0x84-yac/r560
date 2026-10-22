# Mali Driver Vulnerability Testing - Execution Guide

## Overview

This document provides a complete execution guide for testing the Mali driver vulnerability PoCs in `/home/za0x/Desktop/github/r560/poc/`. It covers both quick testing and comprehensive testing methodologies.

## Quick Testing Commands

### 1. Quick Environment Check

```bash
# Check test environment and available files
cd /home/za0x/Desktop/github/r560/poc
ls -la

# Examine test PoCs
cat poc.c | head -80           # Test 1: mm_struct UAF PoC
cat poc_debugfs_kctx_uaf.c | head -80  # Test 2: debugfs UAF PoC

# Check documentation
cat FINDINGS.md | head -50     # First vulnerability analysis
cat mali-r56p0-uaf-report.md | head -50  # Second vulnerability analysis
```

### 2. QEMU Testing Environment

```bash
# Navigate to QEMU test environment
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Quick pipeline (copy-paste ready):
export ARCH=aarch64
./01_fetch_kernel.sh 6.6.0
./02_build_kernel.sh
./03_build_driver.sh
./04_build_poc.sh
./05_run_qemu.sh
./detect_kasan.sh logs/full-*.log
```

## Detailed Test Execution

### Step 1: Prerequisites Setup

```bash
# Check system capabilities and install dependencies if needed
sudo apt update && sudo apt install -y \
    build-essential gcc-aarch64-linux-gnu \
    qemu-system-arm qemu-user-static \
    busybox cpio bc bison flex \
    libelf-dev libssl-dev ncurses-dev \
    gdb-multiarch gdb
```

### Step 2: Quick Test Analysis

```bash
# Examine test PoCs and understand their behavior
cat poc.c > test1_analysis.txt 2>&1

# This creates a file with the mm_struct UAF test
cat poc_debugfs_kctx_uaf.c > test2_analysis.txt 2>&1

# This creates a file with the debugfs UAF test
```

### Step 3: QEMU Environment Setup

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the setup pipeline:
./01_fetch_kernel.sh      # Fetch Linux kernel (~3-10 minutes)
./02_build_kernel.sh      # Build kernel with KASAN (~15-40 minutes)
./03_build_driver.sh      # Build Mali driver (~30 minutes)
./04_build_poc.sh         # Build test PoCs (~10 minutes)
```

### Step 4: Run Tests in QEMU

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Run comprehensive test in QEMU (may take 20-60 minutes)
./05_run_qemu.sh

# The test runs automatically and collects logs
# Look for output in: logs/full-<timestamp>.log
```

### Step 5: Analyze Results

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Analyze KASAN results
./detect_kasan.sh logs/full-*.log

# Examine detailed test logs
cat logs/dmesg-<timestamp>.log | grep -A 30 'KASAN: use-after-free'
```

## Test Analysis Commands

### Test 1: mm_struct UAF Analysis

```bash
# In the QEMU guest (if accessible):
cd /host/mali
./poc                    # Run mm_struct UAF test

# Check for KASAN reports
dmesg | grep -B 10 -A 30 'KASAN: use-after-free'

# Expected KASAN signature:
# BUG: KASAN: use-after-free in kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]
```

### Test 2: debugfs UAF Analysis

```bash
# The debugfs UAF runs automatically in the QEMU test environment
# Look for results in the logs directory

# Search for debugfs UAF reports
cat logs/full-*.log | grep -B 5 -A 25 'kbasep_mem_profile_seq_show'

# Check for privilege boundary crossing
cat logs/full-*.log | grep -B 5 -A 25 'mem_profile'
```

## Test Result Interpretation

### Expected Test 1 (mm_struct UAF) Results

**Successful Test Output**:
```
BUG: KASAN: use-after-free in kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]
    Write of size 8 at addr ffff0000c41f8f78 by task SLOWME/138

    Allotted by task 138:
      kasan_slab_alloc+0x1c4/0x2d8
      dup_mm+0x34/0x6a4                                    <-- child's mm_struct

    Freed by task 142:
      kasan_slab_free+0xb0/0x464
      __mmdrop+0x128/0x1d4

    The buggy address belongs to the object at ffff0000c41e1dc0
      which belongs to the cache mm_struct of size 944
    The buggy address is located 696 bytes inside of
      944-byte region [ffff0000c41e1dc0, ffff0000c41e2170)
```

### Expected Test 2 (debugfs UAF) Results

**Successful Test Output**:
```
BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x? (kernel/...)
    Read of size 8 at addr ...
    by task poc/784:
      ...
    freed by task kbase_release+0x...:
      ...
```

## Test Validation Scripts

### KASAN Analysis Script

```bash
#!/bin/bash
# analyze_kasan_results.sh - Analyze test results

set -euo pipefail

LOG_DIR="${1:-logs}"
SEARCH_TERM="KASAN: use-after-free"

if [ ! -d "$LOG_DIR" ]; then
    echo "Error: Log directory '$LOG_DIR' not found"
    exit 1
fi

echo "=== Mali Driver Vulnerability Test Results ==="
echo "Searching for: $SEARCH_TERM"
echo "Log directory: $LOG_DIR"
echo ""

# Count total occurrences
total_occurrences=$(find "$LOG_DIR" -name "*.log" -type f -exec grep -c "$SEARCH_TERM" {} \; | awk '{sum+=$1} END {print sum}')

echo "Total UAF occurrences found: $total_occurrences"
echo ""

# Display recent occurrences
find "$LOG_DIR" -name "full-*.log" -type f -exec grep -l "$SEARCH_TERM" {} \; | while read log_file; do
    echo "=== File: $log_file ==="
    echo "Date: $(basename "$log_file" | sed 's/full-//; s/.log//')"
    echo ""
    grep -B 5 -A 25 "$SEARCH_TERM" "$log_file" | head -50
    echo ""
    echo "===================================================="
    echo ""
done
```

### Environment Status Check

```bash
#!/bin/bash
# check_test_environment.sh - Check test environment status

echo "=== Mali Driver Test Environment Status ==="
echo ""

echo "System Information:"
echo "  - OS: $(uname -s) $(uname -r)"
echo "  - Architecture: $(uname -m)"
echo "  - User: $(whoami)"
echo ""

echo "Test Component Availability:"

# Check for core test files
test_files=(
    "poc/poc.c: mm_struct UAF test"
    "poc/poc_debugfs_kctx_uaf.c: debugfs UAF test"
    "poc/qemu-test/README.md: QEMU test environment"
    "build.sh: Driver build system"
    "run_arm64.sh: QEMU launcher"
)

for file_info in "${test_files[@]}"; do
    file_path="${file_info%%:*}"
    file_desc="${file_info#*: }"
    
    if [ -f "$file_path" ]; then
        echo "  ✓ $file_desc"
    else
        echo "  ✗ $file_desc (missing)"
    fi
done

echo ""
echo "QEMU Test Environment:"
if [ -d "poc/qemu-test" ]; then
    echo "  ✓ QEMU test directory available"
    if [ -f "poc/qemu-test/README.md" ]; then
        echo "  ✓ QEMU test documentation available"
    else
        echo "  ✗ QEMU test documentation missing"
    fi
else
    echo "  ✗ QEMU test directory missing"
fi
```

## Test Execution Scripts

### Complete Test Execution Script

```bash
#!/bin/bash
# run_mali_driver_tests.sh - Complete test execution script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$SCRIPT_DIR"
QEMU_TEST_DIR="$POC_DIR/qemu-test"

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "${BLUE}[TEST]${NC} $1"; }

print_banner() {
    echo "============================================================"
    echo "Mali Driver Vulnerability Test Suite"
    echo "Repository: $(pwd)"
    echo "============================================================"
}

# Quick test mode (non-QEMU)
quick_test() {
    log_header "Quick Test Mode"
    log_info "Running quick analysis without QEMU"
    
    # Check test environment
    log_info "Checking test environment..."
    check_test_environment
    
    # Analyze test PoCs
    log_info "Analyzing test PoCs..."
    cd "$POC_DIR"
    echo "=== Test 1: mm_struct UAF ==="
    echo "File: poc.c"
    echo "Lines: $(wc -l < poc.c)"
    echo "Description: Parent/child race condition UAF"
    echo ""
    
    echo "=== Test 2: debugfs UAF ==="
    echo "File: poc_debugfs_kctx_uaf.c"
    echo "Lines: $(wc -l < poc_debugfs_kctx_uaf.c)"
    echo "Description: Single-process deterministic debugfs UAF"
    echo ""
    
    # Show vulnerability summary
    log_info "Vulnerability Summary:"
    echo "  Test 1: mm_struct Use-After-Free (CWE-416)"
    echo "    - Type: Race condition"
    echo "    - Target: struct mm_struct"
    echo "    - Success rate: ~8% (KASAN: 100%)"
    echo "  Test 2: debugfs kctx Use-After-Free (CWE-416)"
    echo "    - Type: Deterministic"
    echo "    - Target: struct kbase_context"
    echo "    - Success rate: 100%"
}

# Check test environment
check_test_environment() {
    echo "System Information:"
    echo "  - OS: $(uname -s) $(uname -r)"
    echo "  - Architecture: $(uname -m)"
    echo "  - User: $(whoami)"
    echo ""
    
    echo "Test Components:"
    
    # Check core test files
    core_files=(
        "$POC_DIR/poc.c"
        "$POC_DIR/poc_debugfs_kctx_uaf.c"
        "$POC_DIR/qemu-test/README.md"
    )
    
    for file in "${core_files[@]}"; do
        if [ -f "$file" ]; then
            echo "  ✓ $(basename "$file")"
        else
            echo "  ✗ $(basename "$file") (missing)"
        fi
    done
}

# Main execution
main() {
    print_banner
    
    case "${1:-quick}" in
        "quick"|
        "q")
            quick_test
            ;;
        "qemu"|
        "q")
            if [ -d "$QEMU_TEST_DIR" ]; then
                log_header "QEMU Test Environment"
                log_info "Starting comprehensive QEMU tests..."
                log_warn "This may take 20-60 minutes and requires host privileges"
                echo ""
                log_info "To run QEMU tests, execute:"
                echo "  cd $QEMU_TEST_DIR"
                echo "  export ARCH=aarch64"
                echo "  ./01_fetch_kernel.sh 6.6.0"
                echo "  ./02_build_kernel.sh"
                echo "  ./03_build_driver.sh"
                echo "  ./04_build_poc.sh"
                echo "  ./05_run_qemu.sh"
                echo "  ./detect_kasan.sh logs/full-*.log"
            else
                log_error "QEMU test environment not found at $QEMU_TEST_DIR"
                exit 1
            fi
            ;;
        *)
            quick_test
            ;;
    esac
}

main "$@"