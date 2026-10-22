# Mali Driver Vulnerability Testing - Complete Summary

## Repository Overview

This repository contains comprehensive test cases for ARM Mali GPU kernel driver vulnerabilities. It focuses on two distinct classes of Use-After-Free (UAF) vulnerabilities:

1. **mm_struct Use-After-Free** - Race condition vulnerability
2. **debugfs kctx Use-After-Free** - Deterministic debugfs dangling pointer bug

## Test Files Summary

### Core Test PoCs
- **`poc.c`** - Midgard Mali Kbase mm_struct UAF (race condition)
- **`poc_debugfs_kctx_uaf.c`** - CSF r56p0 debugfs kctx UAF (deterministic)

### Analysis Documentation
- **`FINDINGS.md`** - First vulnerability discovery and analysis
- **`mali-r56p0-uaf-report.md`** - Second vulnerability report (4 findings)
- **`deep_seek_report.md`** - Deep analysis of memory management
- **`memory_primitives_catalog.md`** - Complete memory management primitives catalog

### Testing Infrastructure
- **`qemu-test/`** - Full QEMU test environment for comprehensive testing
- **`build.sh`** - Driver build system
- **`run_arm64.sh`** - QEMU launcher

## Testing Strategy Overview

### Testing Approach Comparison

| Testing Method | Advantages | Disadvantages | Best Use Case |
|----------------|------------|---------------|---------------|
| **Quick Analysis** | Fast, user-space only, good for understanding | Limited validation, no KASAN testing | Initial analysis, documentation |
| **QEMU Environment** | Comprehensive, KASAN-enabled, realistic | Time-intensive, complex setup | Production vulnerability validation |

### Test Case Analysis

#### Test Case 1: mm_struct UAF (`poc.c`)
- **Vulnerability Class**: Use-After-Free race condition
- **Target**: `struct mm_struct` in Mali Kbase driver
- **Root Cause**: Missing reference counting on `kctx->process_mm` pointer
- **Exploitation**: Parent/child process race condition
- **Success Rate**: ~8% without KASAN, 100% with KASAN
- **Impact**: Kernel heap corruption, privilege escalation potential

#### Test Case 2: debugfs kctx UAF (`poc_debugfs_kctx_uaf.c`)
- **Vulnerability Class**: Deterministic Use-After-Free
- **Target**: `struct kbase_context` via debugfs `i_private` dangling pointer
- **Root Cause**: `debugfs_remove_recursive()` doesn't invalidate open file handles
- **Exploitation**: Privilege boundary crossing (unprivileged closer → privileged reader)
- **Success Rate**: 100% deterministic
- **Impact**: Kernel read primitive, cross-privilege boundary escalation

## Testing Execution Guide

### Step 1: Quick Environment Check

```bash
# Navigate to test directory
cd /home/za0x/Desktop/github/r560/poc

# List all test files
ls -la

# Examine test PoCs (read-only analysis)
echo "=== Test 1: mm_struct UAF PoC ==="
cat poc.c | head -80

echo "=== Test 2: debugfs UAF PoC ==="
cat poc_debugfs_kctx_uaf.c | head -80

# Check analysis documentation
echo "=== Vulnerability Analysis ==="
cat FINDINGS.md | head -50
```

### Step 2: QEMU Environment Setup (Recommended)

```bash
# Navigate to QEMU test environment
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the complete pipeline:
export ARCH=aarch64                    # Set architecture
./01_fetch_kernel.sh 6.6.0             # Fetch Linux kernel (~3-10 min)
./02_build_kernel.sh                   # Build kernel with KASAN (~15-40 min)
./03_build_driver.sh                   # Build Mali driver (~30 min)
./04_build_poc.sh                      # Build test PoCs (~10 min)
./05_run_qemu.sh                       # Run comprehensive test (~20-60 min)
./detect_kasan.sh logs/full-*.log      # Analyze results
```

### Step 3: Test Analysis Commands

```bash
# In the QEMU guest (if accessible):
cd /host/mali
./poc                    # Run mm_struct UAF test

# Check for KASAN UAF reports
dmesg | grep -B 10 -A 30 'KASAN: use-after-free'

# The debugfs UAF runs automatically in QEMU test environment
# Results captured in logs/ directory

# Analyze KASAN results
cat logs/full-*.log | grep -B 5 -A 25 'KASAN: use-after-free'
```

## Test Results Analysis

### Expected Test 1 (mm_struct UAF) Output

**Successful Test Characteristics**:
- **Trigger**: Race condition between parent/child processes
- **Detection**: KASAN reports `use-after-free in kbasep_add_mm_counter`
- **Target Field**: `mm->rss_stat.count[MM_FILEPAGES]` at offset 0x192 (696)
- **Memory Layout**: Freed `mm_struct` (944 bytes)
- **Exploitation**: Kernel heap corruption, privilege escalation primitive

### Expected Test 2 (debugfs UAF) Output

**Successful Test Characteristics**:
- **Trigger**: Single-process deterministic UAF
- **Detection**: KASAN reports `use-after-free in kbasep_mem_profile_seq_show`
- **Target**: `struct kbase_context` via debugfs `i_private`
- **Exploitation**: Privilege boundary crossing with attacker-shaped payload
- **Impact**: Kernel read primitive, cross-privilege escalation

## Test Validation Scripts

### Quick Validation Script

```bash
#!/bin/bash
# validate_tests.sh - Quick validation of test PoCs

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Mali Driver Test Validation ==="
echo "Repository: $POC_DIR"
echo ""

echo "Test 1: mm_struct UAF PoC"
echo "  File: $POC_DIR/poc.c"
echo "  Lines: $(wc -l < "$POC_DIR/poc.c")"
echo "  Description: Parent/child race condition UAF"
echo "  Target: struct mm_struct in Mali Kbase driver"
echo "  Success rate: ~8% (KASAN: 100%)"
echo ""

echo "Test 2: debugfs UAF PoC"
echo "  File: $POC_DIR/poc_debugfs_kctx_uaf.c"
echo "  Lines: $(wc -l < "$POC_DIR/poc_debugfs_kctx_uaf.c")"
echo "  Description: Single-process deterministic debugfs UAF"
echo "  Target: struct kbase_context via debugfs i_private"
echo "  Success rate: 100%"
echo ""

echo "Analysis Documentation:"
for doc in "$POC_DIR/FINDINGS.md" "$POC_DIR/mali-r56p0-uaf-report.md" "$POC_DIR/memory_primitives_catalog.md"; do
    if [ -f "$doc" ]; then
        echo "  ✓ $(basename "$doc") ($(wc -l < "$doc") lines)"
    else
        echo "  ✗ $(basename "$doc") (missing)"
    fi
done

echo ""
echo "Testing Infrastructure:"
if [ -d "$POC_DIR/qemu-test" ]; then
    echo "  ✓ QEMU test environment"
    if [ -f "$POC_DIR/qemu-test/README.md" ]; then
        echo "  ✓ QEMU documentation"
    fi
else
    echo "  ✗ QEMU test environment missing"
fi
```

### KASAN Analysis Script

```bash
#!/bin/bash
# analyze_kasan_results.sh - Analyze KASAN test results

set -euo pipefail

LOG_DIR="${1:-logs}"
SEARCH_TERM="KASAN: use-after-free"

if [ ! -d "$LOG_DIR" ]; then
    echo "Error: Log directory '$LOG_DIR' not found"
    exit 1
fi

echo "=== Mali Driver KASAN Test Analysis ==="
echo "Searching for: $SEARCH_TERM"
echo "Log directory: $LOG_DIR"
echo ""

# Count total occurrences
total=$(find "$LOG_DIR" -name "*.log" -type f -exec grep -c "$SEARCH_TERM" {} \; | awk '{sum+=$1} END {print sum}')

echo "Total UAF occurrences: $total"

echo ""
echo "=== Recent UAF Reports ==="
find "$LOG_DIR" -name "full-*.log" -type f -exec grep -l "$SEARCH_TERM" {} \; | while read log_file; do
    echo "File: $(basename "$log_file")"
    echo "Date: $(basename "$log_file" | sed 's/full-//; s/.log//')"
    echo ""
    grep -B 10 -A 20 "$SEARCH_TERM" "$log_file" | head -60
    echo ""
    echo "===================================================="
    echo ""
done
```

## Test Environment Setup

### System Requirements

**Minimum Requirements**:
- Linux kernel with KASAN support (`CONFIG_KASAN=y`)
- ARM64 architecture (or cross-compilation)
- Root privileges for full testing

**Recommended Requirements**:
- QEMU environment with cross-compilation
- Complete ARM64 development toolchain
- Sufficient disk space for kernel compilation (~50GB+)

### Software Dependencies

```bash
# Ubuntu/Debian dependencies
sudo apt update
sudo apt install -y \
    build-essential \
    gcc-aarch64-linux-gnu \
    qemu-system-arm \
    qemu-user-static \
    busybox \
    cpio \
    bc \
    bison \
    flex \
    libelf-dev \
    libssl-dev \
    ncurses-dev \
    gdb-multiarch \
    gdb
```

## Test Case Details

### Test Case 1: mm_struct UAF

#### Technical Specifications
- **File**: `poc.c`
- **Lines**: 78
- **Architecture**: ARM64
- **Dependencies**: KASAN-enabled kernel
- **Execution Time**: Variable (race condition)
- **Privilege Required**: None (for basic testing)

#### Test Flow
1. Device initialization via `/dev/mali0`
2. Version check ioctl (`KBASE_IOCTL_VERSION_CHECK`)
3. Flags configuration (`KBASE_IOCTL_SET_FLAGS`)
4. Parent tracking page mapping (2 pages)
5. Parent page split (unmap page 2)
6. Process forking (create child)
7. Child tracking page mapping (1 page)
8. Controlled delay (sleep 2 seconds)
9. Child page unmap (triggers UAF setup)
10. Child process exit (frees mm_struct)
11. Parent delay (sleep 1 second)
12. Parent name change (`SLOWME`) - enables kernel patch
13. Parent page unmap (triggers drain UAF)
14. Parent name change (`PARENT`) - ends kernel patch
15. Race condition execution

#### Detection Method
- **Primary**: KASAN `use-after-free in kbasep_add_mm_counter`
- **Secondary**: Stack trace showing debugfs reader vs `kbase_context_free`
- **Target Offset**: 0x192 in `mm_struct` (696 bytes)

### Test Case 2: debugfs UAF

#### Technical Specifications
- **File**: `poc_debugfs_kctx_uaf.c`
- **Lines**: 297
- **Architecture**: ARM64
- **Dependencies**: KASAN-enabled kernel, debugfs
- **Execution Time**: Fixed (deterministic)
- **Privilege Required**: Root (for debugfs access)

#### Test Flow
1. Device initialization via `/dev/mali0`
2. MEM_PROFILE_ADD ioctl (creates debugfs files)
3. Debugfs directory enumeration
4. mem_profile debugfs file opening (privileged reader)
5. Device file closing (triggers kctx cleanup)
6. Read from dangling debugfs file (UAF trigger)
7. File descriptor cleanup

#### Detection Method
- **Primary**: KASAN `use-after-free in kbasep_mem_profile_seq_show`
- **Secondary**: Privilege boundary crossing analysis
- **Target**: `struct kbase_context` via `i_private` dangling pointer

## Test Impact Analysis

### Vulnerability Classification

| Vulnerability | Classification | Impact Level | Exploitation Difficulty |
|---------------|----------------|--------------|--------------------------|
| mm_struct UAF | CWE-416 Use-After-Free | High | Medium (race condition) |
| debugfs UAF | CWE-416 Use-After-Free | High | Low (deterministic) |

### Security Impact

**Test 1 Impact**:
- **Kernel Heap Corruption**: Write to freed `mm_struct`
- **Privilege Escalation**: Potential for kernel code execution
- **System Stability**: Kernel crashes/ooops possible

**Test 2 Impact**:
- **Privilege Boundary Crossing**: Unprivileged closer → privileged reader
- **Kernel Read Primitive**: Attacker-controlled buffer redirection
- **Information Disclosure**: Kernel memory read primitive

## Testing Recommendations

### For Security Researchers

1. **Start with Quick Analysis**: Use the quick testing approach to understand the vulnerabilities
2. **Set Up QEMU Environment**: For comprehensive testing, follow the QEMU pipeline
3. **Document Findings**: Use the analysis documentation as reference
4. **Validate Exploits**: Confirm the expected KASAN signatures

### For Developers

1. **Understand Root Causes**: Focus on reference counting and debugfs handling
2. **Implement Fixes**: Address the specific patterns causing UAFs
3. **Testing Strategy**: Use deterministic tests for validation
4. **Regression Testing**: Ensure fixes don't break existing functionality

### For Organizations

1. **Risk Assessment**: Evaluate privilege escalation potential
2. **Remediation Planning**: Prioritize fixes based on impact
3. **Testing Resources**: Invest in comprehensive test environments
4. **Security Validation**: Use established test cases for validation

## Conclusion

This repository provides a comprehensive foundation for testing ARM Mali driver vulnerabilities. The two test cases demonstrate different classes of UAF vulnerabilities with varying exploitation complexity and impact.

For vulnerability research and validation, this represents an excellent starting point with:
- Well-documented vulnerabilities
- Reproducible test cases
- Comprehensive analysis
- Established testing infrastructure

The test suite validates both race condition and deterministic UAF vulnerabilities, demonstrating the range of exploitation techniques and security impacts in kernel driver code.