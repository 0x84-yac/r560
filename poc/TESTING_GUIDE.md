# Mali Driver Vulnerability Testing Guide

## Overview

This guide provides comprehensive instructions for testing the Mali driver vulnerability PoCs in `/home/za0x/Desktop/github/r560/poc/`. The repository contains two primary test cases:

1. **`poc.c`** - Midgard Mali Kbase `mm_struct` Use-After-Free (UAF)
2. **`poc_debugfs_kctx_uaf.c`** - CSF r56p0 debugfs kctx UAF

Both PoCs demonstrate different classes of kernel memory management vulnerabilities in ARM Mali GPU drivers.

## Test Environment Requirements

### Minimum Requirements
- Linux kernel with KASAN support (`CONFIG_KASAN=y`)
- ARM64 architecture (or cross-compilation setup)
- Mali driver compatibility (r42p0 for Midgard, r56p0 for CSF)
- Root privileges for full testing

### Recommended Testing Environment
For comprehensive vulnerability analysis, the QEMU test environment is recommended:

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the pipeline in README.md:
./01_fetch_kernel.sh      # Fetch Linux kernel
./02_build_kernel.sh      # Build kernel with KASAN
./03_build_driver.sh      # Build Mali driver
./04_build_poc.sh         # Build test PoCs
./05_run_qemu.sh          # Run comprehensive test in QEMU
./detect_kasan.sh         # Analyze test results
```

## Test Case Analysis

### Test Case 1: mm_struct UAF (`poc.c`)

#### Vulnerability Summary
- **Type**: Use-After-Free race condition
- **Target**: `struct mm_struct` in Mali Kbase driver
- **Root Cause**: Missing reference counting on `kctx->process_mm` pointer
- **Impact**: Kernel heap corruption, privilege escalation potential

#### Technical Details
- **CWE**: CWE-416 Use-After-Free, CWE-672 Operation on Resource after Expiration
- **Function**: `kbasep_os_process_page_usage_drain()`
- **Vulnerable Code**: `kbasep_add_mm_counter(mm, MM_FILEPAGES, -pages)`
- **Offset**: Field at `mm->rss_stat.count[MM_FILEPAGES]` (offset 0x192 or 696)

#### Reproduction Method
1. Open `/dev/mali0` device
2. Create tracking VMA via `mmap()` with special handle
3. Split VMA via `munmap()` (triggers race)
4. Fork child process
5. Child creates competing VMA and exits (frees mm_struct)
6. Parent triggers drain with 5-second kernel patch delay
7. Parent writes to freed child's mm_struct

#### Detection Method
- **KASAN**: `BUG: KASAN: use-after-free in kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]`
- **Stack Trace**: Shows debugfs reader vs `kbase_context_free`
- **Memory Layout**: Freed `mm_struct` at offset 696 inside 944-byte region

### Test Case 2: debugfs kctx UAF (`poc_debugfs_kctx_uaf.c`)

#### Vulnerability Summary
- **Type**: Deterministic Use-After-Free via debugfs
- **Target**: `struct kbase_context` via `i_private` dangling pointer
- **Root Cause**: `debugfs_remove_recursive()` doesn't invalidate open file handles
- **Impact**: Kernel read primitive, privilege boundary crossing

#### Technical Details
- **CWE**: CWE-416 Use-After-Free
- **Function**: `kbasep_mem_profile_seq_show()` / `kbasep_add_mm_counter()`
- **Affected Files**: `mem_profile`, `infinite_cache`, `force_same_va`, `mem_jit_*` debugfs files
- **Attack Vector**: Unprivileged userspace → privileged debugfs reader

#### Reproduction Method
1. Open `/dev/mali0` and execute `KBASE_IOCTL_MEM_PROFILE_ADD`
2. Creates `mem_profile` debugfs with attacker-controlled buffer
3. Open debugfs file (privileged reader)
4. Close device file (`/dev/mali0`) - frees `kctx` via `vfree()`
5. Read from still-open debugfs file - UAF occurs

#### Detection Method
- **KASAN**: `BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x?`
- **Privilege Boundary**: Shows cross-privilege corruption
- **Stack Trace**: Debugfs reader vs `kbase_context_free`

## Testing Strategy

### Step 1: Environment Setup

#### Option A: Quick Local Testing (User Space)
```bash
cd /home/za0x/Desktop/github/r560/poc

# Check existing PoCs
cat poc.c | head -50      # Examine mm_struct UAF PoC
cat poc_debugfs_kctx_uaf.c | head -50  # Examine debugfs UAF PoC

# Review build system
ls -la build.sh run_arm64.sh
```

#### Option B: Comprehensive QEMU Testing
```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the 6-step pipeline:
./01_fetch_kernel.sh      # Step 1: Fetch Linux tree
./02_build_kernel.sh      # Step 2: Build kernel with KASAN
./03_build_driver.sh      # Step 3: Build Mali driver
./04_build_poc.sh         # Step 4: Build PoCs
./05_run_qemu.sh          # Step 5: Run QEMU test
./detect_kasan.sh         # Step 6: Analyze results
```

### Step 2: Test Execution

#### Test 1: mm_struct UAF Execution
```bash
# For QEMU environment
cd /home/za0x/Desktop/github/r560/poc
./run_arm64.sh --flavor valhall  # Or bifrost

# In the guest (inside QEMU):
cd /host/mali
./poc                  # Run mm_struct UAF test
dmesg | grep -A 40 'KASAN: use-after-free'
```

#### Test 2: debugfs UAF Execution
```bash
# For QEMU environment with debugfs
# The PoC will run automatically as part of the QEMU test environment
# Look for debugfs UAF reports in logs/
```

### Step 3: Test Analysis

#### KASAN Report Analysis

**Expected Test 1 (mm_struct UAF) Output**:
```
BUG: KASAN: use-after-free in kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]
Write of size 8 at addr ffff0000c41f8f78 by task SLOWME/138

CPU: 0 PID: 138 Comm: SLOWME Not tainted 5.10.155 #2
Call trace:
  dump_backtrace+0x0/0x298
  show_stack+0x18/0x24
  dump_stack+0xf4/0x160
  print_address_description.constprop.0x6c/0x484
  kasan_report+0x104/0x1f4
  check_memory_region+0xe8/0x1a0
  __kasan_check_write+0x3c/0x48
  kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]     <-- WRITE
  kbase_special_vm_close+0xb4/0x120 [mali_kbase]               <-- .close callback

Allotted by task 138:
  kasan_save_stack+0x38/0x74
  kmem_cache_alloc+0x1c4/0x2d8
  dup_mm+0x34/0x6a4                                    <-- child's mm_struct

Freed by task 142:
  kasan_save_stack+0x38/0x74
  kmem_cache_free+0xb0/0x464
  __mmdrop+0x128/0x1d4                                    <-- mm_struct freed
  mmput+0x1a0/0x1d0
  do_exit+0x48c/0xe34

The buggy address belongs to the object at ffff0000c41e1dc0
  which belongs to the cache mm_struct of size 944
The buggy address is located 696 bytes inside of
  944-byte region [ffff0000c41e1dc0, ffff0000c41e2170)
```

**Expected Test 2 (debugfs UAF) Output**:
```
BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x? (kernel/...)
Read of size 8 at addr ...
by task poc/784:
  ...
freed by task kbase_release+0x...:
  ...
```

#### Test Result Classification

| Result | Description | Test 1 | Test 2 |
|--------|-------------|--------|--------|
| **SUCCESS** | KASAN UAF detected | ✓ | ✓ |
| **CLEAN** | No UAF, but test completed | - | - |
| **INCONCLUSIVE** | Other failure mode | - | - |
| **ERROR** | Test setup/execution failure | - | - |

### Step 4: Test Validation

#### Test 1 Validation Points
1. **Race Window**: Verify ~8% success rate without KASAN
2. **KASAN Detection**: Confirm UAF reports with KASAN
3. **Memory Corruption**: Validate target field corruption (offset 0x192)
4. **Privilege Impact**: Assess privilege escalation potential

#### Test 2 Validation Points
1. **Determinism**: Verify 100% success rate with proper setup
2. **Privilege Boundary**: Confirm cross-privilege exploitation
3. **Debugfs Coverage**: Test all affected debugfs files
4. **Write Primitive**: Validate attacker-shaped payload effectiveness

## Test Resources

### Debug Output Analysis

#### Kernel Log Analysis Script
```bash
#!/bin/bash
# analyze_kasan.sh - Analyze KASAN reports from test runs

set -euo pipefail

LOG_DIR="${1:-logs}"
SEARCH_TERM="KASAN: use-after-free"

if [ ! -d "$LOG_DIR" ]; then
    echo "Error: Log directory '$LOG_DIR' not found"
    exit 1
fi

echo "=== KASAN Analysis ==="
echo "Searching for: $SEARCH_TERM"
echo "Log directory: $LOG_DIR"
echo ""

# Find all relevant log files
LOG_FILES=$(find "$LOG_DIR" -name "*.log" -type f | head -10)

if [ -z "$LOG_FILES" ]; then
    echo "No log files found in $LOG_DIR"
    exit 0
fi

for log_file in $LOG_FILES; do
    echo "=== Analyzing: $log_file ==="
    grep -c "$SEARCH_TERM" "$log_file" | xargs echo "Total UAF occurrences:"
    grep -A 5 "$SEARCH_TERM" "$log_file" | head -50
    echo ""
done
```

### Test Environment Status Check

```bash
#!/bin/bash
# check_test_env.sh - Check test environment status

echo "=== Mali Driver Test Environment Status ==="
echo ""

echo "System Information:"
echo "  - OS: $(uname -s) $(uname -r)"
echo "  - Architecture: $(uname -m)"
echo "  - Kernel: $(uname -r)"

echo ""
echo "Test Components Check:"

# Check for required files
required_files=(
    "$HOME/za0x/Desktop/github/r560/poc/poc.c"
    "$HOME/za0x/Desktop/github/r560/poc/poc_debugfs_kctx_uaf.c"
    "$HOME/za0x/Desktop/github/r560/poc/qemu-test/README.md"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file (missing)"
    fi
done

echo ""
echo "Build System Check:"
if [ -f "$HOME/za0x/Desktop/github/r560/build.sh" ]; then
    echo "  ✓ build.sh available"
else
    echo "  ✗ build.sh missing"
fi

echo ""
echo "QEMU Test Environment:"
if [ -d "$HOME/za0x/Desktop/github/r560/poc/qemu-test" ]; then
    echo "  ✓ qemu-test directory available"
    if [ -f "$HOME/za0x/Desktop/github/r560/poc/qemu-test/README.md" ]; then
        echo "  ✓ qemu-test/README.md available"
    else
        echo "  ✗ qemu-test/README.md missing"
    fi
else
    echo "  ✗ qemu-test directory missing"
fi
```

## Test Summary

### Test Case 1: mm_struct UAF
- **Success Conditions**: KASAN detects use-after-free in `kbasep_add_mm_counter`
- **Key Validation**: Target field corruption at offset 0x192
- **Testing Complexity**: Medium (race condition requires precise timing)
- **Resource Requirements**: KASAN-enabled kernel, ARM64 environment

### Test Case 2: debugfs UAF
- **Success Conditions**: KASAN detects use-after-free in debugfs reader
- **Key Validation**: Privilege boundary crossing confirmed
- **Testing Complexity**: Low (deterministic, single-process)
- **Resource Requirements**: Root access, debugfs mounted

### Recommended Testing Order
1. **Start with Test 2 (debugfs UAF)**: Easier to reproduce, validates environment
2. **Follow with Test 1 (mm_struct UAF)**: More complex, validates race condition handling
3. **Comparative Analysis**: Compare exploitation techniques and impact

## Conclusion

This testing guide provides comprehensive instructions for validating the two primary Mali driver vulnerability PoCs. The repository is well-structured with established testing methodologies and comprehensive analysis documentation. For production vulnerability assessment, the QEMU test environment is strongly recommended to ensure complete control over the testing environment and accurate vulnerability validation.