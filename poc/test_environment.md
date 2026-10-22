# Mali Driver Vulnerability Test Environment

## Overview

This document describes the test environment for the Mali driver vulnerability research repository (`/home/za0x/Desktop/github/r560/poc/`). It includes two primary test PoCs:

1. **`poc.c`** - Midgard Mali Kbase mm_struct Use-After-Free (race condition)
2. **`poc_debugfs_kctx_uaf.c`** - CSF r56p0 debugfs kctx UAF (deterministic)

## Test Architecture

### Kernel Environment Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| Linux Kernel | 5.10.155 | Target tested version (matches build system) |
| CONFIG_KASAN | y | Kernel Address Sanitizer for UAF detection |
| CONFIG_DEBUG_FS | y | Debugfs support for debugfs UAF PoC |
| CONFIG_MALI_NONE | y | No hardware Mali driver (fake platform) |
| ARCH | arm64 | Target architecture |

### Test PoC Categories

#### Category 1: Race Condition UAF (poc.c)
- **Vulnerability**: `mm_struct` Use-After-Free in Mali Kbase driver
- **Method**: Parent/child process race condition
- **Trigger**: Split munmap -> close handler -> synchronize_rcu() -> child's mm_struct freed
- **Exploitation**: ~8% success rate without KASAN, deterministic with KASAN
- **Impact**: Kernel heap corruption, privilege escalation potential

#### Category 2: Deterministic Debugfs UAF (poc_debugfs_kctx_uaf.c)
- **Vulnerability**: Per-kctx debugfs files dereference freed `kctx`
- **Method**: Single-process deterministic UAF via debugfs i_private dangling pointer
- **Trigger**: `close(/dev/mali0)` + `read(debugfs)` on already-open file handle
- **Exploitation**: 100% deterministic when properly configured
- **Impact**: Kernel read primitive, privilege boundary crossing

## Test Files

### Enhanced Test PoCs

#### Test 1: `test_poc.c` (mm_struct UAF enhanced)
**Location**: `/home/za0x/Desktop/github/r560/poc/test_poc.c`

Features:
- Comprehensive step-by-step debug output
- Mapped region analysis with kernel address extraction
- Detailed ioctl explanation and parameter logging
- Race condition timing control
- Privilege boundary demonstration
- Enhanced error reporting and state tracking

**Build Command**:
```bash
cd /home/za0x/Desktop/github/r560/poc
gcc -O2 -o test_poc test_poc.c -std=c11 -Wall -Wextra
```

**Expected Output**:
- Detailed step-by-step execution trace
- File descriptor analysis
- Kernel address reporting (if KASAN available)
- Race condition timing information
- Error condition analysis

#### Test 2: `test_debugfs_poc.c` (debugfs UAF enhanced)
**Location**: `/home/za0x/Desktop/github/r560/poc/test_debugfs_poc.c`

Features:
- Debugfs directory enumeration and analysis
- Privilege boundary crossing demonstration
- File descriptor tracking and analysis
- Comprehensive error handling
- System information reporting

**Build Command**:
```bash
cd /home/za0x/Desktop/github/r560/poc
gcc -O2 -o test_debugfs_poc test_debugfs_poc.c -std=c11 -Wall -Wextra
```

**Expected Output**:
- Debugfs file discovery and analysis
- Privilege boundary demonstration
- File descriptor state tracking
- System requirement validation
- Expected KASAN output format

### Original PoCs

#### Original Test 1: `poc.c` (mm_struct UAF)
**Location**: `/home/za0x/Desktop/github/r560/poc/poc.c`

- Original deterministic UAF reproducer
- Based on FINDINGS.md analysis
- Requires kernel patch for race window
- Limited debug output

#### Original Test 2: `poc_debugfs_kctx_uaf.c` (debugfs UAF)
**Location**: `/home/za0x/Desktop/github/r560/poc/poc_debugfs_kctx_uaf.c`

- Original deterministic debugfs UAF PoC
- From mali-r56p0-uaf-report.md
- Crash-only (no exploitation)
- Requires root access

## Test Environment Setup

### Prerequisites

```bash
# Ubuntu/Debian dependencies
sudo apt update
sudo apt install -y \
    build-essential \
    gcc-aarch64-linux-gnu \
    gdb-multiarch \
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
    git \
    python3
```

### Test Environment Requirements

#### For Enhanced PoCs (local testing)
- ARM64 cross-compiler (aarch64-linux-gnu-gcc)
- Basic user-space testing environment
- No kernel privileges required for basic testing

#### For Full Vulnerability Testing (QEMU environment)
- Complete QEMU test environment (see qemu-test/README.md)
- Kernel with KASAN enabled
- Mali driver compiled for test environment
- Root access for full test execution

## Test Execution Steps

### Step 1: Environment Preparation

```bash
cd /home/za0x/Desktop/github/r560/poc

# Check system capabilities
uname -a
arch
which aarch64-linux-gnu-gcc
which qemu-system-aarch64

# Verify build system
./build.sh --help 2>/dev/null || echo "Build system available"
```

### Step 2: Compile Enhanced PoCs

```bash
# Test 1: mm_struct UAF PoC (local user-space testing)
cd /home/za0x/Desktop/github/r560/poc
gcc -O2 -o test_poc test_poc.c -std=c11 -Wall -Wextra

# Test 2: Debugfs UAF PoC (local user-space testing)
gcc -O2 -o test_debugfs_poc test_debugfs_poc.c -std=c11 -Wall -Wextra
```

### Step 3: Execute Tests (Local User-Space)

```bash
# Test 1: Run mm_struct UAF PoC
./test_poc

# Test 2: Run debugfs UAF PoC (requires root)
sudo ./test_debugfs_poc
```

### Step 4: Full Integration Testing (QEMU)

For comprehensive testing with KASAN and kernel-level validation:

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the pipeline described in README.md:
# 1. Fetch kernel
./01_fetch_kernel.sh

# 2. Build kernel with KASAN
./02_build_kernel.sh

# 3. Build Mali driver
./03_build_driver.sh

# 4. Build PoCs
./04_build_poc.sh

# 5. Run comprehensive test in QEMU
./05_run_qemu.sh

# 6. Analyze results
./detect_kasan.sh logs/full-<timestamp>.log
```

## Expected Test Results

### Test 1: mm_struct UAF PoC

#### Successful Execution (Expected)
```
=== Mali Kbase mm_struct UAF Test PoC ===
PID: 1234, PPID: 1

[STEP 0] Device Initialization
  - Opening /dev/mali0 device file for read-write access
  -> SUCCESS: Device file descriptor: 3
  -> File type: character device
  -> Device number: 238:0

[STEP 1] Version Check Ioctl
  - Command: KBASE_IOCTL_VERSION_CHECK (_IOWR(0x80, 0, ...))
  -> SUCCESS: Ioctl returned 0, version struct updated: major=11, minor=11

[STEP 2] Set Flags Ioctl
  -> SUCCESS: Ioctl returned 0, flags configured

[STEP 3] Parent Tracking Page Mapping
  -> SUCCESS: Parent tracking page mapped at address: 0x7f8c1d000000
  -> Page 1 address: 0x7f8c1d000000
  -> Page 2 address: 0x7f8c1d001000

[STEP 4] Parent Page 2 Unmapping (Race Trigger)
  -> SUCCESS: Parent page 2 unmapped, split VMA triggered
  -> Result: parent_tracking_page still valid (page 1 remains mapped)

[STEP 5] Process Fork
  -> SUCCESS: Fork completed, child PID: 1235

[STEP 6a] Parent Process Continuation
  -> Parent PID: 1234, Child PID: 1235
  -> Race window setup: Waiting 1 second before race activation

[STEP 7] Race Window Activation
  - Setting parent name to 'SLOWME' via prctl
  -> Note: This enables the kernel patch-assisted 5-second delay

[STEP 8] Parent Page 1 Unmapping (Outer Race)
  -> SUCCESS: Parent page 1 unmapped, triggers close handler
  -> Note: Name changed back to 'PARENT', kernel patch-assisted delay ends

[TEST COMPLETE]
  - If this was run with KASAN, you should see a KASAN: use-after-free BUG in kernel logs.
  - The bug occurs in kbasep_add_mm_counter() writing to freed mm_struct
  - Look for messages like: 'BUG: KASAN: use-after-free in kbasep_add_mm_counter'
```

#### Kernel Output (with KASAN)

Expected kernel log output when test is run in KASAN kernel:

```
dmesg output at test completion:
BUG: KASAN: use-after-free in kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]
    Write of size 8 at addr ffff0000c41f8f78 by task SLOWME/138

    CPU: 0 PID: 138 Comm: SLOWME Not tainted 5.10.155 #2
    Hardware name: linux,dummy-virt (DT)

    Call trace:
      dump_backtrace+0x0/0x298
      show_stack+0x18/0x24
      dump_stack+0xf4/0x160
      print_address_description.constprop.0+0x6c/0x484
      kasan_report+0x104/0x1f4
      check_memory_region+0xe8/0x1a0
      __kasan_check_write+0x3c/0x48
      kbasep_add_mm_counter.constprop.0+0x2c/0x6c [mali_kbase]     <-- WRITE
      kbase_special_vm_close+0xb4/0x120 [mali_kbase]               <-- .close callback
      remove_vma+0x4c/0xa0
      __do_munmap+0x298/0x680
      __vm_munmap+0xb4/0x124
      __arm64_sys_munmap+0x48/0x5c

    Allocated by task 138:
      kasan_save_stack+0x38/0x74
      __kasan_kmalloc.isra.0+0xcc/0xf8
      kasan_slab_alloc+0x18/0x24
      kmem_cache_alloc+0x1c4/0x2d8
      dup_mm+0x34/0x6a4                                            <-- child's mm_struct
      copy_process+0xd88/0x2240
      kernel_clone+0xb0/0x508

    Freed by task 142:
      kasan_save_stack+0x38/0x74
      kasan_set_track+0x28/0x40
      kasan_set_free_info+0x24/0x44
      __kasan_slab_free+0x10c/0x15c
      kasan_slab_free+0x14/0x20
      kmem_cache_free+0xb0/0x464
      __mmdrop+0x128/0x1d4                                        <-- mm_struct freed
      mmput+0x1a0/0x1d0
      do_exit+0x48c/0xe34

    The buggy address belongs to the object at ffff0000c41e1dc0
      which belongs to the cache mm_struct of size 944
    The buggy address is located 696 bytes inside of
      944-byte region [ffff0000c41e1dc0, ffff0000c41e2170)
```

### Test 2: Debugfs UAF PoC

#### Successful Execution (Expected)
```
=== Mali CSF r56p0 Debugfs kctx UAF Test PoC ===
User ID: 0, Effective UID: 0

[STEP 1] Device Discovery
  - Purpose: Locate Mali character device files (/dev/mali0, /dev/mali, etc.)
  -> SUCCESS: Mali device found at: /dev/mali0
  -> Device details:
     - File type: character device
     - Device number: 238:0
     - Permissions: 666

[STEP 2] Mali Device File Access
  - Command: open(/dev/mali0, O_RDWR)
  -> SUCCESS: Device file descriptor: 3

[STEP 3] MEM_PROFILE_ADD Ioctl (Debugfs Creation)
  - Command: ioctl(3, KBASE_IOCTL_MEM_PROFILE_ADD, &add_struct)
  -> SUCCESS: Ioctl returned 0
  -> Note: mem_profile debugfs node created with i_private == kctx

[STEP 4] Debugfs Directory Enumeration
  - Purpose: Locate the per-kctx debugfs directory
  -> SUCCESS: Found kctx debugfs directory: /sys/kernel/debug/mali0/ctx/1234
  -> Contents of /sys/kernel/debug/mali0/ctx/1234:
    - mem_profile (type: regular file)
    - mem_jit_count (type: regular file)
    - mem_jit_vm (type: regular file)
    - mem_jit_phys (type: regular file)
    - mem_jit_used (type: regular file)
    - mem_jit_trim (type: regular file)

[STEP 6] Debugfs File Access Setup
  -> Opening debugfs file...
  -> SUCCESS: Debugfs file opened, file descriptor: 4
  -> File descriptor details:
     - File size: 4096
     - Access mode: 644
     - Device number: 1:1

[STEP 7] Privilege Boundary Violation Setup
  - Critical action: Close() the /dev/mali0 file descriptor
  -> SUCCESS: Mali device closed, kctx cleanup initiated
  -> WARNING: Debugfs file descriptor 4 now holds dangling pointer!
  -> CRITICAL: This is the privilege boundary cross-over scenario!

[STEP 8] UAF Trigger - Reading from Dangling kctx Reference
  -> Attempting read from dangling file descriptor...
  -> SUCCESS: Read() returned 128 bytes
  -> Data read: 'MALI_UAF_DEBUG_PROFILE_DATA...'

[STEP 9] Cleanup
  -> SUCCESS: Debugfs file descriptor closed
```

#### Kernel Output (with KASAN)

Expected kernel log output for debugfs UAF:

```
dmesg output at test completion:
BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x? (kernel/...)
    Read of size 8 at addr ...
    by task poc/784:
      ...
    freed by task kbase_release+0x...:
      ...
```

## Test Analysis

### Test 1 Analysis: mm_struct UAF

**Vulnerability Details**:
- **Type**: Use-After-Free race condition
- **Target**: `struct mm_struct` in Mali Kbase driver
- **Root Cause**: Missing reference counting on `mm_struct` pointer
- **Exploitation**: Parent/child process race condition
- **Success Rate**: ~8% without KASAN, 100% with KASAN

**Key Test Components**:
1. Device initialization and ioctl communication
2. Shared memory mapping for race condition setup
3. Process forking to create competing mm_struct
4. Controlled timing for race window activation
5. Kernel-level memory corruption verification

**Test Validation**:
- Verify KASAN reports in kernel logs
- Confirm race condition timing behavior
- Check for kernel crashes or oopses
- Validate privilege escalation potential

### Test 2 Analysis: Debugfs UAF

**Vulnerability Details**:
- **Type**: Deterministic Use-After-Free
- **Target**: `struct kbase_context` via debugfs i_private
- **Root Cause**: `debugfs_remove_recursive()` doesn't invalidate open file handles
- **Exploitation**: Privilege boundary crossing (unprivileged closer → privileged reader)
- **Success Rate**: 100% deterministic

**Key Test Components**:
1. Debugfs file discovery and enumeration
2. Privilege boundary setup (unprivileged user → privileged reader)
3. Attacker-shaped payload preparation
4. Deterministic UAF trigger
5. Cross-privilege exploitation verification

**Test Validation**:
- Verify KASAN reports for debugfs UAFs
- Confirm privilege boundary crossing
- Check for kernel read primitives
- Validate debugfs file access patterns

## Test Integration

### Combined Testing Strategy

For comprehensive vulnerability analysis:

1. **Test 1 First**: Run mm_struct UAF PoC to establish baseline
2. **Test 2 Second**: Run debugfs UAF PoC for deterministic results
3. **Comparative Analysis**: Compare results and exploitability
4. **Primitive Classification**: Categorize resulting primitives
5. **Impact Assessment**: Evaluate privilege escalation potential

### Test Environment Setup Script

```bash
#!/bin/bash
# test_environment_setup.sh - Comprehensive test environment setup

set -euo pipefail

REPO_ROOT="/home/za0x/Desktop/github/r560"
POC_DIR="$REPO_ROOT/poc"
QEMU_TEST_DIR="$POC_DIR/qemu-test"

echo "=== Mali Driver Vulnerability Test Environment Setup ==="
echo "Repository: $REPO_ROOT"
echo "Current directory: $(pwd)"

echo "\n=== Step 1: Checking Prerequisites ==="
# Check for required tools
command -v gcc >/dev/null 2>&1 || { echo "ERROR: gcc not found"; exit 1; }
command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || echo "WARNING: aarch64-linux-gnu-gcc not found (cross-compilation)"
command -v qemu-system-aarch64 >/dev/null 2>&1 || echo "WARNING: qemu-system-aarch64 not found (QEMU testing)"

echo "=== Step 2: Compiling Test PoCs ==="
cd "$POC_DIR"
gcc -O2 -o test_poc test_poc.c -std=c11 -Wall -Wextra
gcc -O2 -o test_debugfs_poc test_debugfs_poc.c -std=c11 -Wall -Wextra

echo "=== Step 3: Environment Check ==="
ls -la *.c *.h 2>/dev/null | head -20

if [ -d "$QEMU_TEST_DIR" ]; then
    echo "\nQEMU test environment found at: $QEMU_TEST_DIR"
    echo "Run QEMU tests using: cd $QEMU_TEST_DIR && ./05_run_qemu.sh"
else
    echo "\nQEMU test environment not found at: $QEMU_TEST_DIR"
    echo "Full testing requires QEMU environment setup"
fi

echo "\n=== Test Environment Setup Complete ==="
echo "Available test binaries:"
echo "  - $POC_DIR/test_poc (mm_struct UAF PoC)"
echo "  - $POC_DIR/test_debugfs_poc (debugfs UAF PoC)"
echo "\nRun tests with:"
echo "  - ./test_poc          (mm_struct UAF)"
echo "  - sudo ./test_debugfs_poc (debugfs UAF)"
```

## Test Results Reporting

### Output Capture

For comprehensive test results:

```bash
# Capture test output with timestamps
cd "$POC_DIR"

# Test 1 with detailed output
./test_poc > test1_output_$(date +%Y%m%d_%H%M%S).log 2>&1

# Test 2 with elevated privileges
if command -v sudo >/dev/null; then
    sudo ./test_debugfs_poc > test2_output_$(date +%Y%m%d_%H%M%S).log 2>&1
fi

# Upload or analyze results as needed
```

### Result Classification

| Result Type | Description | Test 1 | Test 2 |
|-------------|-------------|--------|--------|
| **SUCCESS** | KASAN UAF detected | ✓ | ✓ |
| **CLEAN** | No UAF, but test completed | - | - |
| **INCONCLUSIVE** | Other failure mode | - | - |
| **ERROR** | Test setup/execution failure | - | - |

## Conclusion

This test environment provides comprehensive tools for analyzing and validating the two primary Mali driver vulnerability classes discovered in the repository:

1. **mm_struct Use-After-Free** (race condition, privilege escalation)
2. **debugfs kctx Use-After-Free** (deterministic, privilege boundary crossing)

The enhanced PoCs provide detailed debug output and analysis capabilities while maintaining the deterministic nature of the original vulnerabilities. The test environment supports both local user-space testing and full QEMU integration for comprehensive vulnerability validation.