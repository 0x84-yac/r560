# Mali Driver Vulnerability Testing - Quick Start Guide

## Overview

This repository contains comprehensive test cases for ARM Mali GPU kernel driver vulnerabilities. Two primary test cases demonstrate different classes of memory management bugs:

1. **mm_struct Use-After-Free** - Race condition between parent/child processes
2. **debugfs kctx Use-After-Free** - Deterministic debugfs dangling pointer bug

## Test Files Summary

### Core Test PoCs
- **`poc.c`** - Midgard Mali Kbase mm_struct UAF (race condition)
- **`poc_debugfs_kctx_uaf.c`** - CSF r56p0 debugfs kctx UAF (deterministic)

### Analysis Documentation
- **`FINDINGS.md`** - First vulnerability discovery and analysis
- **`poc/mali-r56p0-uaf-report.md`** - Second vulnerability report (4 findings)
- **`poc/deep_seek_report.md`** - Deep analysis of memory management
- **`poc/memory_primitives_catalog.md`** - Complete memory management primitives catalog

### Testing Infrastructure
- **`poc/qemu-test/`** - Full QEMU test environment for comprehensive testing
- **`build.sh`** - Driver build system
- **`run_arm64.sh`** - QEMU launcher

## Quick Testing Approach

### 1. Environment Check

```bash
cd /home/za0x/Desktop/github/r560/poc

# Check what we have
ls -la

# Examine the test PoCs
head -100 poc.c                    # Test 1: mm_struct UAF
cat poc_debugfs_kctx_uaf.c         # Test 2: debugfs UAF

# Check build system
cat ../build.sh | head -50          # Build scripts
```

### 2. Test Environment Status

```bash
# Check test environment
cat poc/TESTING_GUIDE.md | head -50  # Testing guide

# Look at analysis documentation
cat poc/mali-r56p0-uaf-report.md | head -100  # Main vulnerability report
```

### 3. QEMU Testing Environment (Recommended)

For comprehensive vulnerability testing with proper kernel validation:

```bash
cd /home/za0x/Desktop/github/r560/poc/qemu-test

# Follow the quick pipeline:
export ARCH=aarch64
./01_fetch_kernel.sh 6.6.0     # Fetch kernel
./02_build_kernel.sh           # Build kernel with KASAN
./03_build_driver.sh           # Build Mali driver  
./04_build_poc.sh              # Build test PoCs
./05_run_qemu.sh               # Run comprehensive test
./detect_kasan.sh logs/full-*.log  # Analyze results
```

## Test Execution Options

### Option A: Quick Test Check

```bash
# Just check what we have and environment
cat poc/README_TESTING.md | head -30

# Examine test PoCs (read-only)
cat poc.c | head -80
cat poc_debugfs_kctx_uaf.c | head -80
```

### Option B: Comprehensive Testing

```bash
# Use the full test environment
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

## Test Analysis

### Expected Results

**Test 1: mm_struct UAF (`poc.c`)**
- **Type**: Race condition Use-After-Free
- **Trigger Rate**: ~8% without KASAN, 100% with KASAN
- **Output**: KASAN: `use-after-free in kbasep_add_mm_counter`
- **Key Field**: `mm->rss_stat.count[MM_FILEPAGES]` at offset 0x192

**Test 2: debugfs UAF (`poc_debugfs_kctx_uaf.c`)**
- **Type**: Deterministic Use-After-Free
- **Trigger Rate**: 100% deterministic
- **Output**: KASAN: `use-after-free in kbasep_mem_profile_seq_show`
- **Key Impact**: Privilege boundary crossing

### Test Validation Commands

```bash
# In the QEMU guest:
cd /host/mali
./poc                    # Run mm_struct UAF test
dmesg | grep -A 30 'KASAN: use-after-free'

# The debugfs UAF runs automatically in QEMU test environment
# Results in logs/ directory
```

## Test Resources

### Analysis Documentation
```bash
# Key analysis files:
cat poc/FINDINGS.md               # First vulnerability analysis
cat poc/mali-r56p0-uaf-report.md   # Second vulnerability analysis  
cat poc/memory_primitives_catalog.md  # Memory management primitives
```

### Testing Guide
```bash
# Complete testing guide:
cat poc/TESTING_GUIDE.md | head -100
```

### Build System
```bash
# Build system details:
cat ../build.sh | head -100
cat ../run_arm64.sh               # QEMU launcher
```

## Test Summary

### Vulnerability Types Tested

| Test | Vulnerability | Method | Success Rate | Complexity |
|------|---------------|--------|--------------|------------|
| 1 | mm_struct UAF | Parent/child race | ~8% (KASAN: 100%) | Medium |
| 2 | debugfs UAF | Single-process deterministic | 100% | Low |

### Testing Requirements

| Requirement | Test 1 | Test 2 | Notes |
|-------------|--------|--------|-------|
| KASAN-enabled kernel | ✓ | ✓ | Required for detection |
| ARM64 architecture | ✓ | ✓ | Target architecture |
| Root access | - | ✓ | For debugfs access |
| QEMU environment | ✓ | ✓ | Recommended for full testing |

## Recommended Testing Strategy

### Step 1: Environment Setup
1. Set up QEMU test environment (recommended)
2. Build kernel with KASAN enabled
3. Build Mali driver
4. Build test PoCs

### Step 2: Test Execution
1. Run QEMU test environment
2. Both PoCs run automatically
3. Capture and analyze KASAN reports

### Step 3: Result Analysis
1. Use `detect_kasan.sh` script for classification
2. Examine kernel logs for UAF details
3. Validate vulnerability impact
4. Document findings

## Conclusion

This repository provides comprehensive test cases for two distinct classes of ARM Mali driver vulnerabilities. The QEMU test environment offers the most reliable testing methodology for validating these vulnerabilities in a controlled environment.

For vulnerability research, this represents a solid foundation with:
- Well-documented vulnerabilities
- Reproducible test cases
- Comprehensive analysis
- Established testing infrastructure

The test suite validates both race condition and deterministic UAF vulnerabilities, demonstrating different exploitation techniques and privilege escalation potential.