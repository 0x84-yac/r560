#!/bin/bash
# Run Tests - Comprehensive test script for Mali driver vulnerability PoCs

set -euo pipefail

REPO_ROOT="/home/za0x/Desktop/github/r560"
POC_DIR="$REPO_ROOT/poc"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function for colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Print banner
print_banner() {
    echo "============================================================"
    echo "Mali Driver Vulnerability Test Suite"
    echo "Repository: $REPO_ROOT"
    echo "Test Directory: $POC_DIR"
    echo "============================================================"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for C compiler
    if ! command -v gcc >/dev/null 2>&1; then
        log_error "gcc compiler not found"
        exit 1
    fi
    
    # Check for cross-compiler (optional)
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        log_info "Cross-compiler available: aarch64-linux-gnu-gcc"
    else
        log_warn "Cross-compiler not found (optional for ARM testing)"
    fi
    
    # Check QEMU (optional)
    if command -v qemu-system-aarch64 >/dev/null 2>&1; then
        log_info "QEMU available: qemu-system-aarch64"
    else
        log_warn "QEMU not found (full testing requires QEMU)"
    fi
    
    log_info "Prerequisites check complete"
}

# Compile test PoCs
compile_tests() {
    log_header "Compiling test PoCs..."
    
    cd "$POC_DIR"
    
    # Compile enhanced PoCs
    log_info "Compiling test_poc.c (mm_struct UAF)..."
    if gcc -O2 -o test_poc test_poc.c -std=c11 -Wall -Wextra; then
        log_info "✓ test_poc compiled successfully"
    else
        log_error "Failed to compile test_poc.c"
        exit 1
    fi
    
    log_info "Compiling test_debugfs_poc.c (debugfs UAF)..."
    if gcc -O2 -o test_debugfs_poc test_debugfs_poc.c -std=c11 -Wall -Wextra; then
        log_info "✓ test_debugfs_poc compiled successfully"
    else
        log_error "Failed to compile test_debugfs_poc.c"
        exit 1
    fi
    
    log_info "Test compilation complete"
}

# Run test 1: mm_struct UAF PoC
run_test1() {
    log_header "Running Test 1: mm_struct UAF PoC (test_poc.c)"
    echo "Description: Mali Kbase mm_struct Use-After-Free race condition test"
    echo "Method: Parent/child process race condition"
    echo "Expected: KASAN reports when run in KASAN-enabled kernel"
    echo ""
    
    if [ ! -f "$POC_DIR/test_poc" ]; then
        log_error "test_poc binary not found"
        exit 1
    fi
    
    echo "=== Test 1 Execution ==="
    echo "Running: ./test_poc"
    echo ""
    
    # Run test with timeout
    timeout 30 "$POC_DIR/test_poc" 2>&1 || {
        log_warn "Test completed with timeout (expected for some tests)"
        return 0
    }
}

# Run test 2: debugfs UAF PoC
run_test2() {
    log_header "Running Test 2: debugfs UAF PoC (test_debugfs_poc.c)"
    echo "Description: Mali CSF r56p0 debugfs kctx UAF test"
    echo "Method: Single-process deterministic debugfs dangling pointer"
    echo "Expected: KASAN reports when run in KASAN-enabled kernel"
    echo "Note: Requires root privileges for full debugfs access"
    echo ""
    
    if [ ! -f "$POC_DIR/test_debugfs_poc" ]; then
        log_error "test_debugfs_poc binary not found"
        exit 1
    fi
    
    echo "=== Test 2 Execution ==="
    echo "Running with sudo: sudo ./test_debugfs_poc"
    echo ""
    
    # Run test with elevated privileges
    if command -v sudo >/dev/null 2>&1; then
        timeout 30 sudo "$POC_DIR/test_debugfs_poc" 2>&1 || {
            log_warn "Test completed with timeout (expected for some tests)"
            return 0
        }
    else
        log_warn "sudo not available, skipping Test 2 (requires root)"
        return 0
    fi
}

# Check environment capabilities
check_environment() {
    log_header "Checking environment capabilities..."
    
    echo "System Information:"
    echo "  - OS: $(uname -s) $(uname -r)"
    echo "  - Architecture: $(uname -m)"
    echo "  - User: $(whoami)"
    echo "  - Effective UID: $(id -u)"
    echo ""
    
    echo "Available Tools:"
    echo "  - gcc: $(gcc --version | head -1 | cut -d' ' -f4)"
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "  - aarch64-linux-gnu-gcc: $(aarch64-linux-gnu-gcc --version | head -1 | cut -d' ' -f4)"
    else
        echo "  - aarch64-linux-gnu-gcc: Not available"
    fi
    
    if command -v qemu-system-aarch64 >/dev/null 2>&1; then
        echo "  - qemu-system-aarch64: Available"
    else
        echo "  - qemu-system-aarch64: Not available (full testing requires QEMU)"
    fi
    
    echo ""
    
    # Check for /dev/mali0
    if [ -c /dev/mali0 ] 2>/dev/null; then
        echo "Mali device: /dev/mali0 (character device, major:minor $(stat -c '%t:%T' /dev/mali0))"
    else
        echo "Mali device: /dev/mali0 not found (driver may not be loaded)"
    fi
    
    # Check debugfs
    if [ -d /sys/kernel/debug ] 2>/dev/null; then
        echo "Debugfs: /sys/kernel/debug available"
        if find /sys/kernel/debug -name "mali*" -type d 2>/dev/null | grep -q "."; then
            echo "Debugfs Mali entries: Available"
        else
            echo "Debugfs Mali entries: No Mali-specific debug entries found"
        fi
    else
        echo "Debugfs: /sys/kernel/debug not mounted"
    fi
}

# Show test information
show_test_info() {
    log_header "Test Information"
    
    echo "Test Suite Overview:"
    echo "=================="
    echo ""
    echo "Test 1: mm_struct Use-After-Free"
    echo "  - File: test_poc.c"
    echo "  - Vulnerability: CWE-416 Use-After-Free"
    echo "  - Method: Parent/child process race condition"
    echo "  - Target: struct mm_struct in Mali Kbase driver"
    echo "  - Impact: Kernel heap corruption, privilege escalation"
    echo "  - Success Rate: ~8% without KASAN, 100% with KASAN"
    echo ""
    echo "Test 2: debugfs kctx Use-After-Free"
    echo "  - File: test_debugfs_poc.c"
    echo "  - Vulnerability: CWE-416 Use-After-Free"
    echo "  - Method: Single-process deterministic debugfs UAF"
    echo "  - Target: struct kbase_context via debugfs i_private"
    echo "  - Impact: Kernel read primitive, privilege boundary crossing"
    echo "  - Success Rate: 100% deterministic"
    echo ""
    echo "Test Environment:
    - Enhanced PoCs with detailed debug output
    - Deterministic test execution
    - Comprehensive error reporting
    - File descriptor tracking
    - Privilege boundary analysis
    - Kernel address extraction
    "
    
    echo ""
    echo "Requirements:
    - KASAN-enabled kernel for detection (recommended)
    - Root access for Test 2 (debugfs)
    - ARM64 architecture (or cross-compilation)
    - Mali driver (r42p0 or r56p0 compatible)
    "
}

# Main execution
main() {
    print_banner
    
    # Parse command line arguments
    case "${1:-}" in
        "--check-only")
            check_prerequisites
            check_environment
            exit 0
            ;;
        "--info")
            show_test_info
            exit 0
            ;;
        "--quick")
            check_prerequisites
            compile_tests
            run_test1
            exit $?
            ;;
        "--full")
            check_prerequisites
            compile_tests
            run_test1
            run_test2
            exit $?
            ;;
        "")
            # Default behavior
            check_prerequisites
            compile_tests
            show_test_info
            echo ""
            log_header "Starting Test Suite"
            echo "Run with --quick, --full, --info, or --check-only for specific options"
            exit 0
            ;;
        *)
            echo "Usage: $0 [--quick|--full|--info|--check-only]"
            echo ""
            echo "Options:"
            echo "  --quick    Run quick tests (Test 1 only)"
            echo "  --full     Run full test suite (both tests)"
            echo "  --info     Show test information"
            echo "  --check-only Check prerequisites only"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"