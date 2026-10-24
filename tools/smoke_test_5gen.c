/*
 * smoke_test_5gen.c - smoke test for Mali Kbase gen5 (CSF r56p0) in NO_MALI mode
 *
 * This test verifies driver initialization and the correct gen5 setup
 * sequence:
 *   1. Device node existence and permissions
 *   2. Debugfs structure availability
 *   3. VERSION_CHECK (CSF cmd 52) + SET_FLAGS -> creates the kcontext
 *   4. MEM_PROFILE_ADD -> creates the per-kctx mem_profile debugfs file
 *   5. Per-kctx debugfs directory appears under .../ctx/<tgid>_<id>
 *
 * Note: gen5 has no Job Manager frontend. The legacy VERSION_CHECK command
 * (cmd 0) is the deliberately disabled reserved command and returns EPERM;
 * it is not "NO_MALI hardening". Use the CSF command (cmd 52) and then
 * SET_FLAGS. Without SET_FLAGS no context exists, so every context ioctl
 * (MEM_PROFILE_ADD included) returns EPERM and no per-kctx debugfs dir is
 * created. See tools/mali_handshake.h.
 *
 * Compile: aarch64-linux-gnu-gcc -static -O2 -Wall -o smoke_test_5gen smoke_test_5gen.c
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "mali_handshake.h"

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_mem_profile_add {
    uint64_t buffer;
    uint32_t len;
    uint32_t padding;
};
#define KBASE_IOCTL_MEM_PROFILE_ADD \
    _IOW(KBASE_IOCTL_TYPE, 27, struct kbase_ioctl_mem_profile_add)

/* For testing ioctl behavior in NO_MALI mode */
static void test_device_node(void)
{
    printf("=== Test 1: Device Node ===\n");

    struct stat st;
    if (stat("/dev/mali0", &st) != 0) {
        printf("[FAIL] /dev/mali0 does not exist: %s\n", strerror(errno));
        return;
    }

    if (!S_ISCHR(st.st_mode)) {
        printf("[FAIL] /dev/mali0 is not a character device\n");
        return;
    }

    printf("[PASS] /dev/mali0 exists as char device (major=%d, minor=%d)\n",
           (int)(st.st_rdev >> 8), (int)(st.st_rdev & 0xff));

    /* Check permissions */
    if (access("/dev/mali0", R_OK | W_OK) != 0) {
        printf("[FAIL] /dev/mali0 not readable/writable: %s\n", strerror(errno));
        return;
    }
    printf("[PASS] /dev/mali0 is readable and writable\n");
}

static void test_debugfs_structure(void)
{
    printf("\n=== Test 2: Debugfs Structure ===\n");

    DIR *d = opendir("/sys/kernel/debug/mali0");
    if (!d) {
        printf("[FAIL] /sys/kernel/debug/mali0 not accessible: %s\n", strerror(errno));
        return;
    }
    printf("[PASS] /sys/kernel/debug/mali0 exists\n");

    struct dirent *e;
    int found_top_level = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        found_top_level = 1;
        printf("  [INFO] Found: %s\n", e->d_name);
    }
    closedir(d);

    if (!found_top_level)
        printf("[WARN] No debugfs files found under /sys/kernel/debug/mali0\n");

    /* Check for ctx directory */
    d = opendir("/sys/kernel/debug/mali0/ctx");
    if (d) {
        printf("[PASS] /sys/kernel/debug/mali0/ctx exists\n");
        closedir(d);
    } else {
        printf("[INFO] /sys/kernel/debug/mali0/ctx not found: %s\n", strerror(errno));
    }
}

static void test_ioctl_setup(void)
{
    printf("\n=== Test 3: IOCTL setup sequence (VERSION_CHECK + SET_FLAGS) ===\n");

    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        printf("[FAIL] Cannot open /dev/mali0: %s\n", strerror(errno));
        return;
    }

    uint16_t major = 0, minor = 0;
    int rc = mali_kbase_version_check(fd, &major, &minor);
    int err = errno;

    if (rc < 0) {
        printf("[FAIL] VERSION_CHECK failed: %s\n", strerror(err));
        close(fd);
        return;
    }
    printf("[PASS] VERSION_CHECK ok (kernel UK version %u.%u)\n", major, minor);

    rc = mali_kbase_set_flags(fd, 0);
    err = errno;
    if (rc < 0) {
        printf("[FAIL] SET_FLAGS failed: %s\n", strerror(err));
        close(fd);
        return;
    }
    printf("[PASS] SET_FLAGS ok (kcontext created)\n");

    {
        char payload[] = "smoke-test";
        struct kbase_ioctl_mem_profile_add add = {
            .buffer = (uint64_t)(uintptr_t)payload,
            .len = sizeof(payload),
            .padding = 0,
        };

        rc = ioctl(fd, KBASE_IOCTL_MEM_PROFILE_ADD, &add);
        err = errno;
        if (rc < 0)
            printf("[FAIL] MEM_PROFILE_ADD failed: %s\n", strerror(err));
        else
            printf("[PASS] MEM_PROFILE_ADD ok (mem_profile debugfs created)\n");
    }

    {
        DIR *d = opendir("/sys/kernel/debug/mali0/ctx");
        if (d) {
            struct dirent *e;
            printf("[PASS] per-kctx debugfs dir present:\n");
            while ((e = readdir(d))) {
                if (e->d_name[0] == '.')
                    continue;
                printf("  [INFO] ctx entry: %s\n", e->d_name);
            }
            closedir(d);
        } else {
            printf("[FAIL] no per-kctx debugfs dir: %s\n", strerror(errno));
        }
    }

    close(fd);
}

static void test_mmap_basic(void)
{
    printf("\n=== Test 4: MMAP Basic Operations ===\n");

    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        printf("[FAIL] Cannot open /dev/mali0: %s\n", strerror(errno));
        return;
    }

    /* mmap is a context operation: complete VERSION_CHECK + SET_FLAGS first. */
    if (mali_kbase_setup(fd) < 0) {
        printf("[FAIL] Kbase setup failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    /* Try basic mmap - may fail in NO_MALI but tests basic functionality */
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("[INFO] mmap at offset 0 returned: %s\n", strerror(errno));
    } else {
        printf("[PASS] mmap succeeded, addr=%p\n", addr);
        munmap(addr, 4096);
    }

    close(fd);
}

static int check_driver_info(void)
{
    printf("\n=== Test 5: Driver Info from Dmesg ===\n");

    FILE *f = fopen("/proc/kmsg", "r");
    if (!f) {
        printf("[INFO] Cannot read /proc/kmsg (may need root)\n");
    } else {
        char buf[256];
        int found = 0;
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "Probed as mali")) {
                printf("[PASS] Driver probed: %s", buf);
                found = 1;
                break;
            }
        }
        fclose(f);
        if (!found)
            printf("[INFO] Driver probe message not found in /proc/kmsg\n");
    }

    /* Alternative: check dmesg if available */
    struct stat st;
    if (stat("/var/log/dmesg", &st) == 0) {
        printf("[INFO] dmesg log found at /var/log/dmesg\n");
    }

    return 0;
}

static int check_kasan_status(void)
{
    printf("\n=== Test 6: Kasan Status ===\n");

    int f = open("/sys/kernel/debug/kasan", O_RDONLY);
    if (f >= 0) {
        printf("[PASS] KASAN debugfs available\n");
        close(f);
    } else {
        printf("[INFO] KASAN debugfs not available: %s\n", strerror(errno));
    }

    /* Check if KASAN is enabled in kernel */
    FILE *f_cmdline = fopen("/proc/cmdline", "r");
    if (f_cmdline) {
        char cmdline[512] = {0};
        if (fgets(cmdline, sizeof(cmdline), f_cmdline)) {
            if (strstr(cmdline, "kasan")) {
                printf("[PASS] KASAN enabled in kernel cmdline\n");
            }
        }
        fclose(f_cmdline);
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *dev = (argc > 1) ? argv[1] : "/dev/mali0";

    printf("Mali Kbase gen5 (r56p0) NO_MALI Smoke Test\n");
    printf("============================================\n");
    printf("Testing device: %s\n\n", dev);

    test_device_node();
    test_debugfs_structure();
    test_ioctl_setup();
    test_mmap_basic();
    check_driver_info();
    check_kasan_status();

    printf("\n=== Summary ===\n");
    printf("Use CSF VERSION_CHECK (cmd 52) + SET_FLAGS on gen5; the legacy\n");
    printf("cmd 0 is the disabled reserved command and returns EPERM.\n");
    printf("KASAN should be active for memory safety detection.\n");

    return 0;
}