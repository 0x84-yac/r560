/*
 * drop_priv - drop to an unprivileged uid/gid and exec a command.
 *
 * Used in the Mali bug-bounty virtual platform guest to run privilege-
 * escalation PoCs as a non-root user while the surrounding harness
 * (init, log triage, GDB) runs as root.
 *
 * usage: drop_priv [--uid UID] [--gid GID] COMMAND [ARG...]
 *        drop_priv COMMAND [ARG...]     (defaults: uid=gid=1000, 'poc')
 *
 * exit codes: 1 usage / privilege-drop failure, errno.code on exec failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef DEFAULT_UID
#define DEFAULT_UID 1000
#endif
#ifndef DEFAULT_GID
#define DEFAULT_GID 1000
#endif

static void
die(const char *msg)
{
	fprintf(stderr, "drop_priv: %s: %s\n", msg, strerror(errno));
	_exit(1);
}

int
main(int argc, char **argv)
{
	unsigned long uid = DEFAULT_UID;
	unsigned long gid = DEFAULT_GID;
	int i = 1;

	while (i < argc &&
	       (strcmp(argv[i], "--uid") == 0 || strcmp(argv[i], "--gid") == 0)) {
		if (i + 1 >= argc) {
			fprintf(stderr,
			        "usage: drop_priv [--uid UID] [--gid GID] CMD...\n");
			return 1;
		}
		if (strcmp(argv[i], "--uid") == 0)
			uid = strtoul(argv[i + 1], NULL, 0);
		else
			gid = strtoul(argv[i + 1], NULL, 0);
		i += 2;
	}

	if (i >= argc) {
		fprintf(stderr, "usage: drop_priv [--uid UID] [--gid GID] CMD...\n");
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "drop_priv: must be run as root\n");
		return 1;
	}

	umask(0022);
	if (setgroups(0, NULL) != 0 && errno != EPERM)
		/* continue if not supported, we'll try to drop uid/gid */
		(void)0;
	if (setgid((gid_t)gid) != 0)
		die("setgid");
	if (setuid((uid_t)uid) != 0)
		die("setuid");

	if (getuid() == 0 || geteuid() == 0)
		die("still root after setuid");

	execvp(argv[i], &argv[i]);
	die(argv[i]);
	return 0;
}
