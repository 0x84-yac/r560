/*
 * mali_handshake.h - correct Kbase API handshake for all supported flavors
 *
 * The Kbase UAPI has two VERSION_CHECK ioctl numbers:
 *
 *   cmd 0  (KBASE_IOCTL_VERSION_CHECK_RESERVED, legacy Job Manager)
 *          accepted by the r42p0 valhall/bifrost drivers.
 *
 *   cmd 52 (KBASE_IOCTL_VERSION_CHECK, CSF)
 *          accepted by the r56p0 gen5 (CSF-only) driver.
 *
 * On gen5, cmd 0 is handled by kbase_api_handshake_dummy() which returns
 * -EPERM on purpose.  Because that is the *reserved* command, it does not
 * touch the per-file setup state, so a cmd 52 retry on the same fd works.
 *
 * A successful VERSION_CHECK only records the API version.  The context (and
 * therefore the per-kctx debugfs directory and every non-handshake ioctl,
 * including MEM_PROFILE_ADD) is created by SET_FLAGS.  Both calls are needed
 * before any context ioctl; otherwise the driver returns -EPERM and no
 * /sys/kernel/debug/mali0/ctx/<tgid>_<id> directory appears.
 *
 * Include with a relative path, e.g.:
 *   C files in poc/    -> #include "../tools/mali_handshake.h"
 *   C files in tools/  -> #include "mali_handshake.h"
 */
#ifndef MALI_KBASE_HANDSHAKE_H
#define MALI_KBASE_HANDSHAKE_H

#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MALI_KBASE_IOCTL_TYPE 0x80

struct mali_kbase_ioctl_version_check {
	uint16_t major;
	uint16_t minor;
};

struct mali_kbase_ioctl_set_flags {
	uint32_t create_flags;
};

#define MALI_KBASE_IOCTL_VERSION_CHECK_LEGACY \
	_IOWR(MALI_KBASE_IOCTL_TYPE, 0, struct mali_kbase_ioctl_version_check)
#define MALI_KBASE_IOCTL_VERSION_CHECK_CSF \
	_IOWR(MALI_KBASE_IOCTL_TYPE, 52, struct mali_kbase_ioctl_version_check)
#define MALI_KBASE_IOCTL_SET_FLAGS \
	_IOW(MALI_KBASE_IOCTL_TYPE, 1, struct mali_kbase_ioctl_set_flags)

/*
 * mali_kbase_version_check - issue VERSION_CHECK for either driver family
 *
 * @fd:    open /dev/maliN file descriptor
 * @major: optional output, negotiated major version (may be NULL)
 * @minor: optional output, negotiated minor version (may be NULL)
 *
 * Tries the legacy cmd 0 first (valhall/bifrost r42p0), and retries with the
 * CSF cmd 52 when the legacy command is not implemented (ENOTTY) or is the
 * deliberately disabled reserved command (EPERM, gen5 r56p0).
 *
 * Return: 0 on success, -1 with errno set on failure.
 */
static inline int mali_kbase_version_check(int fd, uint16_t *major, uint16_t *minor)
{
	struct mali_kbase_ioctl_version_check v = { 0, 0 };
	int rc;

	rc = ioctl(fd, MALI_KBASE_IOCTL_VERSION_CHECK_LEGACY, &v);
	if (rc < 0 && (errno == EPERM || errno == ENOTTY)) {
		v.major = 0;
		v.minor = 0;
		rc = ioctl(fd, MALI_KBASE_IOCTL_VERSION_CHECK_CSF, &v);
	}
	if (rc == 0) {
		if (major)
			*major = v.major;
		if (minor)
			*minor = v.minor;
	}

	return rc;
}

/*
 * mali_kbase_set_flags - create the Kbase context for an open device file
 *
 * @fd:           open /dev/maliN file descriptor
 * @create_flags: base_context_create_flags (0 is valid)
 *
 * Return: 0 on success, -1 with errno set on failure.
 */
static inline int mali_kbase_set_flags(int fd, uint32_t create_flags)
{
	struct mali_kbase_ioctl_set_flags f = { create_flags };

	return ioctl(fd, MALI_KBASE_IOCTL_SET_FLAGS, &f);
}

/*
 * mali_kbase_setup - complete the Kbase setup on a freshly opened device file
 *
 * Runs VERSION_CHECK (legacy, then CSF if needed) followed by SET_FLAGS.
 * After this returns 0, the Kbase context exists, context ioctls are accepted
 * and /sys/kernel/debug/<dev>/ctx/<tgid>_<id>/ is populated.
 *
 * Return: 0 on success, -1 with errno set on failure.
 */
static inline int mali_kbase_setup(int fd)
{
	if (mali_kbase_version_check(fd, NULL, NULL) < 0)
		return -1;

	return mali_kbase_set_flags(fd, 0);
}

#endif /* MALI_KBASE_HANDSHAKE_H */
