# Mali r56p0 — QEMU UAF test environment (KASAN-capable, full logging)

Reproducible environment that:

1. Patches the ARM Mali DDK under test with verbose debug/assert configs,
2. Builds the kernel (with KASAN) and the Mali driver (no-mali fake platform,
   so no hardware is needed),
3. Builds a minimal rootfs/initramfs inside which the DDK module is loaded,
4. Runs under QEMU (`qemu-system-aarch64` by default; `qemu-system-x86_64`
   supported too) and **attaches the PoC** as a root-init exec,
5. Captures:

   - the **full serial console log** (`logs/full-<ts>.log`),
   - the **kernel log** (`logs/dmesg-<ts>.log` booted under `dmesg -n 8`),
   - a **KASAN crash-only PoC** with verbose debug output
     (`poc_debugfs_kctx_uaf_debug.c` compiled inside the env),
   - a **side cut of the module debug output** (module load/unload traces).

The production target (SYR): `/home/za0x/Desktop/target/AX504X08X-SW-99002-r56p0-18eac0 (2)/`.

---

## Layout

```
qemu-test/
├── README.md           ← this file
├── 01_fetch_kernel.sh  shallow-clones linux (default v6.6.0) into ./linux
├── 02_build_kernel.sh  applies kernel-fragment.config (KASAN, debugfs, KALLS), builds bzImage/Image
├── 03_build_driver.sh  builds the Mali DDK as an out-of-tree module (no-mali fake platform + verbose debug)
├── 04_build_poc.sh     compiles the debug PoC (native or aarch64)
├── 05_run_qemu.sh      builds initramfs (busybox) and runs QEMU with the PoC attached; collects full logs
├── detect_kasan.sh     greps captured logs for UAF signature (KASAN slab-use-after-free)
├── initramfs/
├──   └── run.sh        insmod mali.ko → mount debugfs → run PoC → dump `dmesg`, `journalctl`-less captured logs
├── poc_debugfs_kctx_uaf_debug.c     verbose debug variant of the deterministic PoC
├── kernel-config.fragment  Kconfig fragment merged by 02 into defconfig
└── logs/               captured outputs (gitignored)
```

---

## 1. Install host dependencies

```bash
# Ubuntu 22.04/24.04: these are typically already present if you have gcc + qemu arm.
sudo apt update
sudo apt install -y \
    bc bison build-essential flex git libelf-dev libssl-dev ncurses-dev \
    gdb-multiarch gdb qemu qemu-system-arm qemu-user-static binfmt-support \
    lz4 binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu busybox cpio
```

## 2. Fetch the Linux tree

```bash
export ARCH=aarch64                # or x86_64
./01_fetch_kernel.sh               # clones ./linux at default v6.6.0 (shallow)
```

Runs ~3-10 min depending on the link. If you already have a kernel tree, skip the fetch by setting `KERNEL_SRC=/path/to/linux`.

## 3. Build the kernel

```bash
./02_build_kernel.sh
# → builds ./linux/arch/aarch64/boot/Image and module cribs
```

`kernel-config.fragment` includes everything needed to make the PoC exercise UAF:
- `CONFIG_DEBUG_FS`, `CONFIG_KASAN` (y), `CONFIG_KALLSYMS=y`
- `CONFIG_MODULES=y`, `CONFIG_UNWINDER_FRAME_POINTER`
- Verbose `-Wno-error` and `CONFIG_KASAN_KUNIT_TEST`
- `CONFIG_MALI_NONE` so no in-tree Mali driver runs (our out-of-tree DDK module owns `/dev/mali0`)

Notably **KASAN config** (`CONFIG_KASAN`) kernels are what ARM's own CI uses for the same driver — the target for disclosure artifacts is an instrumented kernel.

Build cost is ~15-40 min on an 8-16 CPU host (KASAN + modules roughly doubles the vanilla build).

## 4. Build the Mali driver (DDK, out-of-tree)

```bash
DDK=/path/to/mali-ddk
export KERNEL_SRC=$(pwd)/linux   # or set it explicitly wherever else
./03_build_driver.sh $DDK
# builds → $DDK/build/mali.ko with a fake platform ("mali") so it attaches on a QEMU virt machine
```

Can also be used inside the VM without host path: `03_build_driver.sh` does support cross-build; for in-VM builds drop the `CROSS_COMPILE`.

## 5. Build the PoC

```bash
./04_build_poc.sh                # builds ./poc (default aarch64)
# Use 'ARCH=x86_64' first to test locally too.
```

## 6. Run everything in QEMU

```bash
./05_run_qemu.sh                 # boots, attaches PoC, collects full logs
# ─ exit QEMU: ctrl-a x (or wait; run.sh powers off after the PoC finishes)
```

Output in `logs/`:

| File | Content |
|---|---|
| `full-<ts>.log` | entire serial console: boot, module load traces, PoC stdout |
| `dmesg-<ts>.log` | captured `dmesg` (level ≥ debug) at the end of the session |
| `poc-<ts>.log` | stdout/stderr of the PoC run in the initramfs |
| `dmesg-delta-<ts>.log` | kernel log entries that appeared during the PoC run |

## 7. Classify the outcome (KASAN confirmed / clean)

```bash
./detect_kasan.sh logs/full-<ts>.log
```

## 8. Pipeline quickstart (copy-paste)

```bash
export ARCH=aarch64
./01_fetch_kernel.sh 6.6.0
./02_build_kernel.sh
./03_build_driver.sh                       # uses the r56p0 DDK path by default
./04_build_poc.sh
./05_run_qemu.sh                           # boots VM, attaches PoC, captures logs
./detect_kasan.sh logs/full-<ts>.log
```

## 9. Implementation notes (why these choices)

- `/dev/mali0` is created by **devtmpfs**: the DDK registers with `misc_register()`,
  `MISC_DYNAMIC_MINOR`, `mode = 0666` (`mali_kbase_core_linux.c:4587-4591`), so the
  initramfs's `mount -t devtmpfs none /dev` step is enough; `run.sh` does not mknod manually.
- The "fake"/no-mali platform in the DDK (`mali_kbase_platform_fake.c:91`,
  `platform_device_alloc("mali", 0)`) binds the driver on any generic QEMU board,
  which is why the test uses the DDK's *own* virtual-HW mode rather than a hardware DTB.
- `03_build_driver.sh` copies the DDK into a space-free `qemu-test/ddk/` staging dir
  when the vendor path contains spaces, because the kernel's Kbuild cannot accept
  `M=` arguments containing spaces.
- Serial console is used for capture (`console=ttyAMA0` on `virt` machine / `ttyS0`
  on `q35`), not a display — the entire boot log is the deliverable.

```bash
./detect_kasan.sh logs/full-<ts>.log
```

Exit codes:
- `0` — **success**: signature `slab-use-after-free READ` / `BUG: KASAN` observed with this PoC's stack
- `1` — negative: no KASAN signature; the PoC's non-crash run is informational
- `2` — inconclusive: another failure mode (e.g. module did not load, debugfs not mounted)

---

## Notes on running the PoC in a KASAN kernel

The PoC (`poc_debugfs_kctx_uaf.c`, deterministic single-process variant) triggers the use-after-free on the very first `read()` of the still-open debugfs fd after `close(/dev/mali0)`. In a KASAN kernel you get an immediate:

```
BUG: KASAN: slab-use-after-free in kbasep_mem_profile_seq_show+0x? (kernel/...)
Read of size 8 at addr ...
by task poc/784:
...
freed by task kbase_release+0x...:
...
```

If the kernel was built with `CONFIG_KASAN=y` plus the module with `CONFIG_MALI_DEBUG=y`, a second dmesg trace from Mali's own instrumentation appears in the same region and is captured to `dmesg-delta-<ts>.log`. Both are what the upstream security report needs.