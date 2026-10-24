#!/usr/bin/env bash
#
# build.sh - build the Linux kernel + Mali Kbase driver for the Arm GPU bug
#            bounty virtual platform (arm64 / QEMU virt, "dummy model").
#
# Follows Kernel/doc/arm_gpu_virtual_platform_how_to_guide.pdf, Arm64 /
# "Device Tree" configuration (the recommended path; no driver patches) and
# Kernel/README for the base-kernel config. Adapted from the 5th-gen guide to
# the Mali Kbase driver (Job Manager by default) and made multi-flavor: one
# driver family per run, selected with DRIVER_FLAVOR (see flavor.sh).
#
# Produces (per driver flavor: <FLAVOR_ID> = <flavor>-<version>, e.g.
# valhall-r42p0-01eac0):
#   build/kernel-<ver>-<flavor>/arch/arm64/boot/Image.gz  - kernel image
#   build/kernel-<ver>-<flavor>/.../midgard/mali_kbase.ko - Kbase module
#   build/images/virt_mali.dtb                            - qemu-virt base DTB
#   out/<FLAVOR_ID>/Image.gz                              - collected kernel image
#   out/<FLAVOR_ID>/mali_kbase.ko                         - collected Kbase module
#   out/<FLAVOR_ID>/virt_mali.dtb                         - collected DTB
#   out/<FLAVOR_ID>/initramfs-arm64.cpio.gz               - boot initramfs (busybox + init)
#   share/                                                - host<->guest shared folder (9p)
#   out/<FLAVOR_ID>/shared.img                            - host<->guest ext4 disk image
#
# Overridable environment variables:
#   KERNEL_VERSION     (default 5.10.155)
#   DRIVER_FLAVOR      gen5 | valhall | bifrost (default gen5; see flavor.sh)
#                      gen5    -> AX504X08X / mali-5th-gen-gpu-architecture
#                                 (5th Gen, CSF-only frontend; dummy model tKRx)
#                      valhall -> VX504X08X / mali-valhall-gpu
#                      bifrost -> BX304L01B / mali-bifrost-gpu
#   DRIVER_VERSION     (default r56p0-18eac0 for gen5, r42p0-01eac0 otherwise)
#   DRIVER_PREFIX      package prefix    (default: VX504X08X / BX304L01B)
#   DRIVER_REPO        download subdir   (default: mali-valhall-gpu / mali-bifrost-gpu)
#   DRIVER_TARBALL     full tarball name (default: <prefix>-SW-99002-<version>.tar)
#   DRIVER_URL         full download URL (default derived from repo + tarball)
#   ARCH               (default arm64; the guide's supported path)
#   CROSS_COMPILE      (default aarch64-linux-gnu-)
#   MALI_MODE          jm | csf          (default jm - Job Manager frontend;
#                                         both driver families also support csf)
#   DRIVER_MODE        module | builtin  (default module; CONFIG_MALI_MIDGARD=m)
#   ENABLE_KASAN       0 | 1             (default 0; README used 1)
#   ENABLE_DEBUG_INFO  0 | 1             (default 0; README used 1)
#   AUTO_INSTALL       0 | 1             (default 1: apt-get missing packages)
#   JOBS               (default: nproc)
#   FORCE_BUILD        0 | 1             (default 0: skip build if out/ artifacts exist)
#   BUILD_INITRAMFS    0 | 1             (default 1: build the boot initramfs)
#   BUILD_DISK         0 | 1             (default 1: build out/<FLAVOR_ID>/shared.img)
#   DISK_SIZE_MB       (default 64: size of the shared image)
#   BAKE_MODULE        0 | 1             (default 0: module loaded from the share,
#                                         1: also embed it in the initramfs)
#   NO_STRIP           0 | 1             (default 0: stage a --strip-debug copy of
#                                         mali_kbase.ko for fast guest insmod)
#
set -euo pipefail

KERNEL_VERSION="${KERNEL_VERSION:-5.10.155}"
ARCH="${ARCH:-arm64}"
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
MALI_MODE="${MALI_MODE:-jm}"
DRIVER_MODE="${DRIVER_MODE:-module}"
ENABLE_KASAN="${ENABLE_KASAN:-0}"
ENABLE_DEBUG_INFO="${ENABLE_DEBUG_INFO:-0}"
AUTO_INSTALL="${AUTO_INSTALL:-1}"
JOBS="${JOBS:-$(nproc)}"
FORCE_BUILD="${FORCE_BUILD:-0}"
BUILD_INITRAMFS="${BUILD_INITRAMFS:-1}"
BUILD_DISK="${BUILD_DISK:-1}"
DISK_SIZE_MB="${DISK_SIZE_MB:-64}"
BAKE_MODULE="${BAKE_MODULE:-0}"

# Make sure every (sub-)make invocation picks the cross toolchain.
export ARCH CROSS_COMPILE

KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v5.x/${KERNEL_TARBALL}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Driver flavor -> DRIVER_PREFIX / DRIVER_REPO / DRIVER_VERSION /
# DRIVER_TARBALL / DRIVER_URL, plus the per-flavor OUT/KDIR/MDIR paths.
# Explicitly-set variables always win (flavor.sh only fills in defaults).
. "$ROOT/flavor.sh"
flavor_resolve

DL="$ROOT/downloads"
BUILD="$ROOT/build"
IMGDIR="$BUILD/images"        # qemu dumpdtb / dtc work dir (driver-independent)
LOGDIR="$BUILD/logs/$FLAVOR_ID"
SHARE="$ROOT/share"
# KDIR, MDIR and OUT come from flavor.sh:
#   KDIR=$BUILD/kernel-<kver>-<flavor>   MDIR=$BUILD/mali-<FLAVOR_ID>
#   OUT=$ROOT/out/<FLAVOR_ID>

[ "$ARCH" = arm64 ] || fail "ARCH=$ARCH unsupported; this flow is the arm64/Device Tree path"
case "$MALI_MODE" in jm|csf) ;; *) fail "MALI_MODE must be jm|csf (got $MALI_MODE)";; esac
case "$DRIVER_MODE" in module|builtin) ;; *) fail "DRIVER_MODE must be module|builtin (got $DRIVER_MODE)";; esac

log "driver flavor: $FLAVOR_ID  (${DRIVER_TARBALL})"

# ---------------------------------------------------------------------------
# [0/10] prerequisite check (install missing packages)
# ---------------------------------------------------------------------------
# package:probe-command   (empty probe => verify with dpkg -s)
DEPS=(
  "build-essential:gcc"
  "gcc-aarch64-linux-gnu:aarch64-linux-gnu-gcc"
  "binutils-aarch64-linux-gnu:aarch64-linux-gnu-ld"
  "device-tree-compiler:dtc"
  "qemu-system-arm:qemu-system-aarch64"
  "wget:wget"
  "xz-utils:xz"
  "bc:bc"
  "bison:bison"
  "flex:flex"
  "python3:python3"
  "cpio:cpio"
  "libssl-dev:"        # kernel module signing / OPENSSL
  "libelf-dev:"        # objtool / ELF tooling
  "libncurses-dev:"    # menuconfig
  "e2fsprogs:mkfs.ext4" # shared ext4 disk image
  "patch:patch"        # apply kernel/driver patches
)
have() { [ -n "$2" ] && command -v "$2" >/dev/null 2>&1 || dpkg -s "$1" >/dev/null 2>&1; }

log "[0/10] checking prerequisites"
missing=()
for d in "${DEPS[@]}"; do
  pkg="${d%%:*}"; cmd="${d#*:}"
  have "$pkg" "$cmd" || missing+=("$pkg")
done
if [ "${#missing[@]}" -gt 0 ]; then
  log "missing packages: ${missing[*]}"
  [ "$AUTO_INSTALL" = 1 ] || fail "install them, or rerun with AUTO_INSTALL=1"
  command -v apt-get >/dev/null 2>&1 || fail "apt-get unavailable; install manually: ${missing[*]}"
  APT=apt-get; [ "$(id -u)" = 0 ] || APT="sudo apt-get"
  $APT update
  $APT install -y "${missing[@]}"
else
  log "all prerequisites present"
fi

# ---------------------------------------------------------------------------
# [1/10] create the working structure
# ---------------------------------------------------------------------------
log "[1/10] creating directory structure ($FLAVOR_ID)"
mkdir -p "$DL" "$KDIR" "$MDIR" "$IMGDIR" "$LOGDIR" "$OUT" "$SHARE"
if [ ! -f "$ROOT/.gitignore" ]; then
  cat > "$ROOT/.gitignore" <<'EOF'
# build.sh working tree
/downloads/
/build/
/out/
/share/
*.tar
linux-*.tar.xz
*.part
EOF
fi
printf '  %s\n' "downloads/  build/kernel-${KERNEL_VERSION}-${DRIVER_FLAVOR}/  build/mali-${FLAVOR_ID}/" \
                "build/images/  build/logs/${FLAVOR_ID}/  out/${FLAVOR_ID}/  share/"

# ---------------------------------------------------------------------------
# decide whether the kernel/driver build can be skipped
# ---------------------------------------------------------------------------
# If a previous run already produced the kernel image and the Kbase module in
# this flavor's out/ dir, reuse them and jump straight to the DTB / initramfs /
# launch steps. Force a full rebuild with FORCE_BUILD=1.
if [ "$FORCE_BUILD" != 1 ] && [ -s "$OUT/Image.gz" ] && [ -s "$OUT/mali_kbase.ko" ]; then
  SKIP_BUILD=1
  log "existing kernel + driver found in $OUT/ -> skipping build steps (FORCE_BUILD=1 to rebuild)"
else
  SKIP_BUILD=0
fi

if [ "$SKIP_BUILD" = 0 ]; then

# ---------------------------------------------------------------------------
# fetch helpers
# ---------------------------------------------------------------------------
# adopt a tarball already present in the repo root (e.g. a manual download)
adopt() { # <basename>
  if [ ! -s "$DL/$1" ] && [ -s "$ROOT/$1" ]; then
    log "adopting existing $1 from repo root"
    mv "$ROOT/$1" "$DL/$1"
  fi
}
fetch() { # <url> <dest>
  local url="$1" dest="$2"
  if [ -s "$dest" ]; then echo "have $(basename "$dest")"; return 0; fi
  echo "downloading $(basename "$dest")"
  wget -q -O "$dest.part" "$url" || { rm -f "$dest.part"; fail "download failed: $url"; }
  mv "$dest.part" "$dest"
}

# ---------------------------------------------------------------------------
# [2/10] fetch sources
# ---------------------------------------------------------------------------
log "[2/10] fetching sources (kernel $KERNEL_VERSION, driver $FLAVOR_ID)"
adopt "$KERNEL_TARBALL"
adopt "$DRIVER_TARBALL"
fetch "$KERNEL_URL" "$DL/$KERNEL_TARBALL"
fetch "$DRIVER_URL" "$DL/$DRIVER_TARBALL"

# ---------------------------------------------------------------------------
# [3/10] extract
# ---------------------------------------------------------------------------
log "[3/10] extracting"
if [ ! -f "$KDIR/Makefile" ]; then
  tar -C "$KDIR" --strip-components=1 -xJf "$DL/$KERNEL_TARBALL"
fi
# The driver tree always ends up at <...>/driver/product/kernel, but the
# tarballs disagree on a wrapper dir (the Bifrost one has none: entries start
# at driver/product/...), so locate it instead of hardcoding the depth.
rm -rf "$MDIR"; mkdir -p "$MDIR"
tar -C "$MDIR" -xf "$DL/$DRIVER_TARBALL"
MDIR_SRC="$(find "$MDIR" -type d -path '*/driver/product/kernel' -print -quit 2>/dev/null || true)"
[ -n "$MDIR_SRC" ] || fail "driver tree (driver/product/kernel) not found under $MDIR"
[ -d "$MDIR_SRC/drivers/gpu/arm" ] || fail "no drivers/gpu/arm under $MDIR_SRC"

# Apply local patches to the extracted Mali driver source (if any).
# Per-flavor patches live in patches/<DRIVER_FLAVOR>/; shared patches in
# patches/. A shared patch that no longer applies (e.g. a r42p0-supported
# file layout on a newer release) is skipped with a warning so driver-
# version switches in the same tree still build; force old behavior with
# STRICT_PATCHES=1 (hard fail) or SKIP_PATCHES=1 (apply none, e.g. to
# rebuild a patch cleanly against fresh sources).
STRICT_PATCHES="${STRICT_PATCHES:-0}"
SKIP_PATCHES="${SKIP_PATCHES:-0}"
PATCH_SKIPPED=""
PATCH_DIR="$ROOT/patches"
if [ -d "$PATCH_DIR" ] && [ "$SKIP_PATCHES" != 1 ]; then
  shopt -s nullglob
  for p in "$PATCH_DIR"/*.patch "$PATCH_DIR/$DRIVER_FLAVOR"/*.patch; do
    [ -f "$p" ] || continue
    log "applying patch $(basename "$p") to Mali driver source"
    if (cd "$MDIR_SRC" && patch -p1 < "$p"); then
      continue
    elif [ "$STRICT_PATCHES" = 1 ]; then
      fail "failed to apply $(basename "$p") (STRICT_PATCHES=1)"
    else
      printf '\033[1;33mWARNING:\033[0m patch %s does not apply to this driver release - SKIPPED\n' \
        "$(basename "$p")"
      PATCH_SKIPPED="$PATCH_SKIPPED $(basename "$p")"
    fi
  done
  shopt -u nullglob
  rm -f "$MDIR_SRC"/*.rej
fi

# ---------------------------------------------------------------------------
# [4/10] integrate Kbase into the kernel tree
# ---------------------------------------------------------------------------
log "[4/10] integrating Kbase ($FLAVOR_ID) into the kernel tree"
# Drop whatever driver was integrated into this kernel tree before - flavor or
# version switches must not leave stale files behind. The Kbase include/linux
# shims listed below have no upstream 5.10 counterpart, so removing them can
# never clobber a kernel header; include/uapi/gpu is likewise Mali-only.
rm -rf "$KDIR/drivers/gpu/arm" "$KDIR/include/uapi/gpu"
rm -f "$KDIR/include/linux/memory_group_manager.h" \
      "$KDIR/include/linux/priority_control_manager.h" \
      "$KDIR/include/linux/protected_memory_allocator.h" \
      "$KDIR/include/linux/protected_mode_switcher.h" \
      "$KDIR/include/linux/dma-buf-test-exporter.h" \
      "$KDIR/include/linux/version_compat_defs.h"
cp -a "$MDIR_SRC/drivers/." "$KDIR/drivers/"
# Kbase also ships headers that live OUTSIDE drivers/ and must be installed into
# the kernel tree, otherwise compilation dies e.g. with:
#   fatal error: uapi/gpu/arm/midgard/mali_base_kernel.h: No such file or directory
#   fatal error: linux/memory_group_manager.h: No such file or directory
# That is include/uapi/gpu/arm/midgard/*.h (userspace ABI) plus the
# include/linux/*.h shims (memory_group_manager, priority_control_manager,
# protected_memory_allocator, protected_mode_switcher, dma-buf-test-exporter).
# None of these names exist in upstream 5.10, so installing the whole include/
# tree cannot clobber a kernel header.
cp -a "$MDIR_SRC/include/." "$KDIR/include/"
[ -f "$KDIR/include/uapi/gpu/arm/midgard/mali_base_kernel.h" ] \
  || fail "Kbase UAPI headers not installed under $KDIR/include/uapi/gpu"
[ -f "$KDIR/include/linux/memory_group_manager.h" ] \
  || fail "Kbase headers not installed under $KDIR/include/linux"
if [ ! -f "$KDIR/drivers/gpu/arm/Kconfig" ]; then
  mkdir -p "$KDIR/drivers/gpu/arm"
  cp -a "$MDIR_SRC/drivers/gpu/arm/." "$KDIR/drivers/gpu/arm/"
fi
# wire the driver into the build
if ! grep -q 'gpu/arm' "$KDIR/drivers/gpu/Makefile" 2>/dev/null; then
  echo 'obj-$(CONFIG_MALI_MIDGARD) += arm/' >> "$KDIR/drivers/gpu/Makefile"
fi
if ! grep -q 'source "drivers/gpu/arm/Kconfig"' "$KDIR/drivers/video/Kconfig" 2>/dev/null; then
  echo 'source "drivers/gpu/arm/Kconfig"' >> "$KDIR/drivers/video/Kconfig"
fi
grep -q 'source "drivers/gpu/arm/Kconfig"' "$KDIR/drivers/video/Kconfig" \
  || fail "drivers/video/Kconfig not wired for the Mali arm Kconfig"
# The public driver packages do not ship the GPU Arbitration reference code
# (separate, previously non-public Arm package), but drivers/gpu/arm/Kconfig
# still references it. Drop that source line from the kernel-tree copy
# (upstream-neutral, Mali-only file); otherwise every defconfig dies with:
#   drivers/gpu/arm/Kconfig:25: can't open file "drivers/gpu/arm/arbitration/Kconfig"
if grep -q 'arbitration/Kconfig' "$KDIR/drivers/gpu/arm/Kconfig"; then
  sed -i '/arbitration\/Kconfig/d' "$KDIR/drivers/gpu/arm/Kconfig"
fi
grep -q 'arbitration' "$KDIR/drivers/gpu/arm/Kconfig" \
  && fail "arbitration reference still present in $KDIR/drivers/gpu/arm/Kconfig" || true
# The injected DT node uses compatible = "arm,mali-midgard"; verify this driver
# release still carries it in its of_match table (mali_kbase_core_linux.c),
# otherwise the module would build fine but never probe /dev/mali0.
grep -rq '"arm,mali-midgard"' "$MDIR_SRC/drivers/gpu/arm/midgard" \
  || fail "$FLAVOR_ID has no \"arm,mali-midgard\" DT compatible (of_match mismatch)"

# ---------------------------------------------------------------------------
# [5/10] configure
# ---------------------------------------------------------------------------
log "[5/10] configuring the kernel (arm64 / Device Tree, $FLAVOR_ID, MALI_MODE=$MALI_MODE)"
make -C "$KDIR" ARCH="$ARCH" defconfig >/dev/null
{
  echo
  echo '# --- Mali Kbase (Arm GPU bug bounty virtual platform, arm64/DT) ---'
  [ "$DRIVER_MODE" = module ] && echo 'CONFIG_MALI_MIDGARD=m' || echo 'CONFIG_MALI_MIDGARD=y'
  echo 'CONFIG_MALI_EXPERT=y'
  echo 'CONFIG_MALI_NO_MALI=y'
  echo 'CONFIG_MALI_PLATFORM_NAME="devicetree"'
  [ "$MALI_MODE" = csf ] && echo 'CONFIG_MALI_CSF_SUPPORT=y' || echo '# CONFIG_MALI_CSF_SUPPORT is not set'
  # 5th Gen guide: default the "dummy model" to the G725/G925 ("tKRx") GPU.
  # (Valhall/Bifrost keep their Kconfig default, "tMIx".)
  [ "$DRIVER_FLAVOR" = gen5 ] && echo 'CONFIG_MALI_NO_MALI_DEFAULT_GPU="tKRx"'
  echo 'CONFIG_MALI_DEVFREQ=y'
  echo 'CONFIG_PM=y'
  echo 'CONFIG_PM_DEVFREQ=y'
  echo 'CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=y'
  # base-kernel config from Kernel/README (RANDOMIZE_BASE=n always, for nokaslr)
  [ "$ENABLE_KASAN" = 1 ] && echo 'CONFIG_KASAN=y' || echo '# CONFIG_KASAN is not set'
  [ "$ENABLE_DEBUG_INFO" = 1 ] && echo 'CONFIG_DEBUG_INFO=y' || echo '# CONFIG_DEBUG_INFO is not set'
  echo 'CONFIG_RANDOMIZE_BASE=n'
} >> "$KDIR/.config"
make -C "$KDIR" ARCH="$ARCH" olddefconfig 2>&1 | tee "$LOGDIR/config.log"
grep -q "^CONFIG_MALI_MIDGARD=$([ "$DRIVER_MODE" = module ] && echo m || echo y)" "$KDIR/.config" \
  || fail "CONFIG_MALI_MIDGARD missing from .config"
grep -q '^CONFIG_MALI_PLATFORM_NAME="devicetree"' "$KDIR/.config" \
  || fail "CONFIG_MALI_PLATFORM_NAME not devicetree"
# olddefconfig can silently drop MALI_CSF_SUPPORT (some releases of this Kconfig
# only allow CSF when the driver is built as a module), so verify the frontend
# we asked for actually ended up in .config instead of defaulting to JM/CSF.
if [ "$MALI_MODE" = csf ]; then
  grep -q '^CONFIG_MALI_CSF_SUPPORT=y' "$KDIR/.config" \
    || fail "MALI_MODE=csf but CONFIG_MALI_CSF_SUPPORT was dropped by olddefconfig (try DRIVER_MODE=module)"
else
  if grep -q '^CONFIG_MALI_CSF_SUPPORT=y' "$KDIR/.config"; then
    fail "MALI_MODE=jm but CONFIG_MALI_CSF_SUPPORT=y in .config"
  fi
fi

# ---------------------------------------------------------------------------
# [6/10] build
# ---------------------------------------------------------------------------
log "[6/10] building kernel + modules ($FLAVOR_ID, $JOBS jobs; this can take a while)"
set +e
make -C "$KDIR" ARCH="$ARCH" -j"$JOBS" 2>&1 | tee "$LOGDIR/kernel-build.log"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" -eq 0 ] || { tail -40 "$LOGDIR/kernel-build.log"; fail "kernel build failed (see $LOGDIR/kernel-build.log)"; }
[ -f "$KDIR/arch/arm64/boot/Image.gz" ] || fail "Image.gz not built"

MKO="$(find "$KDIR/drivers/gpu/arm/midgard" -name 'mali_kbase.ko' 2>/dev/null | head -1 || true)"
[ -n "$MKO" ] || fail "mali_kbase.ko not built (is CONFIG_MALI_MIDGARD=m?)"
cp -f "$KDIR/arch/arm64/boot/Image.gz" "$OUT/Image.gz"
cp -f "$MKO"                           "$OUT/mali_kbase.ko"
log "collected $OUT/Image.gz and $OUT/mali_kbase.ko"

fi  # SKIP_BUILD

# ---------------------------------------------------------------------------
# [7/10] build the Mali device-tree blob (only if we don't already have one)
# ---------------------------------------------------------------------------
if [ "$FORCE_BUILD" = 1 ] || [ ! -s "$OUT/virt_mali.dtb" ]; then
  log "[7/10] building the Mali device-tree node into a qemu-virt DTB"
  qemu-system-aarch64 -machine virt -machine "dumpdtb=$IMGDIR/virt_base.dtb" >/dev/null 2>&1
  [ -s "$IMGDIR/virt_base.dtb" ] || fail "qemu dumpdtb failed"
  dtc -I dtb -O dts "$IMGDIR/virt_base.dtb" -o "$IMGDIR/virt_base.dts" >/dev/null 2>&1
  python3 - "$IMGDIR/virt_base.dts" "$IMGDIR/virt_mali.dts" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines(True)
# Guide node. With the "dummy model" the driver only parses it, so the MMIO
# address just has to be non-overlapping; we place it well above RAM.
node = '''\t\tgpu@6e000000 {
\t\t\tcompatible = "arm,mali-midgard";
\t\t\treg = <0x0 0x6e000000 0x0 0x200000>;
\t\t\tinterrupts = <0x0 0xa8 0x4>, <0x0 0xa8 0x4>, <0x0 0xa8 0x4>;
\t\t\tinterrupt-names = "JOB", "MMU", "GPU";
\t\t\tclock-names = "apb_pclk";
\t\t\tclocks = <0x8000>;
\t\t};
'''
# find the root node and its closing brace, insert the gpu node as the last child
text = ''.join(lines)
start = text.find('{')
depth = 0
end = -1
for i in range(start, len(text)):
    if text[i] == '{': depth += 1
    elif text[i] == '}':
        depth -= 1
        if depth == 0:
            end = i
            break
if end < 0:
    sys.exit("could not locate root node")
out = text[:end] + '\n' + node + text[end:]
open(dst, 'w').write(out)
PY
  dtc -I dts -O dtb "$IMGDIR/virt_mali.dts" -o "$OUT/virt_mali.dtb" >/dev/null 2>&1
  [ -s "$OUT/virt_mali.dtb" ] || fail "dtc dts->dtb failed"
else
  log "[7/10] using existing $OUT/virt_mali.dtb"
fi

# ---------------------------------------------------------------------------
# [8/10] verify artifacts
# ---------------------------------------------------------------------------
log "[8/10] verifying artifacts"
fdtget -t s "$OUT/virt_mali.dtb" /gpu@6e000000 compatible 2>/dev/null | grep -q 'arm,mali-midgard' \
  || fail "gpu node missing/invalid in $OUT/virt_mali.dtb"
[ -s "$OUT/Image.gz" ]     || fail "$OUT/Image.gz missing"
[ -s "$OUT/mali_kbase.ko" ] || fail "$OUT/mali_kbase.ko missing"

{
  echo "flavor  : $FLAVOR_ID ($DRIVER_TARBALL)"
  echo "kernel  : $OUT/Image.gz ($(stat -c%s "$OUT/Image.gz") bytes)"
  echo "module  : $OUT/mali_kbase.ko ($(stat -c%s "$OUT/mali_kbase.ko") bytes)"
  echo "dtb     : $OUT/virt_mali.dtb ($(stat -c%s "$OUT/virt_mali.dtb") bytes)"
  [ -n "$PATCH_SKIPPED" ] && echo "skipped patches:$PATCH_SKIPPED (do not port to this release)"
} | tee "$LOGDIR/summary.txt"

# ---------------------------------------------------------------------------
# [9/10] build the boot initramfs (from scratch)
# ---------------------------------------------------------------------------
if [ "${BUILD_INITRAMFS:-1}" = 1 ]; then
  log "[9/10] building the boot initramfs"
  KO="$OUT/mali_kbase.ko" OUT="$OUT/initramfs-arm64.cpio.gz" \
    ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" JOBS="$JOBS" \
    BAKE_MODULE="${BAKE_MODULE:-0}" \
    DRIVER_FLAVOR="$DRIVER_FLAVOR" DRIVER_VERSION="$DRIVER_VERSION" \
    "$ROOT/initramfs_build.sh" || fail "initramfs build failed"
else
  log "[9/10] skipping initramfs (BUILD_INITRAMFS=0)"
fi

# ---------------------------------------------------------------------------
# [10/10] host <-> guest shared storage (share/ + out/<FLAVOR_ID>/shared.img)
# ---------------------------------------------------------------------------
if [ "${BUILD_DISK:-1}" = 1 ]; then
  log "[10/10] staging share/ and building the shared ext4 image"
  mkdir -p "$SHARE/mali" "$SHARE/out"
  # Stage a --strip-debug copy: the loader does not need DWARF, and parsing
  # the full ~47 MiB module under QEMU/KASAN delays boot by ~40 s.
  if [ "${NO_STRIP:-0}" != 1 ] && command -v "${CROSS_COMPILE}strip" >/dev/null 2>&1 \
     && "${CROSS_COMPILE}strip" --strip-debug -o "$SHARE/mali/mali_kbase.ko.tmp" \
          "$OUT/mali_kbase.ko" 2>/dev/null; then
    mv -f "$SHARE/mali/mali_kbase.ko.tmp" "$SHARE/mali/mali_kbase.ko"
  else
    rm -f "$SHARE/mali/mali_kbase.ko.tmp"
    cp -f "$OUT/mali_kbase.ko" "$SHARE/mali/mali_kbase.ko"
  fi
  cp -f "$ROOT/tools/load_mod.sh" "$SHARE/mali/load_mod.sh"
  cp -f "$ROOT/tools/run.sh"      "$SHARE/mali/run.sh"
  chmod 0755 "$SHARE/mali/load_mod.sh" "$SHARE/mali/run.sh"
  if [ -f "$ROOT/tools/mali_smoke.c" ]; then
    log "  cross-compiling tools/mali_smoke.c (static aarch64)"
    "${CROSS_COMPILE}gcc" -static -O2 -Wall \
      -o "$SHARE/mali/mali_smoke" "$ROOT/tools/mali_smoke.c" \
      || fail "failed to cross-compile tools/mali_smoke.c"
    chmod 0755 "$SHARE/mali/mali_smoke"
  fi
  if [ -f "$ROOT/poc/poc.c" ]; then
    log "  cross-compiling poc/poc.c (static aarch64)"
    "${CROSS_COMPILE}gcc" -static -O2 -Wall \
      -o "$SHARE/mali/poc" "$ROOT/poc/poc.c" \
      || fail "failed to cross-compile poc/poc.c"
    chmod 0755 "$SHARE/mali/poc"
  fi
  IMG="$OUT/shared.img" SRC="$SHARE" SIZE_MB="${DISK_SIZE_MB:-64}" \
    DRIVER_FLAVOR="$DRIVER_FLAVOR" DRIVER_VERSION="$DRIVER_VERSION" \
    "$ROOT/disk.sh" build || fail "disk.sh build failed"
else
  log "[10/10] skipping shared storage (BUILD_DISK=0)"
fi

cat <<EOF

==> done. (driver flavor: $FLAVOR_ID)
      kernel    : $OUT/Image.gz
      module    : $OUT/mali_kbase.ko
      dtb       : $OUT/virt_mali.dtb
      initramfs : $OUT/initramfs-arm64.cpio.gz
      share/    : $SHARE          (9p, live)
      image     : $OUT/shared.img (ext4, ${DISK_SIZE_MB:-64} MiB)

==> boot with:

    ./run_arm64.sh

(run_arm64.sh auto-detects out/$FLAVOR_ID when it is the only built flavor;
 otherwise use:  DRIVER_FLAVOR=$DRIVER_FLAVOR DRIVER_VERSION=$DRIVER_VERSION ./run_arm64.sh )

(/init mounts $SHARE as /host and $OUT/shared.img as /mnt, then loads
 mali_kbase.ko + mali_smoke from the shared storage -- no initramfs rebuild.)

To iterate without rebuilding the initramfs:
  * 9p (live)   : drop files in $SHARE/mali/  ->  guest /host/mali/
  * ext4 image  : ./disk.sh put <file>        ->  guest /mnt/<file>
  * collect back: ./disk.sh get <path> <hostfile>

==> the other driver flavors build side by side in their own out/ subdirs:

    DRIVER_FLAVOR=gen5 ./build.sh     # AX504X08X (5th Gen, CSF-only; default)
    DRIVER_FLAVOR=valhall ./build.sh  # VX504X08X
    DRIVER_FLAVOR=bifrost ./build.sh  # BX304L01B
EOF
