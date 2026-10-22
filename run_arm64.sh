#!/usr/bin/env bash
#
# run_arm64.sh - boot the built arm64 kernel + initramfs under QEMU with the
#               Mali virtual platform, attaching the shared storage:
#
#                 out/<FLAVOR_ID>/shared.img  -> guest /dev/vda  (ext4, -drive)
#                 share/                      -> guest /host      (9p,  -virtfs)
#
#               /init mounts both and loads mali_kbase.ko (+ mali_smoke) from
#               the shared storage, so no initramfs rebuild is needed to swap
#               the module or a test binary.
#
#               The driver flavor directory (out/<flavor>-<version>/) is
#               resolved in this order:
#                 1. OUT (explicit path wins)
#                 2. --flavor <gen5|valhall|bifrost> / DRIVER_FLAVOR env
#                    (+ optional DRIVER_VERSION)
#                 3. auto-detection when exactly one flavor has been built;
#                    several candidates -> error listing them
#               Before booting, share/mali/ is re-staged from the selected
#               out/ dir so the live 9p share can never hold the other
#               flavor's module (disable with NO_STAGE=1).
#
# Usage:
#   ./run_arm64.sh                     # boot (builds the disk image if missing)
#   ./run_arm64.sh --flavor bifrost    # boot the Bifrost flavor's artifacts
#   ./run_arm64.sh --gdb               # add -S -gdb tcp::12345
#   ./run_arm64.sh --disk-only         # do not attach the 9p share
#   ./run_arm64.sh --9p-only           # do not attach the ext4 image
#   ./run_arm64.sh --no-build          # never auto-build shared.img
#   ./run_arm64.sh -- <args...>        # append extra args to qemu
#
# Overridable environment:
#   OUT             (default <root>/out/<FLAVOR_ID>)
#   SHARE           (default <root>/share)
#   DRIVER_FLAVOR   gen5 | valhall | bifrost (default: auto-detect, else gen5)
#   DRIVER_VERSION  (default r42p0-01eac0)
#   NO_STAGE        1 = do not refresh share/mali/ from the selected out/ dir
#   KASAN_EXTRA     extra kernel cmdline args (e.g. "kasan.report_always=1")
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GDB=0; USE_DISK=1; USE_9P=1; NO_BUILD=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --gdb)         GDB=1 ;;
    --disk-only)   USE_9P=0 ;;
    --9p-only)     USE_DISK=0 ;;
    --no-build)    NO_BUILD=1 ;;
    --flavor)      if [ $# -lt 2 ]; then printf -- '--flavor needs gen5|valhall|bifrost\n' >&2; exit 2; fi
                   DRIVER_FLAVOR="$2"; shift ;;
    --flavor=*)    DRIVER_FLAVOR="${1#--flavor=}" ;;
    --)            shift; EXTRA=("$@"); break ;;
    -h|--help)     sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

# --- resolve the flavor-specific out/ dir -----------------------------------
if [ -z "${OUT:-}" ]; then
  . "$ROOT/flavor.sh"
  flavor_detect   # no-op when DRIVER_FLAVOR (e.g. via --flavor) is already set
  flavor_resolve  # fills DRIVER_* and sets OUT=<root>/out/<FLAVOR_ID>
fi
SHARE="${SHARE:-$ROOT/share}"
IMG="$OUT/shared.img"

# Re-stage the live 9p share from the flavor we are about to boot, so
# /host/mali/mali_kbase.ko can never be a different flavor's module.
if [ "${NO_STAGE:-0}" != 1 ] && [ -s "$OUT/mali_kbase.ko" ]; then
  mkdir -p "$SHARE/mali"
  cp -f "$OUT/mali_kbase.ko" "$SHARE/mali/mali_kbase.ko"
  for f in load_mod.sh run.sh; do
    if [ -f "$ROOT/tools/$f" ]; then
      cp -f "$ROOT/tools/$f" "$SHARE/mali/$f"
      chmod 0755 "$SHARE/mali/$f"
    fi
  done
  printf '\033[1;34m==>\033[0m staged %s -> %s/mali/\n' "$OUT/mali_kbase.ko" "$SHARE"
fi

for f in "$OUT/Image.gz" "$OUT/initramfs-arm64.cpio.gz" "$OUT/virt_mali.dtb"; do
  [ -s "$f" ] || { printf 'ERROR: %s missing; run ./build.sh (same DRIVER_FLAVOR/DRIVER_VERSION)\n' "$f" >&2; exit 1; }
done

ARGS=(-machine virt -cpu cortex-a57 -smp 2 -m 4096 -nographic -net nic -net user)
[ "$GDB" = 1 ] && ARGS+=(-S -gdb tcp::12345)

if [ "$USE_DISK" = 1 ]; then
  if [ ! -s "$IMG" ] && [ "$NO_BUILD" != 1 ]; then
    printf '\033[1;34m==>\033[0m building the shared disk image (%s)\n' "$IMG"
    IMG="$IMG" SRC="$SHARE" "$ROOT/disk.sh" build
  fi
  [ -s "$IMG" ] && ARGS+=(-drive "file=$IMG,format=raw,if=virtio")
fi

if [ "$USE_9P" = 1 ]; then
  mkdir -p "$SHARE"
  ARGS+=(-virtfs "local,path=$SHARE,mount_tag=host0,security_model=passthrough")
fi

APPEND='console=ttyAMA0 rdinit=/init acpi=off nokaslr loglevel=7'
# Extra kernel cmdline knobs (e.g. KASAN_EXTRA="kasan.report_always=1").
[ -n "${KASAN_EXTRA:-}" ] && APPEND="$APPEND $KASAN_EXTRA"

ARGS+=(
  -kernel "$OUT/Image.gz"
  -initrd "$OUT/initramfs-arm64.cpio.gz"
  -dtb    "$OUT/virt_mali.dtb"
  -append "$APPEND"
)
[ "${#EXTRA[@]}" -gt 0 ] && ARGS+=("${EXTRA[@]}")

set -x
exec qemu-system-aarch64 "${ARGS[@]}"
