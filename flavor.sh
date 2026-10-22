#!/usr/bin/env bash
#
# flavor.sh - shared driver-flavor resolution (sourced, not executed).
#
# build.sh, run_arm64.sh, initramfs_build.sh and disk.sh all source this file
# so a single set of names drives the whole flow. It supports the two Mali
# kernel-driver families published by Arm:
#
#   DRIVER_FLAVOR   gen5 (default) | valhall | bifrost
#                      gen5   -> the Arm Mali "5th Gen GPU Architecture" CSF-only
#                                driver family (AX-prefix packages)
#   DRIVER_PREFIX   package prefix   (default: AX504X08X / VX504X08X / BX304L01B)
#   DRIVER_REPO     download subdir  (default: mali-5th-gen-gpu-architecture /
#                                    mali-valhall-gpu / mali-bifrost-gpu)
#   DRIVER_VERSION  driver release   (default: r56p0-18eac0 (gen5) /
#                                    r42p0-01eac0 (valhall|bifrost))
#   DRIVER_TARBALL  <prefix>-SW-99002-<version>.tar
#   DRIVER_URL      https://developer.arm.com/-/media/Files/downloads/
#                   mali-drivers/kernel/<repo>/<tarball>
#
# Derived (unless the caller already set them):
#   FLAVOR_ID   <flavor>-<version>           e.g. valhall-r42p0-01eac0
#   OUT         <root>/out/<FLAVOR_ID>       per-flavor artifacts
#   KDIR        <root>/build/kernel-<kver>-<flavor>
#   MDIR        <root>/build/mali-<FLAVOR_ID>
#
# Entry points:
#   flavor_detect    pick the flavor/version from out/<FLAVOR_ID>/ when the
#                    caller did not pin DRIVER_FLAVOR (errors if several
#                    flavors are present)
#   flavor_resolve   full resolution: flavor -> prefix/repo/version/tarball/url
#                    + FLAVOR_ID + OUT/KDIR/MDIR defaults
# Typical use:
#   . "$ROOT/flavor.sh"; flavor_detect; flavor_resolve   # picky callers
#   . "$ROOT/flavor.sh"; flavor_resolve                  # default flavor only

# error helper: use the caller's fail() when it exists (it exits), else ours
__flavor_fail() {
  if command -v fail >/dev/null 2>&1; then
    fail "$*"
  else
    printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# flavor_detect - resolve DRIVER_FLAVOR/DRIVER_VERSION from what was built
# ---------------------------------------------------------------------------
# No-op when the caller already pinned DRIVER_FLAVOR (or OUT). With exactly
# one out/<flavor>-<version>/ artifact dir present, both values are taken from
# it; several candidates (either two flavors or two versions) are an error so
# we never boot/build the wrong one silently.
flavor_detect() {
  [ -n "${DRIVER_FLAVOR:-}" ] && return 0
  [ -n "${OUT:-}" ] && return 0

  local d name
  local -a hits=()
  for d in "$ROOT"/out/*/; do
    [ -d "$d" ] || continue
    name="${d%/}"; name="${name##*/}"
    case "$name" in gen5-*|valhall-*|bifrost-*) ;; *) continue ;; esac
    [ -s "$d/Image.gz" ] || [ -s "$d/mali_kbase.ko" ] \
      || [ -s "$d/initramfs-arm64.cpio.gz" ] || [ -s "$d/virt_mali.dtb" ] \
      || continue
    hits+=("$name")
  done

  if [ "${#hits[@]}" -eq 0 ]; then
    return 0
  elif [ "${#hits[@]}" -eq 1 ]; then
    DRIVER_FLAVOR="${hits[0]%%-*}"
    DRIVER_VERSION="${DRIVER_VERSION:-${hits[0]#*-}}"
    return 0
  fi

  __flavor_fail "multiple driver flavors found in $ROOT/out: ${hits[*]}
  set DRIVER_FLAVOR=gen5|valhall|bifrost (plus DRIVER_VERSION), or OUT=<dir>"
}

# ---------------------------------------------------------------------------
# flavor_resolve - flavour -> prefix / URL / version / paths
# ---------------------------------------------------------------------------
flavor_resolve() {
  local ver_pinned="" parsed

  [ -n "${DRIVER_VERSION:-}" ] && ver_pinned=1

  DRIVER_FLAVOR="${DRIVER_FLAVOR:-gen5}"
  case "$DRIVER_FLAVOR" in
    gen5)
      DRIVER_PREFIX="${DRIVER_PREFIX:-AX504X08X}"
      DRIVER_REPO="${DRIVER_REPO:-mali-5th-gen-gpu-architecture}"
      DRIVER_VERSION="${DRIVER_VERSION:-r56p0-18eac0}"
      ;;
    valhall)
      DRIVER_PREFIX="${DRIVER_PREFIX:-VX504X08X}"
      DRIVER_REPO="${DRIVER_REPO:-mali-valhall-gpu}"
      DRIVER_VERSION="${DRIVER_VERSION:-r42p0-01eac0}"
      ;;
    bifrost)
      DRIVER_PREFIX="${DRIVER_PREFIX:-BX304L01B}"
      DRIVER_REPO="${DRIVER_REPO:-mali-bifrost-gpu}"
      DRIVER_VERSION="${DRIVER_VERSION:-r42p0-01eac0}"
      ;;
    *)
      __flavor_fail "DRIVER_FLAVOR must be gen5|valhall|bifrost (got: $DRIVER_FLAVOR)"
      ;;
  esac

  # The 5th Gen driver family is CSF-only (no Job Manager frontend).
  if [ "$DRIVER_FLAVOR" = gen5 ]; then
    [ "${MALI_MODE:-csf}" = csf ] \
      || printf 'note: flavor gen5 is CSF-only; overriding MALI_MODE=jm -> csf\n' >&2
    MALI_MODE=csf
  fi

  # The 5th Gen packages ship as .tar.gz; the Valhall/Bifrost ones as .tar.
  case "$DRIVER_FLAVOR" in
    gen5)
      DRIVER_TARBALL="${DRIVER_TARBALL:-${DRIVER_PREFIX}-SW-99002-${DRIVER_VERSION}.tar.gz}"
      ;;
    *)
      DRIVER_TARBALL="${DRIVER_TARBALL:-${DRIVER_PREFIX}-SW-99002-${DRIVER_VERSION}.tar}"
      ;;
  esac
  DRIVER_URL="${DRIVER_URL:-https://developer.arm.com/-/media/Files/downloads/mali-drivers/kernel/${DRIVER_REPO}/${DRIVER_TARBALL}}"

  # The caller pinned a full tarball name but no version (e.g.
  # DRIVER_TARBALL=VX504X08X-SW-99002-r43p0-01eac0.tar): keep the version -
  # and therefore FLAVOR_ID / out/<FLAVOR_ID>/ - in sync with it.
  if [ -z "$ver_pinned" ]; then
    parsed="$(printf '%s' "$DRIVER_TARBALL" | grep -oE 'r[0-9]+p[0-9]+' | head -n 1 || true)"
    if [ -n "$parsed" ]; then
      DRIVER_VERSION="$parsed"
    fi
  fi

  FLAVOR_ID="${DRIVER_FLAVOR}-${DRIVER_VERSION}"

  KERNEL_VERSION="${KERNEL_VERSION:-5.10.155}"
  ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

  OUT="${OUT:-$ROOT/out/$FLAVOR_ID}"
  KDIR="${KDIR:-$ROOT/build/kernel-${KERNEL_VERSION}-${DRIVER_FLAVOR}}"
  MDIR="${MDIR:-$ROOT/build/mali-$FLAVOR_ID}"

  return 0
}
