#!/usr/bin/env bash
# detect_kasan.sh — classify a captured QEMU serial log.
#   ./detect_kasan.sh [full-<ts>.log]
# Exit: 0 = UAF/KASAN hit observed, 1 = clean, 2 = inconclusive.
set -u
LOG="${1:-}"
[ -n "$LOG" ] && [ -f "$LOG" ] || { echo "usage: $0 <serial log file>"; exit 2; }

echo "── detect_kasan: $LOG ──"
HITS=$(grep -a -c -E "KASAN: .*use-after-free|slab-use-after-free|use-after-free" "$LOG" || true)
DUMPS=$(grep -a -c -E "BUG: |WARNING: |Oops|segfault" "$LOG" || true)
POC_STEPPED=$(grep -a -c "STEP 5" "$LOG" || true)

echo "use-after-free refs: $HITS"
echo "kernel-die markers : $DUMPS"
if [ "$POC_STEPPED" -gt 0 ]; then
    echo "POC reached STEP 5 (the UAF deref step) — good sign the trigger ran"
fi

if [ "$HITS" -gt 0 ] && grep -aq -E "kbase|debugfs|mali" "$LOG"; then
    echo
    echo "  /\\----------- VISIBLE KASAN/UAF TRACES (/KASAN hit + Mali stack) ---------\\"
    grep -a -m 15 -E "KASAN: .*use-after-free|slab-use-after-free|use-after-free" "$LOG"
    echo "  \\----------- ------------------------------------------------------------/"
    echo "VERDICT: KASAN confirmed the UAF. Copy the section above into the upstream report."
    exit 0
elif [ "$DUMPS" -gt 0 ]; then
    echo "kernel crashed with a non-UAF signature — inspect $LOG for the real fault"
    exit 2
else
    echo "no UAF signature found in the log"
    echo "TIP: make sure CONFIG_KASAN=y, and that ./05_run_qemu.sh copied mali.ko and the PoC"
    exit 1
fi
