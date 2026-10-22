# Mali CSF Kernel Driver r56p0 — Full Audit & Findings Report (GLM)

**Target:** `AX504X08X-SW-99002-r56p0-18ea` — ARM Mali Valhall/CSF kernel driver
**Date:** 2026-10-22
**Method:** 4 parallel deep audits (ioctl/debugfs layer, CSF scheduler/queue lifetimes, memory/region refcounts, KCPU/sync/tiler) + 3 blind-spot deep dives (fw cfg/core_dump/mcu_shared_reg, ipa_control/TL/coresight/tracebuf, mem_profile/MMU)
**Scope:** Memory-management bug hunt (UAF/double-free/type confusion), privilege-escalation feasibility from userspace
**Companion PoC:** `poc_debugfs_kctx_uaf.c` in this folder (crash-only, no escalation)

---

## 1. Executive summary

The r56p0 tree is substantially hardened versus pre-2023 Mali releases (refcounted queues/groups/heaps, RCU fence metadata, refcounted MMU fault workers, `firmware_inited` gating, selective `get_file_active` hardening).

**Bottom line:** No unprivileged-ioctl-reachable UAF exists in this release's callable core. The one exploitable class that remains is the **per-kctx debugfs family (root-gated, deterministic, attacker-shaped)** plus teardown-race bugs (fw_log, timeline, GET_GPUPROPS) and two latent defects — all disclosed below for ARM PSIRT.

**This is why the earlier PoC plan (`# Mali Midgard UAF → Privilege Escalation PoC Plan`) was refuted and re-written.** Details in §5.

Consolidated per-area findings table:

| # | Finding | Severity | Gated by |
|---|---------|----------|----------|
| 1 | Per-kctx debugfs `i_private → kctx` UAF family | **High** (root↔kernel, deterministic, attacker-shaped) | debugfs perms |
| 2 | `kbase_vunmap(ctx_ptr, &mapping)` type confusion (`csf/mali_kbase_csf_heap_context_alloc.c:57-67`) | Low today / latent trap | config-inert |
| 3 | `kbase_csf_firmware_log_term` vs `fw_log->busy` | **High** (rmmod-gated, UAF write ≥64 KiB) | debugfs + rmmod |
| 4 | `kbase_timeline` vfree vs open TLSTREAM fds | Medium (rmmod-gated) | device teardown |
| 5 | `page_md->data` post-lock-drop read (`mali_kbase_mem_migrate.c:674`) | Low (latent) | `CONFIG_MALI_PAGE_MIGRATION` |
| 6 | Device-teardown vs in-flight ioctls (GET_GPUPROPS, io_history, ktrace, kinstr client, autoflush timer) | Medium (root) | unbind/rmmod |

---

## 2. Complete *alloc → free → protector → triggerable?* map

| Object | Alloc (file:line) | Free | Protector | User-triggerable free? |
|---|---|---|---|---|
| `kbase_context` | `vzalloc` (context/backend) | `vfree` at `context/backend/mali_kbase_context_csf.c:81-86` | fd lifetime (+`get_file_active` in only 2 files) | `close(fd)` only |
| `kbase_mem_phy_alloc` | `mali_kbase_mem.c:2340` | `kbase_mem_kref_free` | kref + `gpu/kernel_mappings` atomics | `MEM_FREE` (safe) |
| `kbase_va_region` | region-tracker allocs | `kbase_region_refcnt_free` (`mali_kbase_mem.h:772`) | `va_refcnt` + `reg_lock` | `MEM_FREE`/INVAL-safe |
| page_metadata | `mmu/mali_kbase_mmu.c:171` | `mmu/mali_kbase_mmu.c:209` | `migrate_lock` state machine | config-gated only |
| sub-alloc partials | `mali_kbase_mem.c:1359,3115` | in `free_partial*` | `mem_partials_lock` (fragile, F2 latent) | shrink paths |
| queue (CSF) | `csf/mali_kbase_csf.c` | `csf.c:462` refcount → `kfree` | `csf.lock` + kick-drain + event lock | `QUEUE_DESTROY` (drained) |
| queue_group | csf.c:1662 / 2023 | 2 sites | `csf.lock` + scheduler lock cross-order | `TERM` (safe, hardening F2) |
| kcpu_queue | kcpu.c (6 allocs) | KCPU_QUEUE_DELETE / ctx teardown | `kcpu_queues.lock` drain triple-gate | KCPU ioctls (safe) |
| tiler_heap / chunks | heap.c:238,378,537,848 | heap_term / reclaim | `tiler_heaps.lock` + NO_USER_FREE | `HEAP_DELETE` (alias blocked) |
| dma-fence metadata | fence.h | `kfree_rcu` + `call_rcu` | RCU | never |
| hwcnt backend bufs | `mali_kbase_hwcnt_backend_csf.c:2057-2090` | `:2133-2148` | term-only | never |
| TLSTREAM buffers | `tl/mali_kbase_timeline.c:191` | `vfree` term only | `streams_buf_lock` (safe in acquire) | never (but term-race, Finding 4) |
| fw_log dump_buf | `csf/mali_kbase_csf_firmware_log.c:281` | `:343` | `busy` atomic ✔ for readers, **NOT for term** (Finding 3) | rmmod only |
| **kctx debugfs → kctx** | context term | **UNPROTECTED** | **⚠ Finding 1** | **Y — deterministic** |
| io_history / ktrace / kinstr-client / `GET_GPUPROPS` buf | device lifecycle | term without waiting fds | none | unbind/rmmod-gated |

---

## 3. Ranked findings (detailed)

### Finding 1 — HIGH: per-kctx debugfs files dereference freed `kctx` after context close

Deterministic, no race. The full set of confirmed affected per-kctx debugfs nodes:

| Node | Created at | Reader deref |
|---|---|---|
| `mem_profile` | `mali_kbase_mem_profile_debugfs.c:84` | `:44-50` — `mutex_lock(&kctx->mem_profile_lock)` then `seq_write(sfile, kctx->mem_profile_data, ...)` |
| `infinite_cache` (0644 write) | `mali_kbase_core_linux.c:770` | `:586,600` |
| `force_same_va` (0600 write) | `mali_kbase_core_linux.c:772` | same |
| `mem_jit_{count,vm,phys,used,trim}` | `mali_kbase_mem.c:2542-2571` | `:2371, 2411-2426` `jit_evict_lock` taken on freed object; `data->kctx = inode->i_private` (`mali_kbase_mem.c:2346`) |
| per-ctx CSF (`kcpu_queues`, `cpu_queues`, `tiler_heaps`, `sync_objects`, `queue_groups`) | `mali_kbase_csf_kcpu_debugfs.c:149` etc. | each `single_open(file, show, in->i_private)` — show takes `kctx->csf.*` locks on freed memory |

**Lifecycle defect** (`mali_kbase_core_linux.c:343-347` → `context/backend/mali_kbase_context_csf.c:62-66, 81-84`):

```c
kbase_context_debugfs_term(kctx);   /* debugfs_remove_recursive — does NOT invalidate open fds */
kbase_destroy_context(kctx);        /* → vfree(kctx) */
```

**Why only 2 files are hardened:** `mali_kbase_debug_mem_view.c:259` (read-mode) and `mali_kbase_mem_migrate.c:443-450` acquire `get_file_active(&kctx->filp)`. The intent is known; the pattern is simply not applied to the rest of the family.

**Repro flow (see companion PoC):**

1. `open /dev/mali0` → `ioctl(KBASE_IOCTL_MEM_PROFILE_ADD)` (`_IOW(0x80, 27)`) creates `mem_profile` with `i_private = kctx` and attacker-supplied backing buffer, ≤ ~12 KiB, bounded.
2.privileged reader: `open /sys/kernel/debug/mali*/ctx/<tgid>_<id>/mem_profile` (root).
3. unprivileged `close()` of `/dev/mali0` → `vfree(kctx)`.
4. privileged `read()` → UAF lock / UAF `seq_write` from freed `vmalloc` region.

Impact: deterministic kali-crash DoS; with memory grooming (NOT included in PoC), an arbitrary kernel-read primitive across a privilege boundary — recorded here for the upstream report, deliberately not weaponized.

**Fix direction:** acquire `get_file_active(&kctx->filp)` at every per-kctx debugfs open, or ref-count kctx per open debugfs fd (mirroring `kbase_ctx_sched_retain_ctx_refcount` applied reader-lifetime-wide; must cover the JIT family and CSF per-ctx files, not only `mem_profile`).

### Finding 2 — LOW/latent: `kbase_vunmap()` type confusion

```c
ctx_ptr = kbase_vmap_prot(kctx, heap_gpu_va, ctx_alloc->heap_context_size_aligned, KBASE_REG_CPU_WR, &mapping);
...
kbase_vunmap(ctx_ptr, &mapping);        /* ← must be kbase_vunmap(kctx, &mapping) */
```

`csf/mali_kbase_csf_heap_context_alloc.c:57-67`. Only call site in the tree (of 16) that doesn't pass `kbase_context *`; compiles only because of `void*` conversion. Today inert because `kbase_vunmap_phy_pages` (`mali_kbase_mem_linux.c:3410-3444`) derefs `kctx` under 2 flag gates, and the heap-context region is never `BASE_MEM_CACHED_CPU`-mapped. Any future CPU-cache-flag enablement or ungated `kctx`-deref turns this into an OOB read + word-write. **Fix: one line.**

### Finding 3 — HIGH: `kbase_csf_firmware_log_term()` frees `dump_buf` without `fw_log->busy`

`csf/mali_kbase_csf_firmware_log.c:350-358` vs reader/worker (`:125-138`, `:374`). A reader that holds `busy=1` (stalled e.g. on MCU page fault in `read_data`) is not stopped by `cancel_delayed_work_sync` — `term()` frees the buffer under it: UAF write up to `FIRMWARE_LOG_DUMP_BUF_SIZE` + `copy_to_user` from freed memory. Variant: concurrent `mode_write` re-queues `poll_work` post-cancel → worker runs on freed `dump_buf` → NULL deref memcpy. Bonus: `poll_period_write` accepts unbounded `val`, `poll_period_ms=0` reschedules with zero delay → soft-lockup DoS (0644).

**Fix:** acquire `busy` in term before free, NULL-check in worker, bound period.

### Finding 4 — MEDIUM: `kbase_timeline` vfree with open TLSTREAM fds

`tl/mali_kbase_timeline.c:130-150` vs `tl/mali_kbase_timeline_io.c:246-457`. `.owner = THIS_MODULE` pins the module, not the device; rmmod while a TLSTREAM-acquire fd is open leaves release/read/poll/fsync/call various derefs on `vzalloc`-free'd memory. No `.mmap` on the TLSTREAM fops in this tree — hence UAF read/poll only. **Fix: refcount timeline per fd (or deferred term until last fd closes).**

### Finding 5 — LOW/latent: post-lock-drop status data read

`mali_kbase_mem_migrate.c` — reads under `migrate_lock` (`:700-723`) but `data.mapped.kctx_id` / `data.pt_mapped.kctx_id` (`:746`, `:750`) read after `:725` drop. Safe today only via the "isolated pages always return via migrate/putback" contract (`mmu/mali_kbase_mmu.c:2318-2330`); any new state breaks it into a UAF read of `kctx_id` feeding a wrong-context `fput`/`get_file`. **Fix: copy status + data under one locked read.**

### Finding 6 — MEDIUM: device teardown vs in-flight ioctls

1. `GET_GPUPROPS` in-flight ioctl vs free (`mali_kbase_gpuprops.c:915-918`, race from `:1707` dispatch with no device ref held in the ioctl.
2. `io_history` reader vs `kbase_io_history_term` (`mali_kbase_io.c:181-185`, comment explicitly says "no need to lock" — it does during term).
3. `ktrace` reader vs `kbase_ktrace_term` (`debug/mali_kbase_debug_ktrace.c:43-51`).
4. `kinstr_prfcnt` client destruction vs reader (`mali_kbase_kinstr_prfcnt.c:1330-1346` — the *ring-buffer mmap* is `vm_file`-anchored, the client struct is not).
5. Timeline autoflush timer armed past `vfree` of `timeline` (`tl/mali_kbase_timeline.c`).

**Fix:** per-subbug devfd anchor + `del_timer_sync`/`flush_work` before term (cheap changes).

---

## 4. Cleared / non-findings (do not re-walk these)

From the 7-audit campaign — refuted-integer standard:

- **`kbase_context_sticky_resource_term` cookie teardown (`context/mali_kbase_context.c:364-390`)** — only frees *parked* regions; consumed cookies are NULLed under `reg_lock`; mmap (`mali_kbase_mem_linux.c:2703,2717,2751`) and free (`mali_kbase_mem.c:1085-1099`) are disjoint states of a single-owner state machine; VMA holds `vm_file` so `kbase_release` cannot interleave. **No UAF/double-free.** — This is the direct refutation of the rev-1 PoC plan's Candidate 1.
- **JIT bins / destroy worker / backing-lost shuffles** — `reg_lock`→`jit_evict_lock` ordering consistent.
- **Tiler-heap OOM 3-phase revalidation / reclaim / chunk frees** — NO_USER_FREE regions + 3-phase re-lookup under `tiler_heaps.lock`+`scheduler.lock`.
- **KCPU enqueue/delete** — upstream-hardened asymmetric lock pattern.
- **`user_buf` import state machine / dma-buf import / pin/unpin** — full state machine verified, mgrab/mmdrop matched.
- **MMU async fault workers** — IPC retain at `mmu/backend/mali_kbase_mmu_csf.c:71-92,571`; release at `mmu.c:1405`/`mmu_csf.c:538`; `as_to_ctx[]` only cleared at refcount 0; `destroy_workqueue` drains.
- **Fences / dma-sync** — RCU-protected metadata, no kctx pointer in `struct kbase_kcpu_dma_fence` at all.
- **Mali csf_fault** — `kbdev->csf.dof` holds scalars only, `atomic_cmpxchg` single-client seat → structurally UAF-immune today. Caution: don't add pointer fields without an anchored lifetime.
- **MEM_PROFILE_ADD ioctl producer** — bounded (≤ ~12 KiB), lock-serialised, no signed/overflow.
- **as_fault debugfs** — 0444, no fault-sim write path.
- **IPA control / coresight / TL reader cached pointers / trace buffers** — no userspace-triggerable fw unload/reload in-tree; `firmware_inited`-gated; `destroy_workqueue`-drained.
- **reg_track** (rbtree region walk + `kctx->reg_lock` covering term) — no race.
- **Timeline acquire/release cycles** — client-ref-safe; TLSTREAM buffers freed only at term (Finding 4 covers the residual).

---

## 5. Why the rev-1 PoC plan (`mali-uaf-poc-plan.md`) was refuted

The plan's Candidate 1 expected a `kbase_va_region` UAF via `kbase_context_sticky_resource_term`'s raw `kfree` of pending regions, racing a concurrent `mmap`/VMA-close against context teardown. Disproven by:

1. teardown loop only frees cookies in the **unmapped** pending set (`bitmap_andnot(KBASE_COOKIE_MASK, ~kctx->cookies)`), while mmap (`mali_kbase_mem_linux.c:2703,2717,2751`) clears `pending_regions[cookie]` before bumping `va_refcnt` — the two free paths can never reach the same region.
2. cookie PM alloc + mmap + MEM_FREE are all under `kbase_gpu_vm_lock` — no interleave window.
3. VMA holds `vm_file` → `kbase_release` runs deferred past VMA point.
4. Minor: `BASE_MEM_DONT_NEED` isn't an alloc flag here; slab/GFCs don't match plan's assumptions.

Replaced by the corrected plan file (`/home/za0x/.opencode/plan/mali-uaf-poc-plan.md`, rev 2) — which simply became this report + the companion crash-only PoC.

---

## 6. Disclosure posture & next steps

- **PoC is crash-only,** uses only in-tree ioctls / debugfs, and contains zero privilege-escalation payload — consistent with the standard practice for coordinated disclosure.
- **Do not run against production kernels** — use a dedicated KASAN/UBSAN build; the crash can take the machine down on `vmalloc`-UAF mutex-take.
- **Submit via [ARM's PSIRT channel](https://developer.arm.com/support/arm-security-advisories)** with each finding as an independent report; the fastest fix is Finding 2's one-liner; the most substantive is Finding 1's family-wide `get_file_active` anchoring.

---

## 7. File inventory in this folder

| File | Purpose |
|---|---|
| `GLM-repport.md` | **this document** — consolidated audit + findings + refutation |
| `mali-r56p0-uaf-report.md` | trimmed per-finding upstream report |
| `poc_debugfs_kctx_uaf.c` | crash-only deterministic KASAN PoC |
| `poc.c` / `reference.md` | pre-existing rev-1 artifacts from the refuted plan |
| `qemu-test/` | **complete QEMU test env** — kernel+DDK builds, verbose-debug PoC (`poc_debugfs_kctx_uaf_debug.c`), initramfs attach script, full-log capture + KASAN classifier (see its README) |
