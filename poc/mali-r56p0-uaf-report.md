# ARM Mali CSF Kernel Driver r56p0 — Memory-Safety Findings Report

**Source set:** `AX504X08X-SW-99002-r56p0-18ea` (`driver/product/kernel/drivers/gpu/arm/midgard`)
**Classification:** Coordinated-disclosure draft for ARM PSIRT / Mali kernel-driver maintainers
**Method:** Full source audit (7 independent review passes over the CSF core, scheduler, memory lifecycle, ioctl dispatch, MMU, hwcnt, TL, blind-spot set) + verified crash-only reproduction.
**Disclosure posture:** Follows the standard practice for driver-level input validation bugs: reproduction is deterministic, uses only in-tree ioctls/debugfs, and the PoC performs **no** privilege escalation. No weaponization is included or planned.

---

## Executive summary

The r56p0 release is meaningfully hardened versus older Mali lines — refcounted queues/groups/heaps, RCU fence metadata, refcounted MMU fault workers, `firmware_inited` gating, `get_file_active` hardening *where applied*. We found **no unprivileged ioctl-reachable UAF** in the callable core.

However, the **per-kctx debugfs layer is systematically unanchored** and yields a deterministic use-after-free on `struct kbase_context` after `close(/dev/maliN)`, reproducible with four syscalls and no race. Two other teardown races and two latent defects complete the set. All are root/privileged-edge *as gated above debugfs*, but several are reachable across a privilege boundary when, per the file permissions used, the reader is privileged and the closer is not — the same pattern ARM itself recognized elsewhere (2 files already hardened).

| # | Finding | Severity (indicative) | Gated by |
|---|---------|----------------------|----------|
| 1 | Per-kctx debugfs `i_private → kctx` UAF family | High (root↔kernel, deterministic, attacker-shaped payload possible via MEM_PROFILE_ADD) | debugfs perms |
| 2 | `kbase_vunmap(ctx_ptr, &mapping)` type confusion | Low today; latent trap | config-inert |
| 3 | `kbase_csf_firmware_log_term` vs `fw_log->busy` | High (root; loader-teardown race, UAF write ≥64 KiB) | debugfs+rmmod |
| 4 | `kbase_timeline` vfree vs open TLSTREAM fds | Medium (rmmod-gated UAF) | device teardown |
| 5 | `page_md->data` post-lock-drop read in page migration | Low (compile-gated latent) | `CONFIG_MALI_PAGE_MIGRATION` |
| 6 | Device-teardown vs in-flight ioctls (GET_GPUPROPS, io_history, ktrace, kinstr client, autoflush timer) | Medium (root) | unbind/rmmod |

---

## Finding 1 (High): per-kctx debugfs files dereference freed `kctx` after context close

**Class:** CWE-416 `use-after-free`, deterministic, no race.

**Oracle files (all confirmed by direct source inspection):**

| Debugfs node | Created at | Reader deref of freed kctx |
|---|---|---|
| `mem_profile` | `mali_kbase_mem_profile_debugfs.c:84` | `:44-50` — `mutex_lock(&kctx->mem_profile_lock)`, then `seq_write(sfile, kctx->mem_profile_data, kctx->mem_profile_size)` |
| `infinite_cache` (0644 write) | `mali_kbase_core_linux.c:770` | `:586,600` — write path reads `kctx` then sets `KCTX_INFINITE_CACHE` on freed ctx |
| `force_same_va` (0600 write) | `mali_kbase_core_linux.c:772` | same pattern |
| `mem_jit_{count,vm,phys,used,trim}` | `mali_kbase_mem.c:2542-2571` | `:2371, 2411-2426` — `kctx->jit_evict_lock` taken on freed memory; `data->kctx = inode->i_private` established at open (`mali_kbase_mem.c:2346`) |
| `kcpu_queues`, `cpu_queues`, `tiler_heaps`, `sync_objects`, `queue_groups` (per-ctx CSF) | `mali_kbase_csf_kcpu_debugfs.c:149` etc. | each `single_open(file, show, in->i_private)` — show path takes `kctx->csf.kcpu_queues.lock` / `kctx->csf.lock` / `tiler_heaps.lock` on the freed object |

**Life-cycle defect (`mali_kbase_core_linux.c:343-347` → `context/backend/mali_kbase_context_csf.c:62-66, 81-84`):**

```c
/* kbase_file_delete (device fd release) */
kbase_context_debugfs_term(kctx);   /* debugfs_remove_recursive(kctx->kctx_dentry) */
kbase_destroy_context(kctx);        /* ... eventually vfree(kctx) */
```

`debugfs_remove_recursive()` removes dentries but **does not invalidate already-open file handles** — those handles keep `f_private → kctx`, and any subsequent `read()`, and in 0644/0600 cases also `write()`, dereferences (including mutex-taking inside) the vfree'd `vmalloc` region.

**Why only 2 of ~12 files are hardened:** `mali_kbase_debug_mem_view.c:259` (read mode) and `mali_kbase_mem_migrate.c:443-450` acquire `get_file_active(&kctx->filp)`. ARM clearly knows the pattern; it is simply not applied to the other files.

**Attacker shape (from the disclosure PoC, `disclosure/poc_debugfs_kctx_uaf.c`):**

1. Unprivileged GPU user (or any local process; unprivileged is fine here for *creation*)
   `open(/dev/mali0)` → `ioctl(KBASE_IOCTL_MEM_PROFILE_ADD, {buffer=ctrl-data, len=≤12 KiB})` (kbase ioctl `_IOW(0x80, 27)`) — the payload/injection point is caller-controlled.
2. Any *privileged reader session* (root can be local victim, daemon, or aggregator script):
   `open(/sys/kernel/debug/mali*/ctx/<tgid>_<id>/mem_profile, O_RDONLY)`.
3. The unprivileged user `close()`s `/dev/mali0` → `kbase_release` → vfree(`kctx`).
4. The privileged reader's next `read()` runs on the freed object.

**Impact:**
- Denial-of-service: immediate mutex-lock-into-freed-vmalloc crash (stable).
- Cross-privilege boundary: `mem_profile_data` is caller-supplied (via Step 1 ioctl); with page-specific grooming, freed `kctx` pages back with attacker source data → the *root-side* `seq_write` is redirected — a clean arbitrary-kernel-read primitive into a root-readable buffer, i.e. kernel-integrity escalation privilege boundary *cross-over* by the unprivileged closer. We do NOT include the exploit chain — the disclosure PoC is crash-only.
- Same class covers all listed files; the fix must cover the family, not just `mem_profile`.

**Fix direction:**
- Acquire `get_file_active(&kctx->filp)` in every per-kctx debugfs open (mirroring `debug_mem_view:259`), OR hold a per-open kctx refcount (e.g. `kbase_ctx_sched_retain_ctx_refcount`) around the debugfs open's lifetime, dropping it at release.
- Alternatively, stop allocating per-kctx debugfs open handles with raw `i_private == kctx` and switch to `debugfs_lookup` + registered-reader pattern (`debugfs_file_get()` hardening) matching upstream practice.

---

## Finding 2 (Low/latent): `kbase_vunmap()` type-confused argument at heap-context allocation teardown

**`csf/mali_kbase_csf_heap_context_alloc.c:57-67`:**

```c
ctx_ptr = kbase_vmap_prot(kctx, heap_gpu_va, ctx_alloc->heap_context_size_aligned,
                          KBASE_REG_CPU_WR, &mapping);
...
memset(ctx_ptr, 0, ctx_alloc->heap_context_size_aligned);
kbase_vunmap(ctx_ptr, &mapping);      /* ← WRONG: should be kbase_vunmap(kctx, &mapping) */
```

`kbase_vunmap(struct kbase_context *kctx, struct kbase_vmap_struct *)` (`mali_kbase_mem_linux.h:380`) is the **only** caller in the tree (out of 16) that passes something other than a `kbase_context *`; it compiles only because of `void*` conversion.

Today this is inert: `kbase_vunmap_phy_pages` (`mali_kbase_mem_linux.c:3410-3444`) only derefs `kctx` under 2 flag gates and this region is allocated without `BASE_MEM_CACHED_CPU` flags (`csf/mali_kbase_csf_heap_context_alloc.c:185-204`), so both `KBASE_VMAP_FLAG_SYNC_NEEDED` and `KBASE_VMAP_FLAG_PERMANENT_MAP_ACCOUNTING` paths stay dead. However:

- If any future change enables CPU-cached heap-context pages, or adds an ungated `kctx`-deref to the unmap path, this becomes a spontaneous kernel read + word-write (`atomic_sub` at offset ~`sizeof(kbase_context)` into whatever memory the vmap'd pointer targets).
- 16/16 other call sites use the correct signature — this one is a one-line contract violation with a security-relevant failure mode.

**Fix:** `kbase_vunmap(kctx, &mapping);` (trivial).

---

## Finding 3 (High, root/teardown-gated): `kbase_csf_firmware_log_term()` frees `dump_buf` without taking `fw_log->busy`

**`csf/mali_kbase_csf_firmware_log.c:350-358`** (teardown) vs reader/worker (`:125-138`, `:374`):

```c
/* teardown */
cancel_delayed_work_sync(&fw_log->poll_work);   /* does NOT acquire busy, does NOT wait for it */
kfree(fw_log->dump_buf);
```

```c
/* reader */
if (atomic_cmpxchg(&fw_log->busy, 0, 1) != 0) return -EBUSY;    /* :125 */
n_read = kbase_csf_firmware_trace_buffer_read_data(tb, fw_log->dump_buf, mem);  /* :135 */
not_copied = (n_read) ? copy_to_user(buf, fw_log->dump_buf, n_read) : 0;       /* :138 */
```

A reader that has set `busy=1` and stalls (e.g. page-fault on the MCU-mapped trace buffer inside `trace_buffer_read_data`) is not stopped by `cancel_delayed_work_sync`, and `kbase_csf_firmware_log_term` frees the buffer out from under it: UAF write of up to `FIRMWARE_LOG_DUMP_BUF_SIZE` bytes into the reclaimed slab plus `copy_to_user` from it.

**Trigger:** `kbase_csf_firmware_unload_term()` → invoked from the loader failure path (`csf/mali_kbase_csf_firmware.c:2819`) or device unbind (`device/backend/mali_kbase_device_csf.c:58-67`) **while a `fw_traces` debugfs fd is open** (0444, needs root to read).

**Variant (same file):** a concurrent `mode_write` (`:181`) can re-queue `poll_work` after `cancel_delayed_work_sync` has already returned and before `kfree`: the worker then runs with `dump_buf == NULL` and memcpy's into NULL (`:384`). Additional robustness bug: `kbase_csf_firmware_log_poll_period_write` (`:206-213`) accepts an arbitrary `val` with no bounds check — `poll_period_ms = 0` reschedules the worker at zero delay (soft-lockup DoS; 0644 debugfs).

**Fix:** acquire `busy` (or a dedicated term mutex) in `kbase_csf_firmware_log_term()` before free; NULL-check `dump_buf` in the poll worker; bound `poll_period_ms`.

---

## Finding 4 (Medium, root/teardown-gated): `kbase_timeline` is vfree'd with TLSTREAM-open file handles still attached

**`tl/mali_kbase_timeline.c:130-150`** (term) vs in-flight ops **`tl/mali_kbase_timeline_io.c:246-457`**:

```c
/* term: no refcount against open fds */
for (i = 0; i < TL_STREAM_TYPE_COUNT; i++) { vfree(timeline->streams[i].buffer); ... }
vfree(timeline);

/* release on an already freed timeline: */
446: kbase_timeline_release(filp->private_data);   /* :252-262 derefs freed struct */
```

`anon_inode_getfd` fops pin the module (`.owner = THIS_MODULE`) but not the device object; the acquire/release cycles keep the same `kbdev->timeline` alive across device unbind (`kbase_device_term_partial → kbase_device_firmware_hwcnt_term` path), leaving release/read/poll/fsync running on `vzalloc`-free'd memory.

**Trigger:** device unbind/rmmod while a process holds a TLSTREAM-acquired anon-inode fd (`KBASE_IOCTL_TLSTREAM_ACQUIRE`) or the debugfs `tlstream` (timeline) file was opened.

**Note:** there is **no user-mapped stream buffer** in this tree (no `.mmap` fop on the TLSTREAM file), so the observable primitives are UAF read/poll/fsync + the timer callback touching a freed struct.

**Fix:** refcount `timeline` per open TLSTREAM fd (or defer `kbase_timeline_term` until the last fd closes, mirroring the fix pattern used elsewhere).

---

## Finding 5 (Low, latent): `kbase_page_migrate` reads `page_md->data` after dropping `migrate_lock`

**`mali_kbase_mem_migrate.c`** — status word is read under `migrate_lock` (locked read at `:700-723`), but `data.mapped.kctx_id` (`:746`) and `data.pt_mapped.kctx_id` (`:750`) are read **after** the lock has been dropped (`:725`).

Correct-by-construction today thanks to a non-local invariant: pages must transition `ALLOCATED_MAPPED → FREE_ISOLATED_IN_PROGRESS` on teardown with metadata explicitly retained (via `mmu/mali_kbase_mmu.c:2318-2330`) and reclaimed later by `kbase_page_migrate` / `kbase_page_putback`. That contract is honored, but it is fragile: any new state that allows metadata-free concurrent to the post-drop read collapses into a UAF read of `kctx_id` — feeding a wrong-context `fput`/`get_file`.

**Fix:** copy the status word *and* its `data.*` fields under one `migrate_lock` critical section.

---

## Finding 6 (Medium, root/teardown-gated): device teardown frees kbdev-scoped objects with fds/work in flight

Sub-bugs (each independently reportable):

1. **GET_GPUPROPS in-flight ioctl UAF** — `mali_kbase_gpuprops.c:915-918` frees `kprops->prop_buffer`; per-ioctl there is no device ref held for the duration of the ioctl, so rmmod during a large `copy_to_user` races the free (`mali_kbase_core_linux.c:1707` dispatch path).
2. **io_history reader UAF** — `mali_kbase_io.c:181-185` frees `h->buffer` without acquiring the lock an open reader's `seq_show` would hold (comment explicitly says "no need to lock" — it does during term).
3. **ktrace reader UAF** — `debug/mali_kbase_debug_ktrace.c:43-51` vfrees the buffer without `ktrace.lock`, against an open reader copying the pointers into `seq_file` under that lock at `:363-367`.
4. **kinstr_prfcnt client destruction UAF** — `mali_kbase_kinstr_prfcnt.c:1330-1346` walks the client list and `kfree`s while a `KBASE_IOCTL_KINSTR_PRFCNT_SETUP`-acquired anon-inode fd still references the client struct; only the *mmap'd ring buffer* is `vm_file`-anchored, the client struct itself is not.
5. **Autoflush timer UAF** — `tl/mali_kbase_timeline.c:130-150` (same teardown) leaves `autoflush_timer` potentially armed when `timeline` is vfreed; timer teardown exists only in `kbase_timeline_release` (`:273-280`), which the remove path does not run.

**Fix direction:** take a devfd/refcount per still-live sub-consumer at `kbase_platform_device_remove` (`mali_kbase_core_linux.c:4630-4646`), or del_timer_sync/flush_work surgically before each term step (cheap per-finding change).

---

## Cleared / non-findings (recorded to avoid re-litigation)

These areas were audited to a *refuted-hypothesis* standard; a future pi re-review can start from them rather than redo them.

- **`kbase_context_sticky_resource_term` cookie/default teardown (`context/mali_kbase_context.c:364-390`)** — only freed parked regions; consumed cookies are NULLed unbiasedly under `reg_lock`; mmap path (`mali_kbase_mem_linux.c:2703,2717,2751`) and free path (`mali_kbase_mem.c:1085-1099`) are disjoint states of a single-owner region state machine; VMAs hold `vm_file` so `kbase_release` cannot interleave. No UAF / double-free.
- **JIT bins / destroy worker / backing-lost shuffles** — `reg_lock` → `jit_evict_lock` ordering is consistent; `kbase_jit_backing_lost` is list-shuffle-only.
- **Tiler-heap OOM 3-phase revalidation, reclaim, chunk frees** — NO_USER_FREE regions; 3-phase re-lookup under `tiler_heaps.lock` + `scheduler.lock`; correct-by-construction.
- **KCPU queue enqueue/delete asymmetric-lock UAF** — upstream-hardened shape (re-check under same lock, `cnt`-drain, fence timer_sync).
- **`user_buf` import state machine, dma-buf import/attach, page pinning** — full state machine verified, mgrab/mmdrop matched.
- **MMU async fault-work pipeline** — IRQ workers take `kbase_ctx_sched_retain_ctx_refcount` at `mmu/backend/mali_kbase_mmu_csf.c:71-92/571`; `as_to_ctx[]` cleared only at refcount 0; `destroy_workqueue` drains; no stale-pointer window.
- **Fences / dma-sync-file** — metadata is RCU-protected (`kfree_rcu`, `call_rcu`); no kctx pointer in fence metadata at all.
- **`Mali csf_fault` (dump on fault)** — `kbdev->csf.dof` holds **scalars only** (no pointer fields); single-client gate via `atomic_cmpxchg`; structurally UAF-immune today. Caution: do not add pointer fields without an anchored lifetime.
- **MEM_PROFILE_ADD ioctl itself** — bounded (≤ ~12 KiB), lock-serialized, no signed/overflow issue (the *debugfs reader* lifetime is Finding 1; the producer ioctl is clean).
- **as_fault debugfs** — read-only, no fault-simulation write path in this release.
- **IPA control, coresight, csf TL reader cached pointers, trace buffers** — no userspace-triggerable fw unload/reload in-tree; further derefs are `firmware_inited`-gated or `destroy_workqueue`-drained.
- **`kbase_reg_track`, timeline acquire/release cycles** — kbdev-scoped, no user-triggerable free.

---

## Reproduction

Crash-only PoC: `disclosure/poc_debugfs_kctx_uaf.c` (see build/run instructions in its header). Expected KASAN output: `slab-use-after-free READ` in `seq_write`/`mutex_lock` stack, `freed by` → `vfree(kctx)` in `kbase_context_free`. Not safe to run against production kernels; use a dedicated KASAN build.

---

## Suggested response matrix for upstream

| Finding | Suggested priority | Effort | Notes |
|---|---|---|---|
| 1 | High | Medium-fix | Extend `get_file_active` to every per-kctx fops; hardest is the JIT family where the open-time context struct is stored wholesale |
| 2 | Immediate | Trivial | 1-line signature fix |
| 3 | Medium | Trivial | acquire `busy` in term + NULL-check worker + bound period |
| 4 | Medium | Medium | refcount timeline per fd |
| 5 | Low | Trivial | copy `data` under lock |
| 6 | Medium | Medium | per-sub-bug: devfd anchor + del_timer_sync/flush ordering |
