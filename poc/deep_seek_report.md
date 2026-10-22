# ARM Mali CSF r56p0 — Deep Seek Report

**Memory-management deep analysis and exploitation assessment**

**Source set:** `AX504X08X-SW-99002-r56p0-18eac0`
(`driver/product/kernel/drivers/gpu/arm/midgard`)

**Parent document:** `mali-r56p0-uaf-report.md` (findings 1–6)

**Scope of this report:** a second, source-level pass focused specifically on the
memory-management layer — memory pools, physical-page allocation, UMM/dma-buf import,
JIT growth, region tracking, MMU teardown, and the debugfs knobs that expose those
objects. It records new defects, corrections to the parent report, hypotheses that were
examined and refuted, and an assessment of what the resulting primitives are (and are
not) worth.

**Disclosure posture:** unchanged. This document contains no weaponized exploit and no
privilege-escalation chain. The existing crash-only PoC is not modified. The original
report and PoC were left untouched.

---

## 1. Summary of new results

| ID | Result | Severity (indicative) | Gate / precondition | Relationship to parent report |
|----|--------|----------------------|---------------------|-------------------------------|
| A | Per-kctx **and** device-scope memory-pool debugfs files keep raw pointers into a `vfree()`'d `kbase_context` / `kbase_device`; the per-kctx files include write handlers that can drive `list_del_init()` and page freeing | High as a UAF; write primitive conditional | debugfs write permission + context close (per-kctx) or unbind/rmmod (device-scope) | New member of Finding 1; also a concrete sub-case of Finding 6 |
| B | Padded UMM teardown feeds `KBASE_INVALID_PHYSICAL_ADDRESS` sentinels to the GPU `FLUSH_PA_RANGE` command | Low–Medium (DoS/robustness; platform-dependent) | dma-buf import with non-zero padding, `arch_major > 11`, small region | New |
| C | `kbase_jit_grow()` does not roll back physical pages or `nents` when `kbase_mem_grow_gpu_mapping()` fails after allocation | Low (functional/accounting) | MMU insert failure after successful page allocation | New |
| D | Unchecked `find_next_zero_bit()` result in the partial-2 MiB-page allocator can index bit 512 | Latent (invariant-dependent) | Requires a broken partial-list invariant | New note |
| E | Evictable-unmake error path marks the allocation un-evicted and clears `DONT_NEED` even when backing/mapping failed | Low (silent state corruption) | Allocation or mapping failure | New note |
| F | Parent report overstates the `mem_profile` arbitrary-read primitive: the payload is freed and the pointer/size are cleared before `kfree`/`vfree` of the context | Correction | Requires reclamation with controlled bytes **and** a kernel address | Corrects Finding 1 |

The headline result is **A**: the mem-pool debugfs family is a new, largely overlooked
set of unanchored handles over memory-management state, and unlike the previously listed
oracles it contains a write path that reaches list manipulation and page freeing rather
than just flag bits or a `seq_write`.

---

## 2. Finding A — memory-pool debugfs handles are unanchored and include a write path

### 2.1 Lifecycle: the same defect as Finding 1, but over `mem_pools`

Per-context debugfs is created in `kbase_api_setup_context()` immediately after the
context exists:

```c
/* mali_kbase_core_linux.c:758-776 */
kctx->kctx_dentry = debugfs_create_dir(kctx_name, kbdev->debugfs_ctx_directory);
...
kbase_context_debugfs_init(kctx);
```

The CSF backend then creates the memory-pool files:

```c
/* context/backend/mali_kbase_context_csf.c:46-59 */
void kbase_context_debugfs_init(struct kbase_context *const kctx)
{
        ...
        kbase_mem_pool_debugfs_init(kctx->kctx_dentry, kctx);
        ...
}
```

Teardown removes the dentries but does not invalidate already-open file handles:

```c
/* context/backend/mali_kbase_context_csf.c:62-65 */
void kbase_context_debugfs_term(struct kbase_context *const kctx)
{
        debugfs_remove_recursive(kctx->kctx_dentry);
}
```

The context is `vzalloc()`'d and later `vfree()`'d:

```c
/* context/backend/mali_kbase_context_csf.c:81-86, 134 */
static void kbase_context_free(struct kbase_context *kctx)
{
        kbase_timeline_post_kbase_context_destroy(kctx);
        vfree(kctx);
}
...
kctx = vzalloc(sizeof(*kctx));
```

An open debugfs file's `single_open()` has already copied the raw `i_private` pointer
into its `seq_file`. Nothing in `debugfs_remove_recursive()` reaches back into that
`seq_file`, so the handle survives the `vfree()`.

### 2.2 The new files

`kbase_mem_pool_debugfs_init()` creates four files per context, all with mode `0644`:

```c
/* mali_kbase_mem_pool_debugfs.c:153-177 */
const mode_t mode = 0644;

debugfs_create_file("mem_pool_size",      mode, parent, &kctx->mem_pools.small, ...);
debugfs_create_file("mem_pool_max_size",  mode, parent, &kctx->mem_pools.small, ...);
debugfs_create_file("lp_mem_pool_size",   mode, parent, &kctx->mem_pools.large, ...);
debugfs_create_file("lp_mem_pool_max_size", mode, parent, &kctx->mem_pools.large, ...);
```

The `i_private` values are interior pointers into the `kbase_context` block
(`struct kbase_mem_pool_group mem_pools`, `mali_kbase_defs.h:1856`). The open handlers
capture them:

```c
/* mali_kbase_mem_pool_debugfs.c:96-110 */
static int kbase_mem_pool_debugfs_open(struct inode *in, struct file *file)
{
        return single_open(file, kbase_mem_pool_debugfs_size_show, in->i_private);
}
...
err = kbase_debugfs_helper_seq_write(file, ubuf, count,
                                     MEMORY_GROUP_MANAGER_NR_GROUPS,
                                     kbase_mem_pool_debugfs_trim);
```

`MEMORY_GROUP_MANAGER_NR_GROUPS` is 16
(`driver/product/kernel/include/linux/memory_group_manager.h:33`), so a write can address
any of the 16 small or 16 large pools. The write parser is bounded to 256 bytes
(`mali_kbase_debugfs_helper.c:32, 186-223`), which is more than enough for one or all 16
values.

Unlike `mem_profile` (0444) and the two existing per-kctx write files (`infinite_cache`,
`force_same_va`, which only touch flag bits), these files drive the actual memory-pool
state machine.

### 2.3 What the write path does

There are two callbacks:

```c
/* mali_kbase_mem_pool_debugfs.c:28-46 */
kbase_mem_pool_trim(&mem_pools[index], value);
kbase_mem_pool_set_max_size(&mem_pools[index], value);
```

`kbase_mem_pool_trim()`:

```c
/* mali_kbase_mem_pool.c:749-772 */
cur_size = kbase_mem_pool_size(pool);          /* READ_ONCE(pool->cur_size) */
if (new_size > pool->max_size)
        new_size = pool->max_size;
if (new_size < cur_size)
        kbase_mem_pool_shrink(pool, cur_size - new_size);
else if (new_size > cur_size)
        err = kbase_mem_pool_grow(pool, new_size - cur_size, NULL);
```

`kbase_mem_pool_set_max_size()`:

```c
/* mali_kbase_mem_pool.c:775-791 */
spin_lock(&pool->pool_lock);
pool->max_size = max_size;
cur_size = kbase_mem_pool_size(pool);
if (max_size < cur_size)
        kbase_mem_pool_shrink_locked(pool, cur_size - max_size);
spin_unlock(&pool->pool_lock);
```

Both shrink paths reach `kbase_mem_pool_shrink_locked()` and then
`kbase_mem_pool_remove_locked()`:

```c
/* mali_kbase_mem_pool.c:662-678 */
for (i = 0; i < nr_to_shrink && !kbase_mem_pool_is_empty(pool); i++) {
        p = kbase_mem_pool_remove_locked(pool, FREE_IN_PROGRESS);
        kbase_mem_pool_free_page(pool, p);
}

/* mali_kbase_mem_pool.c:537-564 */
p = list_first_entry(&pool->page_list, struct page, lru);

if (!pool->order && kbase_is_page_migration_enabled()) {
        struct kbase_page_metadata *page_md = kbase_page_private(p);
        spin_lock(&page_md->migrate_lock);
        ...
}

list_del_init(&p->lru);
pool->cur_size--;

return p;
```

and finally `kbase_mem_pool_free_page()`, which dereferences the pool's device and
memory-group-manager callbacks:

```c
/* mali_kbase_mem_pool.c:632-660 */
kbdev = pool->kbdev;
...
dma_unmap_page(kbdev->dev, dma_addr, ..., DMA_BIDIRECTIONAL);
kbdev->mgm_dev->ops.mgm_free_page(kbdev->mgm_dev, pool->group_id, p, pool->order);
```

The grow path is equally pointer-heavy: `kbase_mem_pool_grow()` → `kbase_mem_alloc_page()`
dereferences `pool->kbdev`, `kbdev->dev`, and
`kbdev->mgm_dev->ops.mgm_alloc_page` (`mali_kbase_mem_pool.c:578-620`).

### 2.4 Primitive assessment

A stale file handle therefore gives a privileged writer a **fake `struct kbase_mem_pool`**
inside the freed context block. Assuming the block has been reused or is otherwise
readable/writable, the most direct trigger is one write to `mem_pool_max_size`:

1. `pool->pool_lock` is read from the stale block and used as a spinlock.
2. `pool->max_size = 0` (or any value) is written to the stale block.
3. `pool->cur_size` is read; if non-zero, `kbase_mem_pool_shrink_locked()` runs.
4. `pool->page_list.next` is turned into a `struct page *` by `list_first_entry()`.
5. `list_del_init(&p->lru)` performs the classic unlink — two pointer writes
   (`next->prev = prev` and `prev->next = next`) — then re-initialises `p->lru` to point
   at itself (two more writes to the fake page).
6. `kbase_mem_pool_free_page()` dereferences the fake `pool->kbdev`, then the fake
   `mgm_dev->ops.mgm_free_page` or the migration/free-later path.

If the freed `kbase_context` block is reclaimed with attacker-controlled bytes (for
example a same-size `vmalloc_user()` allocation that userspace can write through its
mapping), the attacker controls `cur_size`, `page_list`, `order`, `dying`, `pool_lock`,
and `kbdev`. That yields a **write-then-crash** primitive: the unlink pointer writes,
followed by a very likely fault when the fake `kbdev`/page metadata is dereferenced.
Making it a clean, continuing arbitrary write requires the fake `kbdev` (or the fake page
metadata) to point at valid kernel memory, which in turn requires a kernel address
disclosure and careful object selection.

Two important qualifiers keep this from being a turnkey exploit:

- **Address knowledge.** `list_del_init()` writes *addresses supplied by the fake list
  nodes*, not arbitrary bytes. To point `page_list.next` at the controlled reclaimer on a
  normal 64-bit kernel with PAN/SMAP, the attacker must know the reclaimer's kernel
  virtual address. Without a vmalloc/KASLR disclosure, the practical outcome is a crash
  rather than a controlled write. On configurations without user-access prevention (some
  32-bit ARM kernels), `page_list.next` can instead point at a userspace-mapped fake
  `struct page`; that removes the reclaimer-address requirement, but the unlink targets
  and a plausible `kbdev` still have to be known.
- **Post-unlink dereference.** The unlink happens before `kbase_mem_pool_free_page()`,
  but the subsequent `pool->kbdev` dereference is not optional. A fake object that does
  not also provide a plausible `kbdev` will fault immediately after the write.

The honest characterization is therefore: **deterministic UAF, reliable DoS, and a
constrained fake-object write/free/indirect-call primitive that becomes dangerous when
combined with an address leak or when the stale handle aliases a live context.** It is
not, by itself, an unprivileged arbitrary-write primitive.

### 2.5 The pristine freed block is mostly inert — reuse is what activates it

This detail matters for triage and for avoiding an overstatement:

`kbase_mem_pool_group_term()` (`mali_kbase_mem_pool_group.c:78-88`) calls
`kbase_mem_pool_term()` for every pool. That function sets `pool->max_size = 0`
(`mali_kbase_mem_pool.c:943`) and drains the pool until `cur_size == 0`
(`:980-999`). A normal `vfree()` then unmaps the range, so a stale access before reuse
faults rather than observing those zeros. If the range is remapped without meaningful
re-initialisation (or is accessed through a KASAN-instrumented path that reports before
the fault), the zeroed post-term state means:

- `trim(pool, value)` clamps `value` to `max_size == 0`, sees `cur_size == 0`, and does
  nothing;
- `set_max_size(pool, value)` can still write `max_size` into the remapped block, but
  `cur_size == 0` means no shrink and no list walk;
- the read handlers return zeros.

The dangerous cases are therefore:

1. **Reuse by a different `kbase_context` of the same size.** Vmalloc is first-fit; a
   subsequent context allocation is a strong candidate for the same virtual range. The
   stale handle now aliases the new context's `mem_pools` at the identical offset. A
   privileged writer can grow, shrink, or re-limit another process's pool. This is
   cross-context resource manipulation and a memory-pressure/DoS vector; the pages being
   freed are genuinely free pages of that pool, so this is not by itself memory
   corruption.
2. **Reuse by an attacker-controlled vmalloc object.** This is the fake-object case in
   §2.4, and is the only route to the list-unlink primitive.
3. **Reuse by an unrelated vmalloc object.** The fixed-offset reads/writes then corrupt
   or disclose that object's fields. Again, address knowledge and object shape determine
   whether this is a crash, a leak, or a controlled write.

The read side deserves separate mention: `mem_pool_size` and `lp_mem_pool_size` are
`0644`, and `kbase_mem_pool_debugfs_size()` only does `READ_ONCE(pool->cur_size)` /
`pool->max_size` for each of 16 pools. It does not take `pool_lock`. On a permissive
debugfs mount this is a lockless read of 32 `size_t` values from fixed offsets in a freed
or reused block. If the block is unmapped, the read faults in kernel context (DoS); if it
is reused by an object with pointer-shaped fields at those offsets, it is a limited
information leak. It is not a general arbitrary-read primitive.

### 2.6 Device-scope pool files: the same pattern over `kbase_device`

The same file also registers device-wide files:

```c
/* mali_kbase_core_linux.c:3715 */
kbase_dev_mem_pool_debugfs_init(kbdev->mali_debugfs_directory, kbdev);

/* mali_kbase_mem_pool_debugfs.c:240-276 */
debugfs_create_file("pgd_mem_pool_size",     0644, parent, &kbdev->pgd_mem_pool, ...);
debugfs_create_file("pgd_mem_pool_max_size", 0644, parent, &kbdev->pgd_mem_pool, ...);
debugfs_create_file("fw_mem_pool_size",      0644, parent, &kbdev->fw_mem_pools.small, ...);
debugfs_create_file("fw_mem_pool_max_size",  0644, parent, &kbdev->fw_mem_pools.small, ...);
debugfs_create_file("lp_fw_mem_pool_size",   0644, parent, &kbdev->fw_mem_pools.large, ...);
debugfs_create_file("lp_fw_mem_pool_max_size", 0644, parent, &kbdev->fw_mem_pools.large, ...);
```

Device teardown only removes the tree:

```c
/* mali_kbase_core_linux.c:3822-3825 */
void kbase_device_debugfs_term(struct kbase_device *kbdev)
{
        debugfs_remove_recursive(kbdev->mali_debugfs_directory);
}
```

The device object itself is `vfree()`'d (`device/mali_kbase_device.c:399-402`), and the
debugfs term callback runs before that in the reverse-order device teardown table
(`device/backend/mali_kbase_device_csf.c:342`). An open `pgd_mem_pool_*` or
`*fw_mem_pool_*` handle therefore points into the freed `kbase_device` block. This is a
rmmod/unbind-gated variant of the same fake-pool primitive; it is a concrete new sub-case
of Finding 6 (device teardown versus in-flight debugfs consumers), not a new root cause.

### 2.7 Gating and fix

- **Write** requires the opener to have write permission on a `0644` file, i.e. normally
  root/CAP_DAC_OVERRIDE. The unprivileged role in the cross-privilege model is the
  *creator/closer* of the context and, if it can reclaim the block, the *shaper* of the
  freed bytes. This extends the baseline's "privileged reader, unprivileged closer"
  model to a "privileged writer, unprivileged shaper" model.
- **Read** is allowed by the file mode but still depends on debugfs mount/path
  permissions. On a root-only debugfs mount it is root-only; on a permissive mount the
  read oracle can be exercised directly by an unprivileged process.
- The per-kctx files exist only with `CONFIG_DEBUG_FS`, and only when the per-context
  directory was created successfully.
- **Fix direction:** acquire a context reference in the `open` handler for every pool
  file (`get_file_active(&kctx->filp)` or a dedicated kctx refcount), released at
  `release`; or stop exposing writable pool state through raw `i_private`. The device
  files need an equivalent device-lifetime anchor. `get_file_active` on the context's
  `filp` mirrors the two already-hardened per-kctx files (`debug_mem_view`,
  `mem_migrate`) and is the minimal consistent fix.
- **Regression test:** open each of the four per-context files, close `/dev/maliN`,
  force a same-size vmalloc reallocation, then read/write the handles under KASAN. The
  parent report's oracle table should be extended with this family.

---

## 3. Finding B — padded UMM teardown sends invalid physical addresses to `FLUSH_PA_RANGE`

### 3.1 How the padding is created

A UMM (dma-buf) import may request read-only padding pages:

```c
/* mali_kbase_mem_linux.c:1426-1446, 1543 */
*va_pages = (PAGE_ALIGN(dma_buf->size) >> PAGE_SHIFT) + (u64)padding;
...
if (padding)
        reg->flags |= KBASE_REG_IMPORT_PAD;
```

The import ioctl accepts `padding` from userspace and rejects it only for non-UMM types
(`mali_kbase_mem_linux.c:1987-1999`). The region therefore has
`reg->nr_pages = dma_buf_pages + padding`, while `alloc->nents` is only the number of
dma-buf pages actually present in the scatter-gather list
(`mali_kbase_mem_linux.c:1281-1295`).

`kbase_alloc_create()` fills every entry of `alloc->pages[]` with a sentinel before any
mapping:

```c
/* mali_kbase_mem.h:938-943 */
for (i = 0; i < nr_pages; i++)
        alloc->pages[i] = as_tagged(KBASE_INVALID_PHYSICAL_ADDRESS);
```

with

```c
/* mali_kbase_mem_lowlevel.h:59 */
#define KBASE_INVALID_PHYSICAL_ADDRESS (~(phys_addr_t)0 & PAGE_MASK)
```

i.e. `0xFFFFFFFFFFFFF000` on a 64-bit build. The padding VAs are mapped to the real
`kctx->aliasing_sink_page` by a separate MMU insert
(`mali_kbase_mem_linux.c:1336-1347`), but that physical address is **not** written into
`alloc->pages[nents]`.

### 3.2 Two call sites flush the sentinel

**Free path.** `kbase_mem_free_region()` tries to reduce the flush count for padded
imports to `nents + 1`:

```c
/* mali_kbase_mem.c:556-571 */
size_t nr_phys_pages = reg->nr_pages;
...
if (reg->flags & KBASE_REG_IMPORT_PAD)
        nr_phys_pages = alloc->nents + 1;
err = kbase_mmu_teardown_imported_pages(kctx->kbdev, &kctx->mmu, reg->start_pfn,
                                        alloc->pages, nr_phys_pages, nr_virt_pages,
                                        kctx->as_nr);
```

The intent is to flush the aliasing sink page once instead of once per padding PTE.
But the extra entry `alloc->pages[nents]` is still the sentinel, not
`kctx->aliasing_sink_page`. The free path therefore flushes one invalid address (and
still never flushes the sink page).

**External-resource unmap path.** `kbase_mem_umm_unmap()` is less careful:

```c
/* mali_kbase_mem_linux.c:1386-1389 */
err = kbase_mmu_teardown_imported_pages(kctx->kbdev, &kctx->mmu, reg->start_pfn,
                                        alloc->pages, reg->nr_pages, reg->nr_pages,
                                        kctx->as_nr);
```

Here every padding slot in `alloc->pages[]` — all sentinels — is passed as a physical
page. This unmap path is reachable through the external-resource/sticky-resource teardown
(`mali_kbase_mem.c:4105-4117`); the normal region-free path above is a second, independent
instance of the same invalid-address flaw (with a count of `nents + 1` rather than all
padding slots).

### 3.3 Why the sentinel reaches the GPU command

`mmu_teardown_pages()` selects a per-page flush when the GPU uses the GPU_CONTROL
interface and the physical count is small:

```c
/* mmu/mali_kbase_mmu.c:3116-3135 */
if (mmu_flush_cache_on_gpu_ctrl(kbdev) && phys &&
    nr_phys_pages <= KBASE_PA_RANGE_THRESHOLD_NR_PAGES)
        flush_op = KBASE_MMU_OP_FLUSH_PT;
```

`KBASE_PA_RANGE_THRESHOLD_NR_PAGES` is 20 (`mmu/mali_kbase_mmu.c:53`), and
`mmu_flush_cache_on_gpu_ctrl()` is true for `arch_major > 11`
(`mmu/mali_kbase_mmu.c:339-342`). The flush loop does not validate the addresses:

```c
/* mmu/mali_kbase_mmu.c:2874-2901, 2894 */
for (i = 0; !flush_done && i < phys_page_nr; i++) {
        spin_lock_irqsave(&kbdev->hwaccess_lock, irq_flags);
        if (mmu_register_updateable(kbdev) && (!kctx || kctx->as_nr >= 0))
                mmu_flush_pa_range(kbdev, as_phys_addr_t(phys[i]), PAGE_SIZE,
                                   KBASE_MMU_OP_FLUSH_MEM);
        ...
}
```

`as_phys_addr_t()` masks the sentinel to `0xFFFFFFFFFFFFF000`; the command computes
`end_pa = start_pa + PAGE_SIZE - 1` and writes both to `GPU_COMMAND_ARG0/1`
(`device/mali_kbase_device_hw.c:112-136`). For the sentinel this produces
`start = 0xFFFFFFFFFFFFF000`, `end = 0xFFFFFFFFFFFFFFFF`.

### 3.4 Impact

The `FLUSH_PA_RANGE` completion is awaited by a busy-wait under `hwaccess_lock` with
interrupts disabled (`device/mali_kbase_device_hw.c:25-103`). The nominal timeout is
50 × 1024 × 1024 GPU cycles, described in the defaults as roughly 0.5 s at 100 MHz
(`mali_kbase_config_defaults.h:372`), scaled by the actual GPU clock. On timeout the
driver logs an error and schedules a GPU reset.

Depending on how the GPU decodes an out-of-range physical address, the command may:

- complete immediately because no cache lines match (benign aside from a wasted flush);
- be truncated/aliased to a valid low physical address, flushing an unrelated page
  (correctness/coherency noise, still not memory corruption); or
- never signal completion, leaving the CPU in the IRQ-off busy-wait until timeout and
  then resetting the GPU.

The last case is the security-relevant one: an interrupt-disabled stall of up to the
scaled timeout, potentially repeated per padded page while the GPU remains updateable,
followed by a GPU reset. On a watchdog-enabled kernel this can escalate to a hard
lockup/reboot. It is a local DoS/robustness bug, not a memory-corruption primitive.

Reachability requires a dma-buf exporter (e.g. dma-heap or udmabuf), an import with
`padding > 0`, a total region size at or below the 20-page partial-flush threshold, and a
GPU with `arch_major > 11`. The mapping must have been established (sticky resource or
normal GPU mapping) so that a teardown with a populated `alloc->pages[]` occurs.

### 3.5 Fix

- Pass the aliasing sink page explicitly for the padding, or clamp the flushed physical
  count to `alloc->nents` and flush `kctx->aliasing_sink_page` once.
- Alternatively, have `mmu_flush_invalidate_teardown_pages()` skip entries for which
  `is_valid_addr(phys[i])` is false (with a `WARN_ON_ONCE`), so an accounting mistake
  cannot turn into an IRQ-off GPU command.
- Add a teardown-side assertion that every `phys[i]` passed to a partial flush is a valid
  physical address.

---

## 4. Finding C — `kbase_jit_grow()` leaves pages allocated but unmapped on mapping failure

`kbase_jit_grow()` allocates the delta pages first, then grows the GPU mapping:

```c
/* mali_kbase_mem.c:2881-2910 */
gpu_pages = kbase_alloc_phy_pages_helper_locked(reg->gpu_alloc, pool, delta, ...);
...
if (reg->cpu_alloc != reg->gpu_alloc) {
        cpu_pages = kbase_alloc_phy_pages_helper_locked(reg->cpu_alloc, pool, delta, ...);
        ...
}
...
ret = kbase_mem_grow_gpu_mapping(kctx, reg, info->commit_pages, old_size, mmu_sync_info);
/*
 * The grow failed so put the allocation back in the
 * pool and return failure.
 */
if (ret)
        goto update_failed;
...
update_failed:
        return ret;
```

The helper has already advanced `alloc->nents` (`mali_kbase_mem.c:1651`), but the failure
label performs no page free and no `nents` rollback. The comment says the allocation is
put back in the pool; the code does not do that. `reg->initial_commit` is also not
updated.

Consequences:

- `gpu_alloc->nents` (and `cpu_alloc->nents`) exceed the number of installed PTEs.
- A retry of the same grow sees `nents >= commit_pages` and takes the `done` path without
  mapping the missing pages, so the region can remain marked backed but be GPU-unmapped.
- The pages stay allocated and accounted until the region is freed; `kbase_mem_evictable_unmake()`
  has already made the allocation non-evictable.

This is a functional/accounting inconsistency and a possible source of GPU faults under
memory pressure or MMU error injection. `kbase_free_phy_pages_helper()` does free based
on `nents`, so the pages are not permanently leaked past region destruction; the defect
is the missing rollback and the resulting unmapped-but-backed state, not a kernel
memory-safety violation.

**Fix:** on `kbase_mem_grow_gpu_mapping()` failure, free the delta pages back to the pool,
restore `nents` and the evictable/`DONT_NEED` state, and leave `initial_commit` unchanged
(the pattern already used by `kbase_mem_commit()`).

---

## 5. Latent and robustness notes

### 5.1 Unchecked partial-page bitmap index

Both partial-page allocation paths do:

```c
/* mali_kbase_mem.c:1314-1318 and 1568-1572 */
pidx = find_next_zero_bit(sa->sub_pages, NUM_PAGES_IN_2MB_LARGE_PAGE, pidx);
bitmap_set(sa->sub_pages, pidx, 1);
```

`find_next_zero_bit()` returns `NUM_PAGES_IN_2MB_LARGE_PAGE` (512) when the bitmap is
full. `bitmap_set(..., 512, 1)` would then write one bit past the bitmap. The code relies
on a non-local invariant: a full partial is unlinked from `kctx->mem_partials` under
`mem_partials_lock` at the point it becomes full (`mali_kbase_mem.c:1322-1326,
1575-1581`), and `free_partial_locked()` / `free_partial()` only re-add a partial when
its weight is exactly 511 (`mali_kbase_mem.c:1490-1494, 1723-1727`). The invariant holds
in the current code, including the group-id and lite variants, so this is latent rather
than reachable.

It is still worth hardening because the failure mode is an out-of-bounds kernel write,
and the invariant could be broken by a future change or by a double-free of a sub-page
(causing a duplicate `list_add()` and a full partial remaining linked). A cheap fix is
to check `pidx >= 512` and `WARN_ON_ONCE`/break, or to assert `!bitmap_full()` before the
loop iteration.

### 5.2 Evictable-unmake failure state

`kbase_mem_linux.c:886-918` calls `kbase_mem_evictable_unmake()`, then attempts
`kbase_alloc_phy_pages_helper()` and `kbase_mem_grow_gpu_mapping()`. If either fails, the
error path still sets `gpu_alloc->evicted = 0` and clears `KBASE_REG_DONT_NEED`, even
though the backing pages were not restored or the mapping was not installed. The region
is then described as un-evicted while its backing is missing. This is silent state
corruption and can cause later GPU faults or reclaim confusion; it is not a kernel
memory-safety issue. The failure path should restore the previous evicted/`DONT_NEED`
state or fully unwind the allocation.

---

## 6. Correction to the parent report: the `mem_profile` arbitrary-read claim

The parent report states that an attacker-supplied `MEM_PROFILE_ADD` payload can be used
to redirect the privileged reader's `seq_write()` after the context is freed. The
teardown order does not support that as written.

`kbase_file_delete()` removes the profile payload *before* destroying the context:

```c
/* mali_kbase_core_linux.c:343-347 */
kbasep_mem_profile_debugfs_remove(kctx);
kbase_context_debugfs_term(kctx);
kbase_destroy_context(kctx);          /* ... vfree(kctx) */
```

and the remove function frees the payload and clears both fields:

```c
/* mali_kbase_mem_profile_debugfs.c:109-121 */
kfree(kctx->mem_profile_data);
kctx->mem_profile_data = NULL;
kctx->mem_profile_size = 0;
```

Therefore, when the context block is `vfree()`'d, the stale `mem_profile` handle does
**not** still point at the attacker's original payload. Its `seq_show()` does:

```c
/* mali_kbase_mem_profile_debugfs.c:38-52 */
mutex_lock(&kctx->mem_profile_lock);
seq_write(sfile, kctx->mem_profile_data, kctx->mem_profile_size);
seq_putc(sfile, '\n');
mutex_unlock(&kctx->mem_profile_lock);
```

Immediately after free, the usual outcome is a fault in `mutex_lock()` on the unmapped
object (the `seq_write()` is `NULL, 0` if the block is still readable). If the block is reused
by a *new* `kbase_context`, the handle reads that new context's profile pointer — i.e.
the new context's own payload, which the attacker may control but which is not arbitrary
kernel memory. To obtain an arbitrary read, the block must instead be reclaimed by an
attacker-controlled vmalloc object that sets `mem_profile_data` to a target kernel
address; that again requires a kernel address disclosure and is not the direct
"payload redirection" described in the parent report.

The underlying Finding 1 UAF is real and remains High: the stale handle still takes a
mutex and dereferences a freed `kbase_context`, with a deterministic DoS and a
reclaim-dependent read. The correction is to the *strength* of the claimed primitive, not
to the existence of the bug. The parent report's suggested fix (anchor every per-kctx
debugfs open with `get_file_active(&kctx->filp)` or a kctx refcount) is still correct,
and should explicitly include the four pool files from Finding A.

---

## 7. Hypotheses examined and refuted

These were checked against the source and are recorded so that future reviews do not
repeat the work.

- **`kinstr_prfcnt` signed ring-index wraparound.** `sample_arr.sample_count` is
  `size_t` (`mali_kbase_kinstr_prfcnt.c:120`); the `write_idx`/`read_idx` updates use
  `%=` against it (`:717, :823, :961, :994`), so the signed `int` is converted to
  `size_t` and the result is non-negative. The `WARN_ON(buf_idx >= sample_count)` guard
  therefore holds. Residual signed-overflow UB after ~2^31 dumps is not an OOB index.
- **Alias `nents` overflow / oversized `vmalloc`.** `kbase_api_mem_alias()` bounds the
  count before allocating the temporary array (`mali_kbase_core_linux.c:1128-1133`), and
  the alias offset/length checks are performed against each source allocation. No
  wraparound to a small allocation followed by a large copy was found.
- **`kbase_mem_from_user_buffer()` `PAGE_ALIGN(address + size)` wrap.** A wrapped size
  becomes a huge `*va_pages`, which is rejected by the `> U64_MAX / PAGE_SIZE` and
  `kbase_import_size_is_valid()` checks (`mali_kbase_mem_linux.c:1627-1636`). No
  undersized allocation.
- **Region-tracker `end_pfn = start_pfn + nr_pages` overflow.** `gpu_pfn` is bounded by
  the GPU VA width (≤ 2^52) and `nr_pages` by the 2^21-page allocation limit, so the sum
  cannot wrap a 64-bit `end_pfn`.
- **MMU teardown array over-read.** `mmu_teardown_pages()` returns `-EINVAL` when
  `nr_virt_pages < nr_phys_pages` (`mmu/mali_kbase_mmu.c:3116-3119`); the `phys[]` reads
  are bounded by the caller's `nr_phys_pages`, and each caller's array is sized for the
  region. The padded-UMM issue in Finding B is an invalid *address*, not an out-of-bounds
  array access.
- **VMA/fault lifetime and `get_aliased_alloc()`.** VMAs hold `vm_file` /
  `kbase_cpu_mapping` references, so closing `/dev/maliN` cannot free the context while a
  mapping exists; alias offset/length bounds hold. No UAF or double-unmap found.
- **CSF user IO page mmap/fault/close.** The fault handler validates
  `nr_pages == BASEP_QUEUE_NR_MMAP_USER_PAGES` and `vm_pgoff == queue->db_file_offset`;
  the queue lifetime is anchored by `get_file(kctx->filp)`/`db_filp`. No defect found.
- **Queue-group creation variants and tiler-heap initialization.** Endpoint maxima are
  bounded by mask popcounts; priority, `cs_min`, handler flags, and DVS/NX/EP-priority
  gating are validated. Tiler `chunk_size` is non-zero and masked to ≤ ~16 MiB,
  `initial_chunks` is bounded by `max_chunks`, `target_in_flight` is non-zero, and
  `group_id` is bounded. Only 32-bit trace multiplications were found, with no
  memory-safety consequence.
- **JIT bin/index/usage arithmetic.** `bin_id`, `id`, and `usage_id` are range-checked
  before indexing the per-bin arrays; `trace_jit_stats()` traversal is bounded.
- **`kbase_free_phy_pages_helper()` underflow.** The runtime
  `WARN_ON(alloc->nents < nr_pages_to_free)` returns `-EINVAL`
  (`mali_kbase_mem.c:1749-1754`), preventing the `alloc->pages + nents - nr_pages`
  underflow. The `_locked` variant has only a debug assert, but all audited callers pass
  valid deltas.
- **Partial-bitmap reachability.** The unchecked `find_next_zero_bit()` in §5.1 is not
  reachable under the current full-partial unlink/re-add invariant; it is a latent
  hardening item, not a live bug.
- **`kbase_vunmap(ctx_ptr, &mapping)` type confusion (Finding 2).** Confirmed inert in
  this configuration; no new path was found that enables the `kctx`-dereferencing flags
  on the heap-context allocation.

---

## 8. Exploitation-primitive assessment

### 8.1 Object placement

Both `struct kbase_context` and `struct kbase_device` are `vzalloc()`'d and `vfree()`'d,
not slab-allocated. That has three consequences:

1. A stale pointer normally lands in an unmapped vmalloc range immediately after free,
   producing a kernel page fault (oops/panic) rather than a silent read of stale bytes.
   KASAN builds report the access as a vmalloc use-after-free.
2. Reuse is first-fit in the vmalloc area. A same-size allocation immediately after the
   free is a good candidate to occupy the same virtual range and remap it. Same-size
   `kbase_context` allocations are the easiest reclaimer; a `vmalloc_user()` buffer of
   the same page-rounded size is the easiest attacker-controlled reclaimer.
3. The stale pointer is an *interior* pointer in the case of the pool files
   (`&kctx->mem_pools.small[0]` or `.large[0]`), so the write offsets are fixed relative
   to that interior point. Reuse by another context therefore aliases exactly the new
   context's pools; reuse by a user buffer gives controlled bytes at those offsets.

### 8.2 What each finding is worth

- **Finding A (per-kctx pool files).** The strongest new primitive. A privileged writer
  can reach `spin_lock`, an 8-byte `max_size` write, `list_del_init()` unlink writes, and
  `kbdev`/`mgm_dev` indirect calls. With a controlled reclaimer and a known kernel
  address it is a fake-object write/free primitive; without address knowledge it is a
  deterministic crash. The cross-context alias variant is reliable but limited to
  resource manipulation/DoS. The read files add a lockless fixed-offset disclosure that
  is only interesting when the block is reused by a pointer-bearing object.
- **Finding A′ (device pool files).** Same primitive over `kbase_device`, gated by
  unbind/rmmod. It is a new concrete sub-case of Finding 6 and reinforces that the
  driver's debugfs layer lacks a general open-handle lifetime anchor.
- **Finding B (padded-UMM sentinel flush).** DoS/robustness only. No kernel memory is
  read or written; the risk is an IRQ-off GPU busy-wait and reset, with platform-specific
  behavior for the out-of-range physical address.
- **Finding C / E.** Reliability and state-consistency defects. They can produce GPU
  faults, accounting drift, or silent loss of backing, but not kernel memory corruption.
- **Finding F (mem_profile).** The parent report's UAF is real; the arbitrary-read story
  requires controlled reclamation plus a kernel address and should not be presented as a
  direct payload redirection.

### 8.3 What is still missing for a chain

The audit did not find a self-contained unprivileged path from any of these bugs to
kernel memory corruption. The gaps are:

- a kernel virtual-address disclosure for the reclaimer (vmalloc/KASLR), needed to turn
  the fake list nodes into useful targets;
- a fake `kbdev`/page-metadata object at a known address so `kbase_mem_pool_free_page()`
  does not fault immediately after the unlink;
- a way to keep the stale handle's write permission (root) while the unprivileged actor
  controls the freed bytes, i.e. the confused-deputy arrangement already described in
  the parent report.

Those are exactly the conditions a weaponized exploit would need to solve, and this
addendum deliberately does not solve them. The disclosure remains a crash-only,
root/privileged-edge report.

---

## 9. Suggested response matrix (additions)

| Item | Suggested priority | Effort | Notes |
|------|-------------------|--------|-------|
| A — per-kctx pool debugfs | High (same class as Finding 1) | Medium | Anchor every open with a kctx ref/`get_file_active`; add the four files to Finding 1's fix and oracle table |
| A′ — device pool debugfs | Medium | Small | Same anchor for `kbase_device`; cover the rmmod/unbind path in Finding 6 |
| B — padded-UMM sentinel flush | Low–Medium | Trivial | Pass the sink page or skip invalid PAs before `FLUSH_PA_RANGE` |
| C — JIT grow rollback | Low | Small | Free the delta and restore `nents`/evictable state on mapping failure |
| D — partial bitmap index | Latent | Trivial | Check `pidx < 512`; keep the full-partial invariant explicit |
| E — evictable-unmake failure | Low | Small | Restore `evicted`/`DONT_NEED` or fully unwind |
| F — mem_profile claim | Correction | None (documentation) | Adjust the parent report's impact wording when it is next revised |

---

## 10. Validation notes (non-weaponized)

- **A:** under KASAN, open one of the four per-context pool files, close the Mali device
  fd to free the context, then read or write the handle. A minimal non-weaponized
  validation can also force a same-size vmalloc reallocation and observe the stale handle
  operating on the new object. No new PoC is included here.
- **B:** instrument `mmu_flush_invalidate_teardown_pages()` to log `phys[i]` for a padded
  UMM import, or use ftrace on `kbase_gpu_cache_flush_pa_range_and_busy_wait()`, and
  confirm the `0xFFFFFFFFFFFFF000` argument during teardown. No GPU reset is required to
  demonstrate the bad argument.
- **C:** use the existing MMU error-injection hook on `kbase_mmu_insert_pages()` and
  inspect `gpu_alloc->nents` versus the installed PTEs after a failed JIT grow.
- **D/E:** source-level invariants and fault injection; no runtime trigger is claimed.

---

## Appendix — key source references

| Topic | Reference |
|-------|-----------|
| Per-kctx debugfs init/term/free | `context/backend/mali_kbase_context_csf.c:46-66, 81-86, 134` |
| Per-kctx pool files and handlers | `mali_kbase_mem_pool_debugfs.c:28-46, 96-177` |
| Device pool files | `mali_kbase_mem_pool_debugfs.c:240-276`; `mali_kbase_core_linux.c:3715, 3822-3825` |
| Debugfs write parsing | `mali_kbase_debugfs_helper.c:32, 186-223` |
| Pool trim/shrink/remove/free | `mali_kbase_mem_pool.c:537-564, 632-692, 749-791` |
| Pool teardown | `mali_kbase_mem_pool.c:924-1005`; `mali_kbase_mem_pool_group.c:78-88` |
| Pool structures | `mali_kbase_defs.h:526-544, 1856` |
| Padded UMM import/map/unmap | `mali_kbase_mem_linux.c:1336-1391, 1426-1543, 1987-1999` |
| UMM free-path teardown | `mali_kbase_mem.c:556-571` |
| Invalid physical address | `mali_kbase_mem_lowlevel.h:59`; `mali_kbase_mem.h:938-943` |
| Teardown flush selection/loop | `mmu/mali_kbase_mmu.c:53, 339-342, 2874-2901, 3116-3152` |
| GPU cache flush busy-wait | `device/mali_kbase_device_hw.c:25-136` |
| Flush timeout | `mali_kbase_config_defaults.h:372` |
| JIT grow | `mali_kbase_mem.c:2803-2921`; `:1651` |
| Free-helper guard | `mali_kbase_mem.c:1733-1765` |
| Partial bitmap | `mali_kbase_mem.c:1314-1326, 1456-1497, 1568-1581, 1719-1727` |
| Evictable-unmake error path | `mali_kbase_mem_linux.c:886-918` |
| mem_profile teardown | `mali_kbase_mem_profile_debugfs.c:38-52, 109-121`; `mali_kbase_core_linux.c:343-347` |
| kinstr ring indices | `mali_kbase_kinstr_prfcnt.c:120, 717, 823, 961, 994` |
