# Mali r56p0 Memory Management Primitives Catalog
**Role**: Kernel exploit developer  
**Goal**: Catalog all memory management operations for exploitation planning

---

## Allocation Primitives by Type

### vmalloc/vzalloc Allocations (Target for Spray)

| Location | Size | Trigger | Controllable |
|----------|------|---------|-------------|
| `context/backend/mali_kbase_context_csf.c:134` | `sizeof(struct kbase_context)` (~10KB+) | `open(/dev/mali0)` | No |
| `device/mali_kbase_device.c:93` | `sizeof(struct kbase_device)` | Module init | No |
| `csf/mali_kbase_csf_kcpu.c:2820` | `sizeof(*queue)` | `KCPU_QUEUE_CREATE` ioctl | No |
| `tl/mali_kbase_timeline.c:103` | `sizeof(*timeline)` | Timeline init | No |
| `tl/mali_kbase_timeline.c:191` | `sizeof(struct kbase_tlstream_buf) * PACKET_COUNT` | Timeline stream | No |
| `csf/mali_kbase_csf_firmware.c:2666` | `mcu_fw->size` | Firmware load | **YES - Size controlled** |
| `csf/mali_kbase_csf_util.c:65` | `sizeof(struct kbasep_printer)` | CSF util | No |
| `mali_kbase_mem_linux.c:1685` | `*va_pages * sizeof(struct page *)` | User buf import | **YES - Page count** |
| `mali_kbase_mem_linux.c:1803` | `sizeof(*aliased) * nents` | Alias import | **YES - nents** |
| `mali_kbase_core_linux.c:1133` | `sizeof(*ai) * alias->in.nents` | Alias ioctl | **YES - nents** |
| `mali_kbase_kinstr_prfcnt.c:1108` | `user_buf` size | Perf counter | Partial |

**Exploitation note**: The firmware load primitive at `csf/mali_kbase_csf_firmware.c:2666` allows **arbitrary vmalloc size**, making it ideal for heap grooming.

### kmalloc/kzalloc Allocations (Slab Objects)

| Location | Size | Trigger | Controllable |
|----------|------|---------|-------------|
| `mali_kbase_core_linux.c:214` | `sizeof(struct kbase_file)` | `open(/dev/mali0)` | No |
| `csf/mali_kbase_csf.c:574` | `sizeof(struct kbase_queue)` | Queue bind | No |
| `csf/mali_kbase_csf.c:1283` | `sizeof(struct kbase_queue_group)` | Group create | No |
| `csf/mali_kbase_csf_tiler_heap.c:281` | `sizeof(*chunk)` | Heap chunk alloc | No |
| `csf/mali_kbase_csf_tiler_heap.c:705` | `sizeof(*heap)` | Heap create | No |
| `csf/mali_kbase_csf_firmware_log.c:281` | `FIRMWARE_LOG_DUMP_BUF_SIZE + 1` (64KB+) | FW log init | No |
| `mali_kbase_mem.c:1359` | `sizeof(*sa)` | Sticky alloc | No |
| `mali_kbase_mem.c:3115` | `sizeof(*prealloc_sas[i])` | Prealloc array | No |
| `mali_kbase_fence_ops.c:95` | `sizeof(*meta_defer)` | Fence defer | No |
| `mali_kbase_kinstr_prfcnt.c:1461` | `scratch_buffer_bytes * sizeof(*)` | Perf scratch | Partial |

### Page Allocations

| Location | Purpose | Trigger |
|----------|---------|--------|
| `mali_kbase_mem_pool.c` | GPU page pool | Various GPU ops |
| Physical pages via `alloc_pages()` | GPU memory | Memory allocation ioctls |

---

## Free Primitives (Potential Double-Free Targets)

### vfree Operations

| Location | Object | Conditions | Risk |
|----------|--------|------------|------|
| `context/backend/mali_kbase_context_csf.c:85` | `kctx` | Context destroy | **UAF - Finding 1** |
| `device/mali_kbase_device.c:401` | `kbdev` | Device destroy | Medium |
| `csf/mali_kbase_csf_kcpu.c:2133` | `queue` | Queue delete | **Race - worker** |
| `tl/mali_kbase_timeline.c:143` | `timeline->streams[i].buffer` | Timeline term | **UAF - Finding 4** |
| `tl/mali_kbase_timeline.c:149` | `timeline` | Timeline term | **UAF - Finding 4** |
| `mali_kbase_io.c:183` | `h->buf` | IO history term | **UAF - Finding 6.2** |
| `mali_kbase_core_linux.c:1163` | `ai` | Alias cleanup | Low |
| `mali_kbase_mem_linux.c:2916` | `kaddr` | vunmap cleanup | Low |
| `csf/mali_kbase_csf_scheduler.c:7683` | `alloc->imported.user_buf.pages` | Scheduler cleanup | Medium |
| `csf/mali_kbase_csf_scheduler.c:7694` | `alloc` | Scheduler cleanup | Medium |
| `mali_kbase_mem.c:1963` | `aliased` | Alias free | Medium |
| `mali_kbase_mem.c:2036` | `alloc->imported.user_buf.pages` | User buf free | Medium |
| `mali_kbase_mem.c:2047` | `alloc` | Alloc free | **Check double-free** |
| `mali_kbase_kinstr_prfcnt.c:1108` | `sample_arr->user_buf` | Perf term | Low |

### kfree Operations

| Location | Object | Conditions | Risk |
|----------|--------|------------|------|
| `csf/mali_kbase_csf.c:480` | `queue` | Queue unbind fail | Medium |
| `csf/mali_kbase_csf.c:1364` | `group` | Group init fail | Medium |
| `csf/mali_kbase_csf.c:1662` | `group` | Group destroy | Medium |
| `csf/mali_kbase_csf_tiler_heap.c:238` | `chunk` | Chunk shrink | **Check double-free** |
| `csf/mali_kbase_csf_tiler_heap.c:378` | `chunk` | Chunk free error | **Check double-free** |
| `csf/mali_kbase_csf_tiler_heap.c:1146` | `chunk` | Chunk destroy | **Check double-free** |
| `csf/mali_kbase_csf_tiler_heap.c:537` | `heap` | Heap destroy error | **Check double-free** |
| `csf/mali_kbase_csf_tiler_heap.c:848` | `heap` | Heap destroy | **Check double-free** |
| `csf/mali_kbase_csf_firmware_log.c:343` | `fw_log->dump_buf` | FW log term | **UAF - Finding 3** |
| `mali_kbase_core_linux.c:354` | `kfile` | File release | Low |
| `mali_kbase_mem.c:1488` | `sa` | Sticky free | Medium |
| `mali_kbase_mem.c:1721` | `sa` | Sticky free 2 | Medium |
| `mali_kbase_mem.c:3334` | `prealloc_sas[i]` | Prealloc cleanup | Low |
| `debug/mali_kbase_debug_ktrace.c:46` | `kbdev->ktrace.rbuf` | ktrace term | **UAF - Finding 6.3** |
| `mali_kbase_kinstr_prfcnt.c:1144` | `cli` | Client destroy | **UAF - Finding 6.4** |

---

## vmap/vunmap Primitives (Kernel VA Mappings)

### vmap Operations

| Location | Purpose | Size | Flags |
|----------|---------|------|-------|
| `mali_kbase_mem_linux.c:3291` | Generic vmap | Variable | `VM_MAP` |
| `csf/mali_kbase_csf.c:284` | Queue vmap | 2 pages | `VM_MAP` |
| `csf/mali_kbase_csf_firmware.c:967` | Firmware interface | `num_pages` | `VM_MAP` |
| `csf/mali_kbase_csf_firmware.c:3631` | CSF mapping | `num_pages` | `VM_MAP` |
| `csf/mali_kbase_csf_firmware_no_mali.c:1618` | No-mali FW | `num_pages` | `VM_MAP` |
| `csf/mali_kbase_csf_sync.c:517` | Ringbuffer | 1 page | `pgprot_noncached` |

### kbase_vmap_prot/kbase_vmap Operations

| Location | Purpose | Protection | vmap_flags |
|----------|---------|------------|------------|
| `mali_kbase_mem_linux.c:3375-3406` | Generic | Configurable | Configurable |
| `csf/mali_kbase_csf_kcpu.c:312` | KCPU cmd | `KBASE_REG_CPU_WR` | 0 |
| `csf/mali_kbase_csf_csg.c:302` | CSG cmd | 0 | 0 |
| `csf/mali_kbase_csf_heap_context_alloc.c:57` | Heap context | `KBASE_REG_CPU_WR` | 0 |
| `csf/mali_kbase_csf_tiler_heap.c:348` | Tiler chunk | `KBASE_REG_CPU_WR` | 0 |
| `csf/mali_kbase_csf_tiler_heap.c:748` | Buffer desc | `KBASE_REG_CPU_WR` | 0 |
| `csf/mali_kbase_csf_tiler_heap.c:783` | GPU VA | `KBASE_REG_CPU_WR` | 0 |

### vunmap Operations

| Location | Type | Accounting |
|----------|------|------------|
| `mali_kbase_mem_linux.c:3410-3444` | `kbase_vunmap_phy_pages` | Decrements `vmap_count` |
| `mali_kbase_mem_linux.c:3446` | `kbase_vunmap` | Wrapper |
| **BUG**: `csf/mali_kbase_csf_heap_context_alloc.c:82` | `kbase_vunmap(ctx_ptr, &mapping)` | **Wrong first arg!** |

### vmap_count Tracking

**Critical primitive**: `page_md->vmap_count` is `u8` (max 255)

| Operation | Location | Effect |
|-----------|----------|--------|
| Increment | `mali_kbase_mem_linux.c:3029` | `page_md->vmap_count++` |
| Overflow check | `mali_kbase_mem_linux.c:3022` | `if (vmap_count == U8_MAX) return -EBUSY` |
| Decrement | `mali_kbase_mem_linux.c:3053,3102,3143` | `page_md->vmap_count--` |
| Zero check | `mali_kbase_mem_linux.c:3050,3099,3140` | `WARN_ON_ONCE(vmap_count == 0)` |
| Migration check | `mali_kbase_mem_migrate.c:583` | `if (vmap_count == 0 && ...)` |

**Attack vector**: Create 255 vmaps → 256th vmap returns `-EBUSY` but if we can bypass check → overflow to 0 → page freed while mapped.

---

## mmap/munmap Primitives (Userspace Mappings)

### mmap Entry Points

| Location | Handler | Type |
|----------|---------|------|
| `mali_kbase_core_linux.c:2008` | `kbase_mmap` | Main entry |
| `mali_kbase_mem_linux.c:2774` | `kbase_context_mmap` | Context dispatch |
| `mali_kbase_mem_linux.c:2623` | `kbase_mmu_dump_mmap` | MMU dump |
| `mali_kbase_mem_linux.c:2699` | `kbasep_reg_mmap` | Region (cookie-based) |
| `mali_kbase_mem_linux.c:3759-3803` | `kbase_csf_cpu_mmap_user_reg_page` | CSF user reg page |
| `mali_kbase_mem_linux.c:3805-3854` | `kbase_csf_cpu_mmap_user_io_pages` | CSF I/O pages |

### Special mmap Handles

| Handle | Value | Purpose |
|--------|-------|--------|
| `BASE_MEM_MAP_TRACKING_HANDLE` | Special | Tracking page |
| `BASE_MEM_MMU_DUMP_HANDLE` | Special | MMU dump |
| `BASE_MEM_COOKIE_BASE` | `0x0...` | Cookie-based regions |
| `BASE_MEM_FIRST_FREE_ADDRESS` | After cookies | Normal regions |

### VMA Operations

| Operation | Handler | Purpose |
|-----------|---------|--------|
| `.open` | `kbase_cpu_vm_open` | Increment refcount |
| `.close` | `kbase_cpu_vm_close` | Decrement, cleanup |
| `.fault` | `kbase_cpu_vm_fault` | Page fault handler |
| `.open` (CSF I/O) | `kbase_csf_user_io_pages_vm_open` | Queue I/O open |
| `.close` (CSF I/O) | `kbase_csf_user_io_pages_vm_close` | **Queue unbind - UAF risk** |
| `.fault` (CSF I/O) | `kbase_csf_user_io_pages_vm_fault` | I/O page fault |
| `.mremap` (CSF I/O) | `kbase_csf_user_io_pages_vm_mremap` | Forbidden |
| `.split` (CSF I/O) | `kbase_csf_user_io_pages_vm_split` | Forbidden |

### GPU mmap/munmap

| Function | Purpose | Risk |
|----------|---------|------|
| `kbase_gpu_mmap` | Map region to GPU VA | Race with close |
| `kbase_gpu_munmap` | Unmap from GPU VA | Use-after-munmap |

---

## Lock Acquisition Patterns (Race Condition Audit)

### Context-Level Locks

| Lock | Protects | Acquisition sites |
|------|----------|------------------|
| `kctx->reg_lock` | Region list | mmap, alloc, free, query |
| `kctx->jit_evict_lock` | JIT regions | JIT alloc/free, **debugfs UAF** |
| `kctx->mem_profile_lock` | mem_profile data | **debugfs UAF target** |
| `kctx->csf.lock` | CSF queues/groups | Queue ops, **debugfs UAF** |
| `kctx->csf.kcpu_queues.lock` | KCPU queues | KCPU ops, **debugfs UAF** |
| `kctx->csf.tiler_heaps.lock` | Tiler heaps | Heap ops, **debugfs UAF** |

### Device-Level Locks

| Lock | Protects | Critical sections |
|------|----------|------------------|
| `kbdev->csf.scheduler.lock` | CSF scheduler | Schedule operations |
| `kbdev->mmu_hw_mutex` | MMU hardware | Page table updates |
| `kbdev->hwcnt.lock` | HW counters | Counter access |

### mmap Lock (Process-Level)

| Function | Purpose |
|----------|--------|
| `down_read(kbase_mem_get_process_mmap_lock())` | Protect VMA ops |
| `down_write(kbase_mem_get_process_mmap_lock())` | Exclusive VMA modification |
| `downgrade_write(kbase_mem_get_process_mmap_lock())` | Write → read |
| `up_read/up_write(kbase_mem_get_process_mmap_lock())` | Release |

**Critical locations**:
- `mali_kbase_mem_linux.c:1061` - down_write before GPU munmap
- `mali_kbase_mem_linux.c:1697` - down_read for user page pin
- `mali_kbase_mem_linux.c:2153` - down_write for mem query
- `mali_kbase_mem_linux.c:2690` - down_read for MMU dump
- `mali_kbase_core_linux.c:1283` - down_read for MEM_ALIAS
- `csf/mali_kbase_csf_kcpu.c:55` - down_read for KCPU suspend

### Lock Ordering (Deadlock Prevention)

```
mmap_lock → reg_lock → mmu_lock
```

Any violation of this ordering → potential deadlock → DoS primitive.

---

## Refcount Primitives

### Physical Allocation Refcounts

| Function | Effect |
|----------|--------|
| `kbase_mem_phy_alloc_get` | Increment alloc refcount |
| `kbase_mem_phy_alloc_put` | Decrement, free at 0 |

### Context Refcounts

| Function | Effect |
|----------|--------|
| `kbase_ctx_sched_retain_ctx_refcount` | Increment ctx refcount |
| `kbase_ctx_sched_release_ctx_refcount` | Decrement ctx refcount |

**Used by**: MMU fault workers (prevents ctx free while worker running)

### File Refcounts

| Function | Effect |
|----------|--------|
| `get_file(kctx->filp)` | Increment file refcount |
| `fput(kctx->filp)` | Decrement file refcount |

**Critical**: Only 2/12 debugfs files use `get_file_active(&kctx->filp)` - **Finding 1**

---

## Copy Operations (Info Leak/Corruption Vectors)

### copy_to_user

| Location | Source | Size | Risk |
|----------|--------|------|------|
| `mali_kbase_core_linux.c` | Various ioctl results | Varies | Info leak if uninitialized |
| `csf/mali_kbase_csf_firmware_log.c:138` | `fw_log->dump_buf` | `n_read` | **UAF read - Finding 3** |
| `mali_kbase_mem_profile_debugfs.c:50` | `kctx->mem_profile_data` | `kctx->mem_profile_size` | **UAF read - Finding 1** |

### copy_from_user

| Location | Dest | Size | Validation |
|----------|------|------|------------|
| `mali_kbase_core_linux.c` | ioctl arg structs | Varies | Size checked |
| `mali_kbase_mem_profile_debugfs.c` | `mem_profile_data` | User-controlled | **Bounded, but injection point** |

---

## DMA-buf Import/Export

### Import Operations

| Location | Function | Risk |
|----------|----------|------|
| `mali_kbase_mem_linux.c:1768-1936` | `kbase_mem_from_umm` | DMA-buf lifetime vs region |
| `mali_kbase_mem_linux.c:2881` | `dma_buf_mmap` | mmap imported buf |

### Lifetime Issues

```c
// Region holds dma_buf reference
reg->cpu_alloc->imported.umm.dma_buf

// But what if:
// 1. Import dma_buf
// 2. mmap region
// 3. Exporter closes dma_buf
// 4. Region still mapped
// Result: Use of freed dma_buf?
```

---

## User Page Import

### Pin Operations

| Location | Function | Risk |
|----------|----------|------|
| `mali_kbase_mem_linux.c:1697-1700` | `pin_user_pages` | Race: user unmaps pages while pinned |
| `mali_kbase_mem_linux.c:1685` | `vmalloc` page array | Allocation size from user |

### Unpin Operations

| Location | Function | Notes |
|----------|----------|-------|
| `mali_kbase_mem.c:2036-2038` | `unpin_user_pages` + free | Check vfree/kfree mismatch |
| `csf/mali_kbase_csf_scheduler.c:7683-7685` | Scheduler cleanup | Same check |

**Race condition**:
```c
// Thread 1: Import user buffer → pin pages
// Thread 2: munmap user buffer
// Thread 3: GPU accesses imported buffer
// Result: Access to freed/reused pages?
```

---

## Sticky Resource Management

### Sticky Allocation (sub-allocation)

| Operation | Location | Risk |
|-----------|----------|------|
| Allocate | `mali_kbase_mem.c:1359` | `kmalloc(sizeof(*sa))` |
| Free | `mali_kbase_mem.c:1488, 1721` | Two free sites - double-free? |
| Prealloc | `mali_kbase_mem.c:3115` | Array of preallocated |
| Cleanup | `mali_kbase_mem.c:3334` | Free preallocated |

**Audit focus**: Can sticky alloc be freed twice through different paths?

---

## JIT Allocation Primitives

### JIT Operations

| Function | Purpose | Location |
|----------|---------|----------|
| `kbase_jit_allocate` | Allocate JIT region | `mali_kbase_mem.c` |
| `kbase_jit_free` | Free JIT region | `mali_kbase_mem.c` |
| `kbase_jit_backing_lost` | Mark backing lost | Shuffle only (safe per audit) |

### JIT Debugfs (UAF Surface)

| File | Reader deref |
|------|-------------|
| `mem_jit_count` | `mutex_lock(&kctx->jit_evict_lock)` on freed kctx |
| `mem_jit_vm` | Same |
| `mem_jit_phys` | Same |
| `mem_jit_used` | Same |
| `mem_jit_trim` | Same |

---

## Summary: High-Value Exploitation Primitives

### 1. Debugfs UAF Family (Finding 1)
- **Trigger**: Open debugfs → close /dev/mali → read debugfs
- **Primitive**: Read/write freed `kctx` structure
- **Data injection**: `KBASE_IOCTL_MEM_PROFILE_ADD` (up to 12 KB)
- **Spray**: KCPU queues, firmware data, timeline buffers

### 2. Firmware Log UAF (Finding 3)
- **Trigger**: Open fw_traces debugfs → rmmod while reader stalled
- **Primitive**: UAF write up to 64 KB
- **Target**: `fw_log->dump_buf` (kmalloc'd)

### 3. vmap_count Overflow (New)
- **Trigger**: Create 255+ vmaps on same page
- **Primitive**: Counter wraps to 0 → page freed while mapped
- **Result**: Use-after-free of physically mapped page

### 4. mmap/close Race (New)
- **Trigger**: Thread 1 mmap with cookie, Thread 2 close fd
- **Primitive**: Use region after free
- **Window**: Between cookie fetch and region use

### 5. Tiler Heap Chunk (Potential)
- **Trigger**: OOM reclaim during concurrent GPU access
- **Primitive**: Use heap chunk after free
- **Complexity**: High (needs GPU programming)

### 6. KCPU Queue Worker Race (Potential)
- **Trigger**: Delete queue while worker executing
- **Primitive**: Worker uses freed queue structure
- **Window**: Between delete and worker completion

---

## Next: Code Audit Workflow

1. **Read critical files** (listed in main plan)
2. **Trace each primitive** end-to-end
3. **Identify all free paths** for each object type
4. **Check refcount correctness** for all shared objects
5. **Audit lock ordering** for deadlock/race conditions
6. **Validate size calculations** for integer overflows
7. **Check error paths** for cleanup bugs
8. **Map state machines** for logic bugs

---

## Grep Commands for Primitive Discovery

```bash
# Find all allocation/free pairs
for func in kmalloc kzalloc vmalloc vzalloc; do
    echo "=== $func ==="
    grep -rn "$func(" . | grep -v Binary | wc -l
done

for func in kfree vfree; do
    echo "=== $func ==="
    grep -rn "$func(" . | grep -v Binary | wc -l
done

# Find all vmap/vunmap
grep -rn "kbase_vmap\|vmap(" . | grep -v Binary
grep -rn "kbase_vunmap\|vunmap(" . | grep -v Binary

# Find all mmap handlers
grep -rn "\.mmap.*=" . | grep -v Binary

# Find all copy operations
grep -rn "copy_to_user\|copy_from_user" . | grep -v Binary | wc -l

# Find all refcount operations
grep -rn "_get\|_put" . | grep -E "phy_alloc|ctx_refcount" | grep -v Binary
```
