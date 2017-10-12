// SPDX-License-Identifier: GPL-2.0+
/*
 * do_on_cpu system call
 *
 * It allows user-space to perform a sequence of operations on per-cpu
 * data in the user-space address space atomically with respect to concurrent
 * accesses from the same cpu. Useful as single-stepping fall-back for
 * restartable sequences, and for performing more complex operations on per-cpu
 * data that would not be otherwise possible to do with restartable sequences,
 * such as migration of per-cpu data from one cpu to another.
 *
 * Copyright (C) 2017-2019 EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/do_on_cpu.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/smp.h>
#include <linux/sort.h>
#include <asm/ptrace.h>
#include <asm/byteorder.h>
#include <asm/cacheflush.h>

#include "do_on_cpu_private.h"
#include "../sched/sched.h"

/*
 * Provide mutual exclution for threads executing a bytecode against an
 * offline CPU.
 */
static DEFINE_MUTEX(do_on_cpu_offline_lock);

/* Maximum virtual address space which can be used by do_on_cpu. */
int sysctl_do_on_cpu_va_max_bytes __read_mostly;
int sysctl_do_on_cpu_va_max_bytes_min;

static atomic_t do_on_cpu_va_allocated_bytes;

/* Waitqueue for do_on_cpu blocked on virtual address space reservation. */
static DECLARE_WAIT_QUEUE_HEAD(do_on_cpu_va_wait);

/*
 * The do_on_cpu system call executes bytecode on behalf of user-space on a
 * specific CPU either with interrupts disabled or within an interrupt handler.
 *
 * A subset of ebpf instructions are supported. The system call receives a
 * CPU number from user-space as argument, which is the CPU on which those
 * instructions need to be performed. 
 *
 * A translation table mapping user-space addresses to vmap addresses, called
 * "translation map", is kept.
 *
 * The algorithm requires 2 interpreter passes:
 * - In IPI handler (cannot fault):
 *   - Pass 1 (page-pinning pass):
 *     - Check that all pages loaded from/stored to are present in the
 *       kernel-userspace translation map.
 *     - If pages are missing to satisfy a memory access, stop interpreter
 *       and return the address, length, and type (rw) of the range for the
 *       missing access. This returns from the IPI handler and goes to the
 *       "Page Pinning", before retrying invocation of the IPI handler.
 *     - No store side-effects are performed,
 *     - Record a trace of all tainted conditional branches and memory
 *       accesses with tainted addresses,
 *     - If the interpreter completes bytecode execution without finding
 *       a missing page to satisfy memory accesses, Pass 2 is executed.
 *   - Pass 2 (store-side-effects pass):
 *     - Check that all tainted conditional branches and memory accesses to
 *       tainted addresses match the execution trace recorded in Pass 1.
 *       On mismatch, return -EAGAIN (if no store was done yet, allowing to
 *       start over and retry Pass 1 from a clean state), or -EIO (if at least
 *       one store was done prior to mismatch detection, which leaves
 *       user-space data in a partially written corrupted state).
 *     - If any page that need to be accessed by loads/stores is missing from
 *       the translation table, it means there is unexpected corruption of
 *       the control or data flow. If it happens at this stage, stop
 *       interpreter and return -EIO (I/O error). This would leave the
 *       user-space data in a partially written corrupted state.
 *     - Perform store side-effects.
 *
 * - "Page Pinning"
 *   - When additional pages are needed to satisfy a memory access from
 *     Pass 1, get references to those pages and add them to the map. The
 *     virtual mappings of all pages within the kernel vmap address space
 *     are then re-created for the entire set of pages in the map.
 *   - Fails with -EFAULT on error,
 *
 *
 * If a bytecode loads from an address after storing to it, the behavior is
 * implementation-defined.
 *
 * An overall maximum of 8192 retired instructions is enforced, so user-space
 * cannot generate a too long interrupt-off critical section or IPI handler.
 * The bytecode length limited to 32 instructions, but backwards jumps are
 * supported.
 *
 * As a reference measurement, the IPI handler duration for a test-case
 * comparing 4096-byte arrays is measured as 180µs on x86-64.
 *
 * If the current thread is running on the requested CPU, interrupts are
 * disabled around interpretation of the operation vector. If the target
 * CPU differs from the current CPU, an IPI is sent to the remote CPU
 * to interpret the bytecode. If the remote CPU is offline, the bytecode is
 * executed while holding a reference count preventing concurrent CPU hotplug
 * changes, with do_on_cpu_offline_lock mutex held.
 */

/*
 * Approximate the amount of virtual address space required per
 * page to a worse-case of CPU_OP_RANGE_PER_PAGE_MAX.
 */
static int do_on_cpu_reserve_va(int nr_pages, int *reserved_va)
{
	int nr_bytes = nr_pages * CPU_OP_RANGE_PER_PAGE_MAX;
	int old_bytes, new_bytes;

	WARN_ON_ONCE(*reserved_va != 0);
	if (nr_bytes > sysctl_do_on_cpu_va_max_bytes) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	do {
		wait_event(do_on_cpu_va_wait,
			(old_bytes = atomic_read(&do_on_cpu_va_allocated_bytes)) +
			nr_bytes <= sysctl_do_on_cpu_va_max_bytes);
		new_bytes = old_bytes + nr_bytes;
	} while (atomic_cmpxchg(&do_on_cpu_va_allocated_bytes,
		 old_bytes, new_bytes) != old_bytes);

	*reserved_va = nr_bytes;
	return 0;
}

static void do_on_cpu_unreserve_va(int *reserved_va)
{
	int nr_bytes = *reserved_va;

	if (!nr_bytes)
		return;
	atomic_sub(nr_bytes, &do_on_cpu_va_allocated_bytes);
	wake_up(&do_on_cpu_va_wait);
	*reserved_va = 0;
}

static
unsigned long do_on_cpu_range_nr_pages(unsigned long addr,
				       unsigned long len)
{
	return ((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1;
}

static
int do_on_cpu_count_pages(u64 addr, unsigned long len)
{
	unsigned long nr_pages;

	/*
	 * Validate that the address is within the process address space.
	 * This allows cast of those addresses to unsigned long throughout the
	 * rest of this system call, because it would be invalid to have an
	 * address over 4GB on a 32-bit kernel.
	 */
	if (addr >= TASK_SIZE)
		return -EINVAL;
	if (!len)
		return 0;
	nr_pages = do_on_cpu_range_nr_pages(addr, len);
	if (nr_pages > 2) {
		WARN_ON(1);
		return -EINVAL;
	}
	return nr_pages;
}

static
int do_on_cpu_check_page(struct page *page, enum do_on_cpu_rw rw)
{
	struct address_space *mapping;

	if (is_zone_device_page(page))
		return -EFAULT;

	/*
	 * The page lock protects many things but in this context the page
	 * lock stabilizes mapping, prevents inode freeing in the shared
	 * file-backed region case and guards against movement to swap
	 * cache.
	 *
	 * Strictly speaking the page lock is not needed in all cases being
	 * considered here and page lock forces unnecessarily serialization
	 * From this point on, mapping will be re-verified if necessary and
	 * page lock will be acquired only if it is unavoidable
	 *
	 * Mapping checks require the head page for any compound page so the
	 * head page and mapping is looked up now.
	 */
	page = compound_head(page);
	mapping = READ_ONCE(page->mapping);

	/*
	 * If page->mapping is NULL, then it cannot be a PageAnon page;
	 * but it might be the ZERO_PAGE (which is OK to read from), or
	 * in the gate area or in a special mapping (for which this
	 * check should fail); or it may have been a good file page when
	 * get_user_pages found it, but truncated or holepunched or
	 * subjected to invalidate_complete_page2 before the page lock
	 * is acquired (also cases which should fail). Given that a
	 * reference to the page is currently held, refcount care in
	 * invalidate_complete_page's remove_mapping prevents
	 * drop_caches from setting mapping to NULL concurrently.
	 *
	 * The case to guard against is when memory pressure cause
	 * shmem_writepage to move the page from filecache to swapcache
	 * concurrently: an unlikely race, but a retry for page->mapping
	 * is required in that situation.
	 */
	if (!mapping) {
		int shmem_swizzled;

		/*
		 * Check again with page lock held to guard against
		 * memory pressure making shmem_writepage move the page
		 * from filecache to swapcache.
		 */
		lock_page(page);
		shmem_swizzled = PageSwapCache(page) || page->mapping;
		unlock_page(page);
		if (shmem_swizzled)
			return -EAGAIN;
		/*
		 * It is valid to read from, but invalid to write to the
		 * ZERO_PAGE.
		 */
		if (!(is_zero_pfn(page_to_pfn(page)) ||
		      is_huge_zero_page(page)) || rw == DO_ON_CPU_WRITE)
			return -EFAULT;
	}
	return 0;
}

static
void do_on_cpu_unmap_all(struct do_on_cpu_map *map)
{
	int i;

	for (i = 0; i < map->nr_vmaps; i++) {
		struct do_on_cpu_vmap *vmap = &map->vmap[i];

		vm_unmap_user_ram((void *)vmap->kaddr_base, vmap->nr_pages);

	}
	/*
	 * Force vm_map flush to ensure we don't exhaust available vmalloc
	 * address space.
	 */
	if (map->nr_vmaps)
		vm_unmap_aliases();
	map->nr_vmaps = 0;
}

static
void do_on_cpu_remove_page(struct do_on_cpu_page *doc_page)
{
	if (doc_page->rw == DO_ON_CPU_WRITE)
		set_page_dirty(doc_page->page);
	put_page(doc_page->page);
}

static
void do_on_cpu_remove_pages_all(struct do_on_cpu_map *map)
{
	int i;

	for (i = 0; i < map->nr_pages; i++)
		do_on_cpu_remove_page(&map->doc_page[i]);
	map->nr_pages = 0;
}

/* start and end are inclusive. */
static int do_on_cpu_map_add(struct do_on_cpu_map *map,
			     struct do_on_cpu_page *start,
			     struct do_on_cpu_page *end)
{
	struct do_on_cpu_vmap *doc_vmap;
	size_t nr_pages = end + 1 - start;
	unsigned long kaddr;
	struct page *pages[DO_ON_CPU_PAGES_MAX];
	size_t i;

	if (map->nr_vmaps >= DO_ON_CPU_PAGES_MAX)
		return -EINVAL;
	for (i = 0; i < nr_pages; i++)
		pages[i] = start[i].page;
	kaddr = (unsigned long) vm_map_user_ram(pages, nr_pages, start->uaddr_base,
						numa_node_id(), PAGE_KERNEL);
	if (!kaddr)
		return -ENOMEM;
	doc_vmap = &map->vmap[map->nr_vmaps++];
	doc_vmap->kaddr_base = kaddr;
	doc_vmap->uaddr_base = start->uaddr_base;
	doc_vmap->uaddr_end = end->uaddr_base + PAGE_SIZE;	/* Exclusive */
	doc_vmap->nr_pages = nr_pages;
	doc_vmap->used = 0;
	return 0;
}

static
int doc_cmp(const void *_a, const void *_b)
{
	const struct do_on_cpu_page *a = _a, *b = _b;
	unsigned long a_addr = a->uaddr_base;
	unsigned long b_addr = b->uaddr_base;

	if (a_addr < b_addr)
		return -1;
	if (a_addr > b_addr)
		return 1;
	return 0;
}

/* Sort by uaddr_base. */
static
void do_on_cpu_map_sort_pages(struct do_on_cpu_map *map)
{
	sort(map->doc_page, map->nr_pages, sizeof(struct do_on_cpu_page),
	     doc_cmp, NULL);	/* use generic swap */
}

/*
 * This function does not distinguish between pages accessed for read or write,
 * and can pass both types of pages to a single mapping if those are contiguous.
 */
static int do_on_cpu_map_all(struct do_on_cpu_map *map)
{
	/* start and end are inclusive. */
	struct do_on_cpu_page *start, *next, *end;
	size_t i;
	int ret;

	/* Sort pages first. */
	do_on_cpu_map_sort_pages(map);

	start = end = &map->doc_page[0];
	for (i = 1; i < map->nr_pages; i++) {
		next = &map->doc_page[i];

		/*
		 * If next page is contiguous, add to same mapping.
		 */
		if (next->uaddr_base == end->uaddr_base + PAGE_SIZE) {
			end = next;
			continue;
		}
		/*
		 * Next page is not contiguous, create mapping from
		 * start to end (inclusive).
		 */
		ret = do_on_cpu_map_add(map, start, end);
		if (ret)
			return ret;
		start = end = next;
	}
	/* Create vmap for pages between start and end (inclusive). */
	return do_on_cpu_map_add(map, start, end);
}

/*
 * Return true if page is found.
 */
static
int do_on_cpu_map_find_page(struct do_on_cpu_map *map,
			    unsigned long uaddr_base,
			    enum do_on_cpu_rw rw)
{
	int i;

	for (i = 0; i < map->nr_pages; i++) {
		struct do_on_cpu_page *doc_page = &map->doc_page[i];
		if (doc_page->uaddr_base == uaddr_base &&
		    (doc_page->rw == DO_ON_CPU_WRITE || rw == DO_ON_CPU_READ))
			return i;
	}
	return -1;
}

static
void map_remove_page_index(struct do_on_cpu_map *map, int i)
{
	int index_last = --map->nr_pages;

	if (i == index_last)
		return;
	do_on_cpu_remove_page(&map->doc_page[i]);
	map->doc_page[i] = map->doc_page[index_last];
}

static
void find_page_remove_wrong_access(struct do_on_cpu_map *map,
				   unsigned long uaddr_base,
				   enum do_on_cpu_rw rw)
{
	int i;

	for (i = 0; i < map->nr_pages; i++) {
		struct do_on_cpu_page *doc_page = &map->doc_page[i];

		if (doc_page->uaddr_base == uaddr_base &&
		    (doc_page->rw == DO_ON_CPU_READ && rw == DO_ON_CPU_WRITE)) {
			map_remove_page_index(map, i);
			break;
		}
	}
}

static
void do_on_cpu_map_add_page(struct do_on_cpu_map *map,
			    struct page *page,
			    unsigned long uaddr_base,
			    enum do_on_cpu_rw rw)
{
	int index = map->nr_pages++;

	map->doc_page[index].uaddr_base = uaddr_base;
	map->doc_page[index].rw = rw;
	map->doc_page[index].used = 0;
	map->doc_page[index].page = page;
}

/*
 * Add page(s) required to satisfy @next_pin's range to the map's pages in
 * sorted uaddr order.
 */
static int do_on_cpu_add_pages(struct do_on_cpu_map *map,
			       struct do_on_cpu_mem_op *next_pin)
{
	unsigned long addr = next_pin->addr;
	unsigned long len = next_pin->len;
	enum do_on_cpu_rw rw = next_pin->rw;
	int nr_pages, nr_put_pages, i, nr_add_set = 0, ret;
	unsigned long uaddr_base[2];
	struct vm_area_struct *vmas[2];
	struct do_on_cpu_page add_set[2];
	struct page *pages[2];
	struct mm_struct *mm = current->mm;

	if (!access_ok(addr, len))
		return -EFAULT;
	nr_pages = do_on_cpu_count_pages(addr, len);
	if (nr_pages <= 0)
		return nr_pages;
	uaddr_base[0] = addr & PAGE_MASK;
	if (nr_pages == 2)
		uaddr_base[1] = uaddr_base[0] + PAGE_SIZE;

	/*
	 * If required pages are already in the map with wrong write access,
	 * remove them from map.
	 */
	for (i = 0; i < nr_pages; i++)
		find_page_remove_wrong_access(map, uaddr_base[i], rw);

	/*
	 * If required pages are missing from map add them to set.
	 */
	for (i = 0; i < nr_pages; i++) {
		if (do_on_cpu_map_find_page(map, uaddr_base[i], rw) < 0) {
			struct do_on_cpu_page *add = &add_set[nr_add_set++];
			add->uaddr_base = uaddr_base[i];
			add->rw = rw;
		}
	}
	nr_pages = nr_add_set;

	if (map->nr_pages + nr_pages >= DO_ON_CPU_PAGES_MAX)
		return -EINVAL;
	if (!nr_pages)
		return 0;
again:
	down_read(&mm->mmap_sem);
	ret = get_user_pages(addr, nr_pages, rw == DO_ON_CPU_WRITE ? FOLL_WRITE : 0, pages,
			     vmas);
	if (ret < nr_pages) {
		if (ret >= 0) {
			nr_put_pages = ret;
			ret = -EFAULT;
		} else {
			nr_put_pages = 0;
		}
		up_read(&mm->mmap_sem);
		goto error;
	}
	/*
	 * do_on_cpu() accesses its own cached mapping of the userspace pages.
	 * Considering that concurrent noncached and cached accesses may yield
	 * to unexpected results in terms of memory consistency, explicitly
	 * disallow do_on_cpu on noncached memory.
	 */
	for (i = 0; i < nr_pages; i++) {
		if (is_vma_noncached(vmas[i])) {
			nr_put_pages = nr_pages;
			ret = -EFAULT;
			up_read(&mm->mmap_sem);
			goto error;
		}
	}
	up_read(&mm->mmap_sem);

	for (i = 0; i < nr_pages; i++) {
		ret = do_on_cpu_check_page(pages[i], rw);
		if (ret) {
			nr_put_pages = nr_pages;
			goto error;
		}
	}
	for (i = 0; i < nr_pages; i++)
		do_on_cpu_map_add_page(map, pages[i], add_set[i].uaddr_base, rw);
	return 0;

error:
	for (i = 0; i < nr_put_pages; i++)
		put_page(pages[i]);
	/*
	 * Retry if a page has been faulted in, or is being swapped in.
	 */
	if (ret == -EAGAIN)
		goto again;
	return ret;

}

static int do_on_cpu_pin_pages(struct bpf_insn *bytecode, u32 len,
			       struct do_on_cpu_map *map,
			       struct do_on_cpu_mem_op *next_pin)
{
	int ret = 0;
	int i;

	for (i = 0; i < map->nr_vmaps; i++) {
		struct do_on_cpu_vmap *doc_vmap = &map->vmap[i];

		if (!doc_vmap->used) {
			/*
			 * A vmap was left unused by previous interpreter pin
			 * pass. This means concurrent updates changed the
			 * required memory ranges. Reset the map and start
			 * over.
			 */
			goto reset_map;
		}
		doc_vmap->used = 0;
	}

	for (i = 0; i < map->nr_pages; i++) {
		struct do_on_cpu_page *doc_page = &map->doc_page[i];

		if (!doc_page->used) {
			/*
			 * A page was left unused by previous interpreter pin
			 * pass. This means concurrent updates changed the
			 * required memory ranges. Reset the map and start
			 * over.
			 */
			goto reset_map;
		}
		doc_page->used = 0;
	}

	/*
	 * Add the page required by @next_pin in sorted uaddr order to the set.
	 */
	if (next_pin->addr) {
		/*
		 * Remove all existing mappings and in preparation to re-create
		 * new ones for the new set of pages.
		 */
		do_on_cpu_unmap_all(map);

		ret = do_on_cpu_add_pages(map, next_pin);
		next_pin->addr = 0;
		next_pin->len = 0;
		next_pin->rw = DO_ON_CPU_READ;
		if (ret)
			return ret;
		/*
		 * Map all pages in the set.
		 */
		ret = do_on_cpu_map_all(map);
	}
	return ret;

reset_map:
	next_pin->addr = 0;
	next_pin->len = 0;
	next_pin->rw = DO_ON_CPU_READ;
	do_on_cpu_unmap_all(map);
	do_on_cpu_remove_pages_all(map);
	return 0;
}

static int __on_cpu_ipi(struct bpf_insn *bytecode, u32 len,
			struct do_on_cpu_map *map,
			struct do_on_cpu_mem_op *next_pin,
			int64_t *result)
{
	struct do_on_cpu_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));

	/* Interpreter pass 1: pin required userspace pages. */
	ret = do_on_cpu_interpreter(bytecode, len, map, next_pin,
				    &ctx, NULL, ON_CPU_PASS_PIN_PAGES);
	if (ret)
		return ret;

	/* Interpreter pass 2: perform store side-effects. */
	ret = do_on_cpu_interpreter(bytecode, len, map, NULL,
				    &ctx, result, ON_CPU_PASS_STORES);
	if (ret)
		return ret;
	return 0;
}

/*
 * Check that the page pointers pinned by get_user_pages()
 * are still in the page table. Invoked with mmap_sem held.
 * Return 0 if pointers match, -EAGAIN if they don't.
 */
static int doc_page_check(struct do_on_cpu_page *doc_page)
{
	struct page *page;
	int ret;

	ret = __get_user_pages_fast(doc_page->uaddr_base, 1,
				    doc_page->rw == DO_ON_CPU_WRITE, &page);
	if (ret == 1)
		put_page(page);
	if (ret < 1) {
		ret = get_user_pages(doc_page->uaddr_base, 1,
				     doc_page->rw == DO_ON_CPU_WRITE ? FOLL_WRITE : 0,
				     &page, NULL);
		if (ret <= 0)
			return -EAGAIN;
		if (ret == 1)
			put_page(page);
	}
	if (page != doc_page->page)
		return -EAGAIN;
	return 0;
}

static int map_check(struct do_on_cpu_map *map)
{
	int i;

	for (i = 0; i < map->nr_pages; i++) {
		int ret;

		ret = doc_page_check(&map->doc_page[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static void on_cpu_ipi(void *info)
{
	struct do_on_cpu_ipi_args *args = info;

	rseq_preempt(current);
	args->ret = __on_cpu_ipi(args->bytecode, args->len, args->map,
				 args->next_pin, args->result);
}

static int do_on_cpu_ipi(struct bpf_insn *bytecode, u32 len,
		      struct do_on_cpu_map *map,
		      struct do_on_cpu_mem_op *next_pin,
		      int64_t *result, int cpu)
{
	struct mm_struct *mm = current->mm;
	struct do_on_cpu_ipi_args args = {
		.bytecode = bytecode,
		.map = map,
		.next_pin = next_pin,
		.len = len,
		.result = result,
	};
	int ret;

retry:
	if (!cpumask_test_cpu(cpu, &current->cpus_allowed))
		return -EINVAL;
	down_read(&mm->mmap_sem);
	ret = map_check(map);
	if (ret)
		goto end;
	ret = smp_call_function_single(cpu, on_cpu_ipi, &args, 1);
	if (ret) {
		up_read(&mm->mmap_sem);
		goto check_online;
	}
	ret = args.ret;
end:
	up_read(&mm->mmap_sem);
	return ret;

check_online:
	get_online_cpus();
	if (cpu_online(cpu)) {
		put_online_cpus();
		goto retry;
	}
	/*
	 * CPU is offline. Perform operation from the current CPU with
	 * cpu_online read lock held, preventing that CPU from coming online,
	 * and with mutex held, providing mutual exclusion against other
	 * CPUs also finding out about an offline CPU.
	 */
	down_read(&mm->mmap_sem);
	ret = map_check(map);
	if (ret)
		goto offline_end;
	mutex_lock(&do_on_cpu_offline_lock);
	ret = __on_cpu_ipi(bytecode, len, map, next_pin, result);
	mutex_unlock(&do_on_cpu_offline_lock);
offline_end:
	up_read(&mm->mmap_sem);
	put_online_cpus();
	return ret;
}

/*
 * do_on_cpu - execute ebpf instructions on a given CPU in interrupt context.
 *
 * Userspace should pass the CPU number on which the instructions should be
 * executed as parameter.
 */
SYSCALL_DEFINE5(do_on_cpu, struct bpf_insn __user *, ubytecode, u32, len,
		int64_t __user *, uresult, int, cpu, int, flags)
{
	struct bpf_insn bytecode[DO_ON_CPU_LEN_MAX];
	struct do_on_cpu_map map = {
		.nr_pages = 0,
		.nr_vmaps = 0,
	};
	struct do_on_cpu_mem_op next_pin = {
		.addr = 0,
		.len = 0,
		.rw = DO_ON_CPU_READ,
	};
	int ret, reserved_va = 0;
	int64_t result = 0;

	if (unlikely(flags & ~(DO_ON_CPU_LEN_MAX_FLAG |
			       DO_ON_CPU_RETIRED_INSN_MAX_FLAG |
			       DO_ON_CPU_PAGES_MAX_FLAG)))
		return -EINVAL;
	if (flags & DO_ON_CPU_LEN_MAX_FLAG) {
		if (flags & (DO_ON_CPU_RETIRED_INSN_MAX_FLAG |
			     DO_ON_CPU_PAGES_MAX_FLAG))
			return -EINVAL;
		return DO_ON_CPU_LEN_MAX;
	}
	if (flags & DO_ON_CPU_RETIRED_INSN_MAX_FLAG) {
		if (flags & DO_ON_CPU_PAGES_MAX_FLAG)
			return -EINVAL;
		return DO_ON_CPU_RETIRED_INSN_MAX;
	}
	if (flags & DO_ON_CPU_PAGES_MAX_FLAG)
		return DO_ON_CPU_PAGES_MAX;
	if (unlikely(cpu < 0))
		return -EINVAL;
	if (len > DO_ON_CPU_LEN_MAX)
		return -EINVAL;
	if (copy_from_user(bytecode, ubytecode, len * sizeof(struct bpf_insn)))
		return -EFAULT;
	ret = do_on_cpu_validate(bytecode, len);
	if (ret)
		return ret;
	ret = do_on_cpu_reserve_va(DO_ON_CPU_PAGES_MAX, &reserved_va);
	if (ret)
		return ret;
again:
	ret = do_on_cpu_ipi(bytecode, len, &map, &next_pin, &result, cpu);
	if (ret == -EAGAIN) {
		ret = do_on_cpu_pin_pages(bytecode, len, &map, &next_pin);
		if (ret && ret != -EAGAIN)
			goto end;
		goto again;
	}
end:
	do_on_cpu_unmap_all(&map);
	do_on_cpu_remove_pages_all(&map);
	do_on_cpu_unreserve_va(&reserved_va);
	if (!ret && uresult && put_user(result, uresult))
		return -EFAULT;
	return ret;
}

/*
 * Dynamic initialization is required on sparc because SHMLBA is not a
 * constant.
 */
static int __init do_on_cpu_init(void)
{
	sysctl_do_on_cpu_va_max_bytes = DO_ON_CPU_VA_MAX_BYTES_MIN;
	sysctl_do_on_cpu_va_max_bytes_min = DO_ON_CPU_VA_MAX_BYTES_MIN;
	return 0;
}
core_initcall(do_on_cpu_init);
