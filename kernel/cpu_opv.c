/*
 * CPU preempt-off operation vector system call
 *
 * It allows user-space to perform a sequence of operations on per-cpu
 * data with preemption disabled. Useful as single-stepping fall-back
 * for restartable sequences, and for performing more complex operations
 * on per-cpu data that would not be otherwise possible to do with
 * restartable sequences.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2017, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/cpu_opv.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/byteorder.h>

#include "sched/sched.h"

/*
 * Typical invocation of cpu_opv need few pages. Keep struct page
 * pointers in an array on the stack of the cpu_opv system call up to
 * this limit, beyond which the array is dynamically allocated.
 */
#define NR_PAGE_PTRS_ON_STACK		8

/* Maximum pages per op. */
#define CPU_OP_MAX_PAGES		4

/* Temporary on-stack buffer size for memcpy and compare operations. */
#define TMP_BUFLEN			64

union op_fn_data {
	uint8_t _u8;
	uint16_t _u16;
	uint32_t _u32;
	uint64_t _u64;
#if (BITS_PER_LONG < 64)
	uint32_t _u64_split[2];
#endif
};

struct cpu_opv_page_ptrs {
	struct page **pages;
	size_t nr;
	bool is_kmalloc;
};

typedef int (*op_fn_t)(union op_fn_data *data, uint64_t v, uint32_t len);

/*
 * Provide mutual exclution for threads executing a cpu_opv against an
 * offline CPU.
 */
static DEFINE_MUTEX(cpu_opv_offline_lock);

/*
 * The cpu_opv system call executes a vector of operations on behalf of
 * user-space on a specific CPU with preemption disabled. It is inspired
 * by readv() and writev() system calls which take a "struct iovec"
 * array as argument.
 *
 * The operations available are: comparison, memcpy, add, or, and, xor,
 * left shift, right shift, and memory barrier. The system call receives
 * a CPU number from user-space as argument, which is the CPU on which
 * those operations need to be performed.  All pointers in the ops must
 * have been set up to point to the per CPU memory of the CPU on which
 * the operations should be executed. The "comparison" operation can be
 * used to check that the data used in the preparation step did not
 * change between preparation of system call inputs and operation
 * execution within the preempt-off critical section.
 *
 * The reason why we require all pointer offsets to be calculated by
 * user-space beforehand is because we need to use get_user_pages_fast()
 * to first pin all pages touched by each operation. This takes care of
 * faulting-in the pages. Then, preemption is disabled, and the
 * operations are performed atomically with respect to other thread
 * execution on that CPU, without generating any page fault.
 *
 * An overall maximum of 4216 bytes in enforced on the sum of operation
 * length within an operation vector, so user-space cannot generate a
 * too long preempt-off critical section (cache cold critical section
 * duration measured as 4.7µs on x86-64). Each operation is also limited
 * a length of 4096 bytes, meaning that an operation can touch a
 * maximum of 4 pages (memcpy: 2 pages for source, 2 pages for
 * destination if addresses are not aligned on page boundaries).
 *
 * If the thread is not running on the requested CPU, it is migrated to
 * it.
 */

static unsigned long cpu_op_range_nr_pages(unsigned long addr,
					   unsigned long len)
{
	return ((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1;
}

static int cpu_op_count_pages(unsigned long addr, unsigned long len)
{
	unsigned long nr_pages;

	if (!len)
		return 0;
	nr_pages = cpu_op_range_nr_pages(addr, len);
	if (nr_pages > 2) {
		WARN_ON(1);
		return -EINVAL;
	}
	return nr_pages;
}

static struct page **cpu_op_alloc_pages_vector(int nr_pages)
{
	return kzalloc(nr_pages * sizeof(struct page *), GFP_KERNEL);
}

/*
 * Check operation types and length parameters. Count number of pages.
 */
static int cpu_opv_check_op(struct cpu_op *op, int *nr_pages, uint32_t *sum)
{
	int ret;

	switch (op->op) {
	case CPU_MB_OP:
		break;
	default:
		*sum += op->len;
	}

	/* Validate inputs. */
	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
	case CPU_MEMCPY_OP:
		if (op->len > CPU_OP_DATA_LEN_MAX)
			return -EINVAL;
		break;
	case CPU_ADD_OP:
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
		switch (op->len) {
		case 1:
		case 2:
		case 4:
		case 8:
			break;
		default:
			return -EINVAL;
		}
		break;
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
		switch (op->len) {
		case 1:
			if (op->u.shift_op.bits > 7)
				return -EINVAL;
			break;
		case 2:
			if (op->u.shift_op.bits > 15)
				return -EINVAL;
			break;
		case 4:
			if (op->u.shift_op.bits > 31)
				return -EINVAL;
			break;
		case 8:
			if (op->u.shift_op.bits > 63)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
		break;
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}

	/* Count pages. */
	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
		ret = cpu_op_count_pages(op->u.compare_op.a, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		ret = cpu_op_count_pages(op->u.compare_op.b, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		break;
	case CPU_MEMCPY_OP:
		ret = cpu_op_count_pages(op->u.memcpy_op.dst, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		ret = cpu_op_count_pages(op->u.memcpy_op.src, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		break;
	case CPU_ADD_OP:
		ret = cpu_op_count_pages(op->u.arithmetic_op.p, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		break;
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
		ret = cpu_op_count_pages(op->u.bitwise_op.p, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		break;
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
		ret = cpu_op_count_pages(op->u.shift_op.p, op->len);
		if (ret < 0)
			return ret;
		*nr_pages += ret;
		break;
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Check operation types and length parameters. Count number of pages.
 */
static int cpu_opv_check(struct cpu_op *cpuopv, int cpuopcnt, int *nr_pages)
{
	uint32_t sum = 0;
	int i, ret;

	for (i = 0; i < cpuopcnt; i++) {
		ret = cpu_opv_check_op(&cpuopv[i], nr_pages, &sum);
		if (ret)
			return ret;
	}
	if (sum > CPU_OP_VEC_DATA_LEN_MAX)
		return -EINVAL;
	return 0;
}

/**
 * fault_in_user_writeable() - Fault in user address and verify RW access
 * @uaddr:	pointer to faulting user space address
 */
static int fault_in_user_writeable(unsigned long uaddr)
{
	struct mm_struct *mm = current->mm;
	int ret;

	down_read(&mm->mmap_sem);
	ret = fixup_user_fault(current, mm, uaddr,
			       FAULT_FLAG_WRITE, NULL);
	up_read(&mm->mmap_sem);

	return ret < 0 ? ret : 0;
}

/*
 * Refusing device pages, the zero page, pages in the gate area, and
 * special mappings. Handle page swapping through retry. Fault in the page if
 * needed.
 */
static int cpu_op_check_page(struct page *page, unsigned long addr)
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
	 * If page->mapping is NULL, then it cannot be a PageAnon
	 * page; but it might be the ZERO_PAGE or in the gate area or
	 * in a special mapping (all cases which we are happy to fail);
	 * or it may have been a good file page when get_user_pages_fast
	 * found it, but truncated or holepunched or subjected to
	 * invalidate_complete_page2 before we got the page lock (also
	 * cases which we are happy to fail).  And we hold a reference,
	 * so refcount care in invalidate_complete_page's remove_mapping
	 * prevents drop_caches from setting mapping to NULL beneath us.
	 *
	 * The case we do have to guard against is when memory pressure made
	 * shmem_writepage move it from filecache to swapcache beneath us:
	 * an unlikely race, but we do need to retry for page->mapping.
	 */
	if (!mapping) {
		int shmem_swizzled, ret;

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
		 * Page needs to be faulted-in. If it succeeds, return
		 * -EAGAIN to retry.
		 */
		ret = fault_in_user_writeable(addr);
		if (!ret)
			return -EAGAIN;
		return ret;
	}
	return 0;
}

static int cpu_op_check_pages(struct page **pages,
			      unsigned long nr_pages,
			      unsigned long addr)
{
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		int ret;

		ret = cpu_op_check_page(pages[i], addr);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
	}
	return 0;
}

static int cpu_op_pin_pages(unsigned long addr, unsigned long len,
			    struct cpu_opv_page_ptrs *page_ptrs,
			    int write)
{
	struct page *pages[2];
	int ret, nr_pages, nr_put_pages, n;

	nr_pages = cpu_op_count_pages(addr, len);
	if (!nr_pages)
		return 0;
again:
	ret = get_user_pages_fast(addr, nr_pages, write, pages);
	if (ret < nr_pages) {
		if (ret >= 0) {
			nr_put_pages = ret;
			ret = -EFAULT;
		} else {
			nr_put_pages = 0;
		}
		goto error;
	}
	ret = cpu_op_check_pages(pages, nr_pages, addr);
	if (ret) {
		nr_put_pages = nr_pages;
		goto error;
	}
	for (n = 0; n < nr_pages; n++)
		page_ptrs->pages[page_ptrs->nr++] = pages[n];
	return 0;

error:
	for (n = 0; n < nr_put_pages; n++)
		put_page(pages[n]);
	/*
	 * Retry if a page has been faulted in, or is being swapped in.
	 */
	if (ret == -EAGAIN)
		goto again;
	return ret;
}

static int cpu_opv_pin_pages_op(struct cpu_op *op,
				struct cpu_opv_page_ptrs *page_ptrs,
				bool *expect_fault)
{
	int ret;

	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
		ret = -EFAULT;
		*expect_fault = op->u.compare_op.expect_fault_a;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.compare_op.a,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.compare_op.a, op->len,
				       page_ptrs, 0);
		if (ret)
			return ret;
		ret = -EFAULT;
		*expect_fault = op->u.compare_op.expect_fault_b;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.compare_op.b,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.compare_op.b, op->len,
				       page_ptrs, 0);
		if (ret)
			return ret;
		break;
	case CPU_MEMCPY_OP:
		ret = -EFAULT;
		*expect_fault = op->u.memcpy_op.expect_fault_dst;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.memcpy_op.dst,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.memcpy_op.dst, op->len,
				       page_ptrs, 1);
		if (ret)
			return ret;
		ret = -EFAULT;
		*expect_fault = op->u.memcpy_op.expect_fault_src;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.memcpy_op.src,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.memcpy_op.src, op->len,
				       page_ptrs, 0);
		if (ret)
			return ret;
		break;
	case CPU_ADD_OP:
		ret = -EFAULT;
		*expect_fault = op->u.arithmetic_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.arithmetic_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.arithmetic_op.p, op->len,
				       page_ptrs, 1);
		if (ret)
			return ret;
		break;
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
		ret = -EFAULT;
		*expect_fault = op->u.bitwise_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.bitwise_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.bitwise_op.p, op->len,
				       page_ptrs, 1);
		if (ret)
			return ret;
		break;
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
		ret = -EFAULT;
		*expect_fault = op->u.shift_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.shift_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.shift_op.p, op->len,
				       page_ptrs, 1);
		if (ret)
			return ret;
		break;
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int cpu_opv_pin_pages(struct cpu_op *cpuop, int cpuopcnt,
			     struct cpu_opv_page_ptrs *page_ptrs)
{
	int ret, i;
	bool expect_fault = false;

	/* Check access, pin pages. */
	for (i = 0; i < cpuopcnt; i++) {
		ret = cpu_opv_pin_pages_op(&cpuop[i], page_ptrs,
				&expect_fault);
		if (ret)
			goto error;
	}
	return 0;

error:
	/*
	 * If faulting access is expected, return EAGAIN to user-space.
	 * It allows user-space to distinguish between a fault caused by
	 * an access which is expect to fault (e.g. due to concurrent
	 * unmapping of underlying memory) from an unexpected fault from
	 * which a retry would not recover.
	 */
	if (ret == -EFAULT && expect_fault)
		return -EAGAIN;
	return ret;
}

static int __op_get_user(union op_fn_data *data, void __user *p, size_t len)
{
	switch (len) {
	case 1:	return __get_user(data->_u8, (uint8_t __user *)p);
	case 2:	return __get_user(data->_u16, (uint16_t __user *)p);
	case 4:	return __get_user(data->_u32, (uint32_t __user *)p);
	case 8:
#if (BITS_PER_LONG == 64)
		return __get_user(data->_u64, (uint64_t __user *)p);
#else
	{
		int ret;

		ret = __get_user(data->_u64_split[0],
				 (uint32_t __user *)p);
		if (ret)
			return ret;
		return __get_user(data->_u64_split[1],
				  (uint32_t __user *)p + 1);
	}
#endif
	default:
		return -EINVAL;
	}
}

static int __op_put_user(union op_fn_data *data, void __user *p, size_t len)
{
	switch (len) {
	case 1:	return __put_user(data->_u8, (uint8_t __user *)p);
	case 2:	return __put_user(data->_u16, (uint16_t __user *)p);
	case 4:	return __put_user(data->_u32, (uint32_t __user *)p);
	case 8:
#if (BITS_PER_LONG == 64)
		return __put_user(data->_u64, (uint64_t __user *)p);
#else
	{
		int ret;

		ret = __put_user(data->_u64_split[0],
				 (uint32_t __user *)p);
		if (ret)
			return ret;
		return __put_user(data->_u64_split[1],
				  (uint32_t __user *)p + 1);
	}
#endif
	default:
		return -EINVAL;
	}
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int do_cpu_op_compare_iter(void __user *a, void __user *b, uint32_t len)
{
	char bufa[TMP_BUFLEN], bufb[TMP_BUFLEN];
	uint32_t compared = 0;

	while (compared != len) {
		unsigned long to_compare;

		to_compare = min_t(uint32_t, TMP_BUFLEN, len - compared);
		if (__copy_from_user_inatomic(bufa, a + compared, to_compare))
			return -EFAULT;
		if (__copy_from_user_inatomic(bufb, b + compared, to_compare))
			return -EFAULT;
		if (memcmp(bufa, bufb, to_compare))
			return 1;
		compared += to_compare;
	}
	return 0;
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int do_cpu_op_compare(unsigned long _a, unsigned long _b, uint32_t len)
{
	void __user *a = (void __user *)_a;
	void __user *b = (void __user *)_b;
	int ret = -EFAULT;
	union op_fn_data tmp[2];

	switch (len) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return do_cpu_op_compare_iter(a, b, len);
	}

	pagefault_disable();

	if (__op_get_user(&tmp[0], a, len))
		goto end;
	if (__op_get_user(&tmp[1], b, len))
		goto end;

	switch (len) {
	case 1:
		ret = !!(tmp[0]._u8 != tmp[1]._u8);
		break;
	case 2:
		ret = !!(tmp[0]._u16 != tmp[1]._u16);
		break;
	case 4:
		ret = !!(tmp[0]._u32 != tmp[1]._u32);
		break;
	case 8:
		ret = !!(tmp[0]._u64 != tmp[1]._u64);
		break;
	default:
		break;
	}
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_memcpy_iter(void __user *dst, void __user *src,
				 uint32_t len)
{
	char buf[TMP_BUFLEN];
	uint32_t copied = 0;

	while (copied != len) {
		unsigned long to_copy;

		to_copy = min_t(uint32_t, TMP_BUFLEN, len - copied);
		if (__copy_from_user_inatomic(buf, src + copied, to_copy))
			return -EFAULT;
		if (__copy_to_user_inatomic(dst + copied, buf, to_copy))
			return -EFAULT;
		copied += to_copy;
	}
	return 0;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_memcpy(unsigned long _dst, unsigned long _src,
			    uint32_t len)
{
	void __user *dst = (void __user *)_dst;
	void __user *src = (void __user *)_src;
	int ret = -EFAULT;
	union op_fn_data tmp;

	switch (len) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return do_cpu_op_memcpy_iter(dst, src, len);
	}

	pagefault_disable();

	if (__op_get_user(&tmp, src, len))
		goto end;
	if (__op_put_user(&tmp, dst, len))
		goto end;
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

static int op_add_fn(union op_fn_data *data, uint64_t count, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 += (uint8_t)count;
		break;
	case 2:
		data->_u16 += (uint16_t)count;
		break;
	case 4:
		data->_u32 += (uint32_t)count;
		break;
	case 8:
		data->_u64 += (uint64_t)count;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_or_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 |= (uint8_t)mask;
		break;
	case 2:
		data->_u16 |= (uint16_t)mask;
		break;
	case 4:
		data->_u32 |= (uint32_t)mask;
		break;
	case 8:
		data->_u64 |= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_and_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 &= (uint8_t)mask;
		break;
	case 2:
		data->_u16 &= (uint16_t)mask;
		break;
	case 4:
		data->_u32 &= (uint32_t)mask;
		break;
	case 8:
		data->_u64 &= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_xor_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 ^= (uint8_t)mask;
		break;
	case 2:
		data->_u16 ^= (uint16_t)mask;
		break;
	case 4:
		data->_u32 ^= (uint32_t)mask;
		break;
	case 8:
		data->_u64 ^= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_lshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 <<= (uint8_t)bits;
		break;
	case 2:
		data->_u16 <<= (uint16_t)bits;
		break;
	case 4:
		data->_u32 <<= (uint32_t)bits;
		break;
	case 8:
		data->_u64 <<= (uint64_t)bits;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_rshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 >>= (uint8_t)bits;
		break;
	case 2:
		data->_u16 >>= (uint16_t)bits;
		break;
	case 4:
		data->_u32 >>= (uint32_t)bits;
		break;
	case 8:
		data->_u64 >>= (uint64_t)bits;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_fn(op_fn_t op_fn, unsigned long _p, uint64_t v,
			uint32_t len)
{
	union op_fn_data tmp;
	void __user *p = (void __user *)_p;
	int ret = -EFAULT;

	pagefault_disable();
	if (__op_get_user(&tmp, p, len))
		goto end;
	if (op_fn(&tmp, v, len))
		goto end;
	if (__op_put_user(&tmp, p, len))
		goto end;
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/*
 * Return negative value on error, positive value if comparison
 * fails, 0 on success.
 */
static int __do_cpu_opv_op(struct cpu_op *op)
{
	int ret;

	/* Guarantee a compiler barrier between each operation. */
	barrier();

	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
		ret = do_cpu_op_compare(op->u.compare_op.a,
					op->u.compare_op.b,
					op->len);
		if (ret)
			return ret;
		break;
	case CPU_COMPARE_NE_OP:
		ret = do_cpu_op_compare(op->u.compare_op.a,
					op->u.compare_op.b,
					op->len);
		if (ret < 0)
			return ret;
		/*
		 * Stop execution, return positive value if comparison
		 * is identical.
		 */
		if (ret == 0)
			return 1;
		break;
	case CPU_MEMCPY_OP:
		ret = do_cpu_op_memcpy(op->u.memcpy_op.dst,
				       op->u.memcpy_op.src,
				       op->len);
		if (ret)
			return ret;
		break;
	case CPU_ADD_OP:
		ret = do_cpu_op_fn(op_add_fn, op->u.arithmetic_op.p,
				   op->u.arithmetic_op.count, op->len);
		if (ret)
			return ret;
		break;
	case CPU_OR_OP:
		ret = do_cpu_op_fn(op_or_fn, op->u.bitwise_op.p,
				   op->u.bitwise_op.mask, op->len);
		if (ret)
			return ret;
		break;
	case CPU_AND_OP:
		ret = do_cpu_op_fn(op_and_fn, op->u.bitwise_op.p,
				   op->u.bitwise_op.mask, op->len);
		if (ret)
			return ret;
		break;
	case CPU_XOR_OP:
		ret = do_cpu_op_fn(op_xor_fn, op->u.bitwise_op.p,
				   op->u.bitwise_op.mask, op->len);
		if (ret)
			return ret;
		break;
	case CPU_LSHIFT_OP:
		ret = do_cpu_op_fn(op_lshift_fn, op->u.shift_op.p,
				   op->u.shift_op.bits, op->len);
		if (ret)
			return ret;
		break;
	case CPU_RSHIFT_OP:
		ret = do_cpu_op_fn(op_rshift_fn, op->u.shift_op.p,
				   op->u.shift_op.bits, op->len);
		if (ret)
			return ret;
		break;
	case CPU_MB_OP:
		/* Memory barrier provided by this operation. */
		smp_mb();
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int __do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt)
{
	int i, ret;

	for (i = 0; i < cpuopcnt; i++) {
		ret = __do_cpu_opv_op(&cpuop[i]);
		/* If comparison fails, stop execution and return index + 1. */
		if (ret > 0)
			return i + 1;
		/* On error, stop execution. */
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt, int cpu)
{
	int ret;

retry:
	if (cpu != raw_smp_processor_id()) {
		ret = push_task_to_cpu(current, cpu);
		if (ret)
			goto check_online;
	}
	preempt_disable();
	if (cpu != smp_processor_id()) {
		preempt_enable();
		goto retry;
	}
	ret = __do_cpu_opv(cpuop, cpuopcnt);
	preempt_enable();
	return ret;

check_online:
	if (!cpu_possible(cpu))
		return -EINVAL;
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
	mutex_lock(&cpu_opv_offline_lock);
	ret = __do_cpu_opv(cpuop, cpuopcnt);
	mutex_unlock(&cpu_opv_offline_lock);
	put_online_cpus();
	return ret;
}

/*
 * cpu_opv - execute operation vector on a given CPU with preempt off.
 *
 * Userspace should pass current CPU number as parameter.
 */
SYSCALL_DEFINE4(cpu_opv, struct cpu_op __user *, ucpuopv, int, cpuopcnt,
		int, cpu, int, flags)
{
	struct cpu_op cpuopv[CPU_OP_VEC_LEN_MAX];
	struct page *page_ptrs_on_stack[NR_PAGE_PTRS_ON_STACK];
	struct cpu_opv_page_ptrs page_ptrs = {
		.pages = page_ptrs_on_stack,
		.nr = 0,
		.is_kmalloc = false,
	};
	int ret, i, nr_pages = 0;

	if (unlikely(flags))
		return -EINVAL;
	if (unlikely(cpu < 0))
		return -EINVAL;
	if (cpuopcnt < 0 || cpuopcnt > CPU_OP_VEC_LEN_MAX)
		return -EINVAL;
	if (copy_from_user(cpuopv, ucpuopv, cpuopcnt * sizeof(struct cpu_op)))
		return -EFAULT;
	ret = cpu_opv_check(cpuopv, cpuopcnt, &nr_pages);
	if (ret)
		return ret;
	if (nr_pages > NR_PAGE_PTRS_ON_STACK) {
		page_ptrs.pages = cpu_op_alloc_pages_vector(nr_pages);
		if (!page_ptrs.pages)
			return -ENOMEM;
		page_ptrs.is_kmalloc = true;
	}
	ret = cpu_opv_pin_pages(cpuopv, cpuopcnt, &page_ptrs);
	if (ret)
		goto end;
	ret = do_cpu_opv(cpuopv, cpuopcnt, cpu);
end:
	for (i = 0; i < page_ptrs.nr; i++)
		put_page(page_ptrs.pages[i]);
	if (page_ptrs.is_kmalloc)
		kfree(page_ptrs.pages);
	return ret;
}
