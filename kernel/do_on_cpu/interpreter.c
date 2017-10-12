// SPDX-License-Identifier: GPL-2.0 or LGPL-2.1
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/bitmap.h>
#include <linux/nospec.h>

#include "do_on_cpu_private.h"

/*
 * An interpreter context is maintained for validation of memory accesses to
 * tainted addresses and conditional branches depending on tainted conditions.
 *
 * A memory access address or branch condition is tainted if it is the result
 * of a load from user-space memory, or the result of an arithmetic instruction
 * taking a tainted register as input.
 *
 * The context is populated by the page-pinning pass, and checked by the
 * store-side-effects pass. If a tainted memory operation or tainted
 * conditional branch is found to differ between passes, the store-side-effect
 * pass aborts and returns an error. That error depends on whether a
 * store side-effect has been issued by the interpreter prior to detection
 * of the discrepancy. If no store was issued, -EAGAIN is returned, and the
 * interpreter starts over to the page-pinning pass. If a store was issued
 * prior to detection of the discrepancy, -EIO is returned to user-space,
 * which means partial side-effects are done, which should be handled as
 * corruption.
 *
 * Therefore, if user-space expects to modify the memory content which end up
 * being the source of a tainted memory access address or source of a branch
 * condition concurrently from another CPU (e.g. through a pointer store for
 * rcu-like assign/dereference, or storing a value, for instance 0 to unlock a
 * spinlock), the tainted branches or memory accesses within the bytecode
 * should not be performed after store instructions, because they would cause
 * -EIO to be returned, indication of corruption.
 *
 * However, if user-space guarantees that the memory content being the source
 * of a tainted memory access address or source of a branch condition is only
 * ever changed from the same CPU given as parameter to do_on_cpu, then having
 * tainted memory accesses addresses or tainted branch conditions after store
 * instructions will not trigger -EIO.
 */

struct reg {
	u64 v;
	/*
	 * Register is tainted if its value is derived from a load
	 * from memory or results from an instruction taking at least one
	 * tainted register as source.
	 */
	bool tainted;
};

static
void clear_regs(struct reg *reg, int nr_regs)
{
	int i;

	/* Registers are initialized to 0. */
	for (i = 0; i < nr_regs; i++) {
		reg[i].v = 0;
		reg[i].tainted = false;
	}
}

static
void show_regs(size_t pc, struct reg *reg, int nr_regs)
{
	int i;

	printk(KERN_INFO "pc: %zu\n", pc);
	for (i = 0; i < nr_regs; i++) {
		printk(KERN_INFO "r%d: %llu (0x%llx) %s\n", i,
		       reg[i].v, reg[i].v, reg[i].tainted ? " (tainted)" : "");
	}
}

/* len is always <= than page size. */
static
unsigned long do_on_cpu_map_find_kaddr(struct do_on_cpu_map *map,
				       unsigned long uaddr,
				       size_t len, enum do_on_cpu_rw rw)
{
	int i;
	bool found_start = false, found_end = false;

	BUG_ON(len > PAGE_SIZE);

	/* Check page access rights. */
	for (i = 0; i < map->nr_pages; i++) {
		struct do_on_cpu_page *doc_page = &map->doc_page[i];

		if (!found_start &&
		    doc_page->uaddr_base == (uaddr & PAGE_MASK) &&
		    (doc_page->rw == DO_ON_CPU_WRITE || rw == DO_ON_CPU_READ)) {
			found_start = true;
			doc_page->used = 1;
		}
		if (!found_end && doc_page->uaddr_base ==
		    ((uaddr + len - 1) & PAGE_MASK) &&
		    (doc_page->rw == DO_ON_CPU_WRITE || rw == DO_ON_CPU_READ)) {
			found_end = true;
			doc_page->used = 1;
		}
		if (found_start && found_end)
			break;
	}
	if (!found_start || !found_end)
		return 0;

	/* Find kaddr. */
	for (i = 0; i < map->nr_vmaps; i++) {
		struct do_on_cpu_vmap *doc_vmap = &map->vmap[i];

		if (uaddr >= doc_vmap->uaddr_base &&
		    uaddr + len <= doc_vmap->uaddr_end) {
			doc_vmap->used = 1;
			return uaddr - doc_vmap->uaddr_base +
			       doc_vmap->kaddr_base;
		}
	}
	return 0;
}

static
void do_load(u64 *dst_reg, unsigned long kaddr, unsigned long len, int acquire)
{
	//printk("LOAD %lx\n", kaddr);
	switch (len) {
	case 1:	if (acquire)
			*dst_reg = smp_load_acquire((u8 *)kaddr);
		else
			*dst_reg = READ_ONCE(*(u8 *)kaddr);
		break;
	case 2:
		if (acquire)
			*dst_reg = smp_load_acquire((u16 *)kaddr);
		else
			*dst_reg = READ_ONCE(*(u16 *)kaddr);
		break;
	case 4:
		if (acquire)
			*dst_reg = smp_load_acquire((u32 *)kaddr);
		else
			*dst_reg = READ_ONCE(*(u32 *)kaddr);
		break;
	case 8:
#if (BITS_PER_LONG == 64)
		if (acquire)
			*dst_reg = smp_load_acquire((u64 *)kaddr);
		else
			*dst_reg = READ_ONCE(*(u64 *)kaddr);
#else
		if (acquire) {
#ifdef __BIG_ENDIAN
			*dst_reg = ((u64) READ_ONCE(*(u32 *)kaddr)) << 32;
			*dst_reg |= (u64) smp_load_acquire((u32 *)kaddr + 1);
#else
			*dst_reg = (u64) READ_ONCE(*(u32 *)kaddr);
			*dst_reg |= (u64) (smp_load_acquire((u32 *)kaddr + 1) << 32);
#endif

		} else {
#ifdef __BIG_ENDIAN
			*dst_reg = ((u64) READ_ONCE(*(u32 *)kaddr)) << 32;
			*dst_reg |= (u64) READ_ONCE(*((u32 *)kaddr + 1));
#else
			*dst_reg = (u64) READ_ONCE(*(u32 *)kaddr);
			*dst_reg |= (u64) (READ_ONCE(*((u32 *)kaddr + 1)) << 32);
#endif
		}
#endif
		break;
	default:
		printk(KERN_ERR "Incorrect load length %zu\n", len);
	}
	//printk("LOADED value: %lld\n", (long long) *dst_reg);
}

static
void do_store(unsigned long kaddr, unsigned long len, u64 src, int release)
{
	switch (len) {
	case 1:	if (release)
			smp_store_release((u8 *)kaddr, src);
		else
			WRITE_ONCE(*(u8 *)kaddr, src);
		break;
	case 2:
		if (release)
			smp_store_release((u16 *)kaddr, src);
		else
			WRITE_ONCE(*(u16 *)kaddr, src);
		break;
	case 4:
		if (release)
			smp_store_release((u32 *)kaddr, src);
		else
			WRITE_ONCE(*(u32 *)kaddr, src);
		break;
	case 8:
#if (BITS_PER_LONG == 64)
		if (release)
			smp_store_release((u64 *)kaddr, src);
		else
			WRITE_ONCE(*(u64 *)kaddr, src);
#else
		if (release) {
#ifdef __BIG_ENDIAN
			smp_store_release((u32 *)kaddr, (u32) (src >> 32));
			WRITE_ONCE(*((u32 *)kaddr + 1), (u32) src);
#else
			smp_store_release((u32 *)kaddr, (u32) src);
			WRITE_ONCE(*((u32 *)kaddr + 1), (u32) (src >> 32));
#endif
		} else {
#ifdef __BIG_ENDIAN
			WRITE_ONCE(*(u32 *)kaddr, (u32) (src >> 32));
			WRITE_ONCE(*((u32 *)kaddr + 1), (u32) src);
#else
			WRITE_ONCE(*(u32 *)kaddr, (u32) src);
			WRITE_ONCE(*((u32 *)kaddr + 1), (u32) (src >> 32));
#endif
		}
#endif
		break;
	default:
		printk(KERN_ERR "Incorrect store length %zu\n", len);
	}
}

int deref_uptr_load(struct reg *dst_reg, struct reg *src_reg, s16 off, size_t len, int acquire,
		    int prefetch, struct do_on_cpu_map *map,
		    struct do_on_cpu_mem_op *next_pin,
		    struct do_on_cpu_ctx *ctx,
		    enum on_cpu_pass pass)
{
	unsigned long ptr = src_reg->v + off;
	unsigned long kaddr;
	bool tainted = src_reg->tainted;
	int ret;

	//printk("LOAD pass %d\n", pass);
	switch (pass) {
	case ON_CPU_PASS_PIN_PAGES:
		kaddr = do_on_cpu_map_find_kaddr(map, ptr, len, DO_ON_CPU_READ);
		if (!kaddr) {
			next_pin->addr = ptr;
			next_pin->len = len;
			next_pin->rw = DO_ON_CPU_READ;
			return -EAGAIN;
		}
		if (!prefetch) {
			if (tainted) {
				struct do_on_cpu_mem_op *mem_op;

				if (ctx->nr_tainted_mem_ops[
					ON_CPU_PASS_PIN_PAGES] >=
				    DO_ON_CPU_TAINTED_MEM_OPS_MAX)
					return -EINVAL;
				mem_op = &ctx->tainted_mem_ops[
						ctx->nr_tainted_mem_ops[
							ON_CPU_PASS_PIN_PAGES]++];
				mem_op->addr = ptr;
				mem_op->len = len;
				mem_op->rw = DO_ON_CPU_READ;
			}
			do_load(&dst_reg->v, kaddr, len, acquire);
			dst_reg->tainted = true;
		}
		break;
	case ON_CPU_PASS_STORES:
		if (!prefetch && tainted) {
			struct do_on_cpu_mem_op *mem_op;

			/*
			 * We can retry only before the first store, else we
			 * have corruption on target address mismatch.
			 */
			if (ctx->nr_stores > 0)
				ret = -EIO;
			else
				ret = -EAGAIN;
			if (ctx->nr_tainted_mem_ops[ON_CPU_PASS_STORES] >=
			    ctx->nr_tainted_mem_ops[ON_CPU_PASS_PIN_PAGES])
				return ret;
			mem_op = &ctx->tainted_mem_ops[ctx->nr_tainted_mem_ops[
						       ON_CPU_PASS_STORES]++];
			if (mem_op->addr != ptr || mem_op->len != len ||
			    mem_op->rw != DO_ON_CPU_READ) {
				return ret;
			}
		}
		kaddr = do_on_cpu_map_find_kaddr(map, ptr, len, DO_ON_CPU_READ);
		if (!kaddr) {
			/*
			 * Internal coherency issue. Should be validated by execution traces.
			 */
			WARN_ON_ONCE(1);
			return -EIO;
		}
		if (!prefetch) {
			do_load(&dst_reg->v, kaddr, len, acquire);
			dst_reg->tainted = true;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int deref_uptr_store(struct reg *dst_reg, s16 off, size_t len, u64 src,
		     int release, int prefetch, struct do_on_cpu_map *map,
		     struct do_on_cpu_mem_op *next_pin,
		     struct do_on_cpu_ctx *ctx,
		     enum on_cpu_pass pass)
{
	unsigned long ptr = dst_reg->v + off;
	unsigned long kaddr;
	bool tainted = dst_reg->tainted;
	int ret;

	//printk("STORE pass %d\n", pass);
	switch (pass) {
	case ON_CPU_PASS_PIN_PAGES:
		kaddr = do_on_cpu_map_find_kaddr(map, ptr, len, DO_ON_CPU_WRITE);
		if (!kaddr) {
			next_pin->addr = ptr;
			next_pin->len = len;
			next_pin->rw = DO_ON_CPU_WRITE;
			return -EAGAIN;
		}
		if (release)
			smp_mb();
		if (!prefetch) {
			if (tainted) {
				struct do_on_cpu_mem_op *mem_op;

				if (ctx->nr_tainted_mem_ops[
					ON_CPU_PASS_PIN_PAGES] >=
				    DO_ON_CPU_TAINTED_MEM_OPS_MAX)
					return -EINVAL;
				mem_op = &ctx->tainted_mem_ops[
						ctx->nr_tainted_mem_ops[
							ON_CPU_PASS_PIN_PAGES]++];
				mem_op->addr = ptr;
				mem_op->len = len;
				mem_op->rw = DO_ON_CPU_WRITE;
			}
		}
		break;
	case ON_CPU_PASS_STORES:
		if (!prefetch) {
			/*
			 * We can retry only for the first store, else we have
			 * corruption on target address mismatch.
			 */
			if (ctx->nr_stores > 0)
				ret = -EIO;
			else
				ret = -EAGAIN;
			if (tainted) {
				struct do_on_cpu_mem_op *mem_op;

				if (ctx->nr_tainted_mem_ops[
					ON_CPU_PASS_STORES] >=
				    ctx->nr_tainted_mem_ops[ON_CPU_PASS_PIN_PAGES])
					return ret;
				mem_op = &ctx->tainted_mem_ops[
						ctx->nr_tainted_mem_ops[
						       ON_CPU_PASS_STORES]++];
				if (mem_op->addr != ptr || mem_op->len != len ||
				    mem_op->rw != DO_ON_CPU_WRITE) {
					return ret;
				}
			}
		}
		kaddr = do_on_cpu_map_find_kaddr(map, ptr, len, DO_ON_CPU_WRITE);
		if (!kaddr) {
			/*
			 * Internal coherency issue. Should be validated by execution traces.
			 */
			WARN_ON_ONCE(1);
			return -EIO;
		}
		if (!prefetch) {
			do_store(kaddr, len, src, release);
			ctx->nr_stores++;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static
int do_branch(bool taken, bool tainted, struct do_on_cpu_ctx *ctx,
	      enum on_cpu_pass pass)
{
	if (!tainted)
		return 0;
	switch (pass) {
	case ON_CPU_PASS_PIN_PAGES:
		if (ctx->nr_tainted_branches[ON_CPU_PASS_PIN_PAGES] >=
		    DO_ON_CPU_TAINTED_BRANCH_MAX)
			return -EINVAL;
		if (taken)
			bitmap_set(ctx->tainted_branches,
				   ctx->nr_tainted_branches[
					ON_CPU_PASS_PIN_PAGES], 1);
		ctx->nr_tainted_branches[ON_CPU_PASS_PIN_PAGES]++;
		break;
	case ON_CPU_PASS_STORES:
	{
		int ret;

		/*
		 * We can retry only before the first store, else we may have
		 * corruption if branch direction does not match.
		 */
		if (ctx->nr_stores > 0)
			ret = -EIO;
		else
			ret = -EAGAIN;
		if (ctx->nr_tainted_branches[ON_CPU_PASS_STORES] >=
		    ctx->nr_tainted_branches[ON_CPU_PASS_PIN_PAGES])
			return ret;
		if (test_bit(ctx->nr_tainted_branches[
				ON_CPU_PASS_STORES]++, ctx->tainted_branches)
		    != taken)
			return ret;
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

int do_on_cpu_interpreter(const struct bpf_insn *bytecode, size_t len,
			  struct do_on_cpu_map *map,
			  struct do_on_cpu_mem_op *next_pin,
			  struct do_on_cpu_ctx *ctx,
			  int64_t *result,
			  enum on_cpu_pass pass)
{
	struct reg reg[MAX_BPF_REG];
	size_t pc = 0, nr_interpreted_insn = 0;
	int ret = 0;

	clear_regs(reg, MAX_BPF_REG);

	for (;;) {
		const struct bpf_insn *insn;

		if (pc == len) {
			/* Bytecode terminates. */
			break;
		}
		if (pc > len) {
			printk(KERN_ERR "Error: pc (%zu) overflows bytecode length (%zu)\n",
			       pc, len);
			ret = -EINVAL;
			goto end;

		}
		pc = array_index_nospec(pc, len);
		insn = &bytecode[pc];
		if (nr_interpreted_insn++ >= DO_ON_CPU_RETIRED_INSN_MAX) {
			printk(KERN_ERR "Error: Reached maximum number of interpreted insn (%d)\n",
			       DO_ON_CPU_RETIRED_INSN_MAX);
			ret = -EINVAL;
			goto end;
		}

		switch (insn->code) {
			/* Load from immediate. */
		case BPF_LD | BPF_W | BPF_IMM:
			reg[insn->dst_reg].v = (s64) insn->imm;
			reg[insn->dst_reg].tainted = false;
			pc++;
			break;
		case BPF_LD | BPF_DW | BPF_IMM:
			reg[insn->dst_reg].v = ((u64) (insn + 1)->imm << 32) | (u32) insn->imm;
			reg[insn->dst_reg].tainted = false;
			pc += 2;	/* Skip next insn. */
			break;

			/* Load from address. */
		case BPF_LDX | BPF_W | BPF_MEM:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u32), 0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_H | BPF_MEM:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u16), 0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_B | BPF_MEM:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u8), 0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_DW | BPF_MEM:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u64), 0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

			/* Load from address with acquire semantic. */
		case BPF_LDX | BPF_W | BPF_MEM_ACQ_REL:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u32), 1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_H | BPF_MEM_ACQ_REL:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u16), 1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_B | BPF_MEM_ACQ_REL:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u8), 1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_LDX | BPF_DW | BPF_MEM_ACQ_REL:
			ret = deref_uptr_load(&reg[insn->dst_reg], &reg[insn->src_reg], insn->off,
					sizeof(u64), 1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

			/* Store from immediate to address. */
		case BPF_ST | BPF_W | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u32), insn->imm, 0, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_H | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u16), insn->imm, 0, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_B | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u8), insn->imm, 0, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_DW | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u64), insn->imm, 0, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

			/* Store from immediate to address with release semantic. */
		case BPF_ST | BPF_W | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u32), insn->imm, 1, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_H | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u16), insn->imm, 1, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_B | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u8), insn->imm, 1, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_ST | BPF_DW | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u64), insn->imm, 1, 0,
					       map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

			/* Store from register to address. */
		case BPF_STX | BPF_W | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u32), reg[insn->src_reg].v,
					       0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_H | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u16), reg[insn->src_reg].v,
					       0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_B | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u8), reg[insn->src_reg].v,
					       0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_DW | BPF_MEM:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u64), reg[insn->src_reg].v,
					       0, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

			/* Store from register to address with release semantic. */
		case BPF_STX | BPF_W | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u32), reg[insn->src_reg].v,
					       1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_H | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u16), reg[insn->src_reg].v,
					       1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_B | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u8), reg[insn->src_reg].v,
					       1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;
		case BPF_STX | BPF_DW | BPF_MEM_ACQ_REL:
			ret = deref_uptr_store(&reg[insn->dst_reg], insn->off,
					       sizeof(u64), reg[insn->src_reg].v,
					       1, 0, map, next_pin, ctx, pass);
			if (ret)
				goto error_mem;
			pc++;
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
			reg[insn->dst_reg].v += (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
			reg[insn->dst_reg].v += reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_SUB | BPF_K:
			reg[insn->dst_reg].v -= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_SUB | BPF_X:
			reg[insn->dst_reg].v -= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_MUL | BPF_K:
			reg[insn->dst_reg].v *= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_MUL | BPF_X:
			reg[insn->dst_reg].v *= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_DIV | BPF_K:
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v / (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
			if (!(u32) reg[insn->src_reg].v) {
				printk(KERN_ERR "Error: Divide by 0\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v / (u32) reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_OR | BPF_K:
			reg[insn->dst_reg].v |= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_OR | BPF_X:
			reg[insn->dst_reg].v |= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_AND | BPF_K:
			reg[insn->dst_reg].v &= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_AND | BPF_X:
			reg[insn->dst_reg].v &= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_LSH | BPF_K:
			reg[insn->dst_reg].v = reg[insn->dst_reg].v << insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
			if (reg[insn->src_reg].v >= 32 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Left shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = reg[insn->dst_reg].v << reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_RSH | BPF_K:
			reg[insn->dst_reg].v = reg[insn->dst_reg].v >> insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_RSH | BPF_X:
			if (reg[insn->src_reg].v >= 32 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Right shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = reg[insn->dst_reg].v >> reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_NEG:
			reg[insn->dst_reg].v = -reg[insn->dst_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_MOD | BPF_K:
			reg[insn->dst_reg].v %= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
			if (reg[insn->src_reg].v == 0) {
				printk(KERN_ERR "Error: Modulo by 0\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v %= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_XOR | BPF_K:
			reg[insn->dst_reg].v ^= (u32) insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
			reg[insn->dst_reg].v ^= reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
			reg[insn->dst_reg].v = (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU | BPF_MOV | BPF_X:
			reg[insn->dst_reg].v = reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU | BPF_ARSH | BPF_K:
			reg[insn->dst_reg].v = (s64) reg[insn->dst_reg].v >> insn->imm;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU | BPF_ARSH | BPF_X:
			if (reg[insn->src_reg].v >= 32 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Right shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = (s64) reg[insn->dst_reg].v >> reg[insn->src_reg].v;
			reg[insn->dst_reg].v = (u32) reg[insn->dst_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;

		case BPF_ALU64 | BPF_ADD | BPF_K:
			reg[insn->dst_reg].v += (u64)(s64) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_ADD | BPF_X:
			reg[insn->dst_reg].v += reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_SUB | BPF_K:
			reg[insn->dst_reg].v -= (u64)(s64) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_SUB | BPF_X:
			reg[insn->dst_reg].v -= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_MUL | BPF_K:
			reg[insn->dst_reg].v *= (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MUL | BPF_X:
			reg[insn->dst_reg].v *= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_DIV | BPF_K:
			reg[insn->dst_reg].v /= (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_DIV | BPF_X:
			if (!reg[insn->src_reg].v) {
				printk(KERN_ERR "Error: Divide by 0\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v /= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_OR | BPF_K:
			reg[insn->dst_reg].v |= (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_OR | BPF_X:
			reg[insn->dst_reg].v |= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_AND | BPF_K:
			reg[insn->dst_reg].v &= (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_AND | BPF_X:
			reg[insn->dst_reg].v &= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_LSH | BPF_K:
			reg[insn->dst_reg].v = reg[insn->dst_reg].v << insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_LSH | BPF_X:
			if (reg[insn->src_reg].v >= 64 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Left shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = reg[insn->dst_reg].v << reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_RSH | BPF_K:
			reg[insn->dst_reg].v = reg[insn->dst_reg].v >> insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_RSH | BPF_X:
			if (reg[insn->src_reg].v >= 64 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Right shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = reg[insn->dst_reg].v >> reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_NEG:
			reg[insn->dst_reg].v = -reg[insn->dst_reg].v;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOD | BPF_K:
			reg[insn->dst_reg].v %= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOD | BPF_X:
			if (reg[insn->src_reg].v == 0) {
				printk(KERN_ERR "Error: modulo by 0\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v %= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_XOR | BPF_K:
			reg[insn->dst_reg].v ^= (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_XOR | BPF_X:
			reg[insn->dst_reg].v ^= reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOV | BPF_K:
			reg[insn->dst_reg].v = (u32) insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOV | BPF_X:
			reg[insn->dst_reg].v = reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			reg[insn->dst_reg].v = (s64) reg[insn->dst_reg].v >> insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			if (reg[insn->src_reg].v >= 64 || reg[insn->src_reg].v < 0) {
				printk(KERN_ERR "Error: Right shift by %lld undefined.\n",
				       reg[insn->src_reg].v);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->dst_reg].v = (s64) reg[insn->dst_reg].v >> reg[insn->src_reg].v;
			reg[insn->dst_reg].tainted = reg[insn->dst_reg].tainted ||
						     reg[insn->src_reg].tainted;
			pc++;
			break;

		case BPF_ALU | BPF_MB:
		case BPF_ALU64 | BPF_MB:
			/* Issue memory barrier instruction. */
			smp_mb();
			pc++;
			break;

		case BPF_JMP | BPF_JA:
			ret = do_branch(true, false, ctx, pass);
			if (ret)
				goto error_branch;
			pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v == (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v == (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JEQ | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v == reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v == reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGT | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v > (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v > (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGT | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v > reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v > reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v >= (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v >= (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGE | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v >= reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v >= reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSET | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v & (u32) insn->imm,
					reg[insn->dst_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v & (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSET | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v & reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v & reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JNE | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v != (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v != (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JNE | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v != reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v != reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLT | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v < (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v < (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLT | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v < reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v < reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLE | BPF_K:
			ret = do_branch(reg[insn->dst_reg].v <= (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v <= (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLE | BPF_X:
			ret = do_branch(reg[insn->dst_reg].v <= reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if (reg[insn->dst_reg].v <= reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGT | BPF_K:
			ret = do_branch((s64) reg[insn->dst_reg].v > insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v > insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGT | BPF_X:
			ret = do_branch((s64) reg[insn->dst_reg].v > (s64) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v > (s64) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGE | BPF_K:
			ret = do_branch((s64) reg[insn->dst_reg].v >= insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v >= insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGE | BPF_X:
			ret = do_branch((s64) reg[insn->dst_reg].v >= (s64) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v >= (s64) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLT | BPF_K:
			ret = do_branch((s64) reg[insn->dst_reg].v < insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v < insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLT | BPF_X:
			ret = do_branch((s64) reg[insn->dst_reg].v < (s64) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v < (s64) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLE | BPF_K:
			ret = do_branch((s64) reg[insn->dst_reg].v <= insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v <= insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLE | BPF_X:
			ret = do_branch((s64) reg[insn->dst_reg].v <= (s64) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s64) reg[insn->dst_reg].v <= (s64) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;

		case BPF_JMP32 | BPF_JA:
			ret = do_branch(true, false, ctx, pass);
			if (ret)
				goto error_branch;
			pc += insn->off;
			pc++;
		case BPF_JMP32 | BPF_JEQ | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v == (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v == (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v == (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v == (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGT | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v > (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v > (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGT | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v > (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v > (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGE | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v >= (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v >= (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGE | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v >= (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v >= (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSET | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v & (u32) insn->imm,
					reg[insn->dst_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v & (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSET | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v & (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v & (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JNE | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v != (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v != (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JNE | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v != (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v != (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLT | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v < (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v < (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLT | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v < (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v < (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLE | BPF_K:
			ret = do_branch((u32) reg[insn->dst_reg].v <= (u32) insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v <= (u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLE | BPF_X:
			ret = do_branch((u32) reg[insn->dst_reg].v <= (u32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((u32) reg[insn->dst_reg].v <= (u32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_K:
			ret = do_branch((s32) reg[insn->dst_reg].v > insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v > insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_X:
			ret = do_branch((s32) reg[insn->dst_reg].v > (s32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v > (s32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_K:
			ret = do_branch((s32) reg[insn->dst_reg].v >= insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v >= insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_X:
			ret = do_branch((s32) reg[insn->dst_reg].v >= (s32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v >= (s32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_K:
			ret = do_branch((s32) reg[insn->dst_reg].v < insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v < insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_X:
			ret = do_branch((s32) reg[insn->dst_reg].v < (s32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v < (s32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			ret = do_branch((s32) reg[insn->dst_reg].v <= insn->imm,
					reg[insn->dst_reg].tainted, ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v <= insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			ret = do_branch((s32) reg[insn->dst_reg].v <= (s32) reg[insn->src_reg].v,
					reg[insn->dst_reg].tainted || reg[insn->src_reg].tainted,
					ctx, pass);
			if (ret)
				goto error_branch;
			if ((s32) reg[insn->dst_reg].v <= (s32) reg[insn->src_reg].v)
				pc += insn->off;
			pc++;
			break;

		case BPF_JMP | BPF_EXIT:
		case BPF_JMP32 | BPF_EXIT:
			goto end;

		default:
			printk(KERN_ERR "Error: Unsupported insn code %d\n",
				insn->code);
			ret = -EINVAL;
			goto end;
		}
	}
end:
	if (!ret && result)
		*result = reg[BPF_REG_0].v;
	if (ret && ctx->nr_stores > 0)
		ret = -EIO;
	return ret;

error_mem:
	if (ret != -EAGAIN && ret != -ERESTARTSYS) {
		printk(KERN_ERR "do_on_cpu: pc (%zu) error (%d) performing memory access\n",
		       pc, ret);
		show_regs(pc, reg, MAX_BPF_REG);
	}
	goto end;
error_branch:
	if (ret != -EAGAIN && ret != -ERESTARTSYS) {
		printk(KERN_ERR "do_on_cpu: pc (%zu) error (%d) performing branch\n",
		       pc, ret);
		show_regs(pc, reg, MAX_BPF_REG);
	}
	goto end;
}
