/* SPDX-License-Identifier: GPL-2.0 or LGPL-2.1 */
#ifndef _DO_ON_CPU_PRIVATE_H
#define _DO_ON_CPU_PRIVATE_H

#include <linux/bpf.h>

#ifndef BPF_JMP32
#define BPF_JMP32	0x06
#endif

#ifndef BPF_MEM_ACQ_REL
#define BPF_MEM_ACQ_REL	0xe0
#endif

/* ALU */
#ifndef BPF_MB
#define BPF_MB		0xd0
#endif

/*
 * Maximum number of instructions expected for a bytecode.
 */
#define DO_ON_CPU_LEN_MAX		32

/*
 * Maximum number of retired instructions per bytecode.
 */
#define DO_ON_CPU_RETIRED_INSN_MAX	65536

/*
 * Invocation of do_on_cpu supports touching a maximum of 8 pages.
 * Keep those in an array on the stack of the do_on_cpu system call.
 */
#define DO_ON_CPU_PAGES_MAX		8

/* Maximum address range size (aligned on SHMLBA) per page. */
#define CPU_OP_RANGE_PER_PAGE_MAX	SHMLBA

/*
 * Minimum value for sysctl_do_on_cpu_va_max_bytes is the maximum virtual
 * memory space needed by one do_on_cpu system call.
 */
#define DO_ON_CPU_VA_MAX_BYTES_MIN	\
		(DO_ON_CPU_PAGES_MAX * CPU_OP_RANGE_PER_PAGE_MAX)

/*
 * Maximum number of loads/stores to tainted addresses (addresses derived
 * from a load from user-space).
 */
#define DO_ON_CPU_TAINTED_MEM_OPS_MAX	4

/*
 * Maximum number of tainted branches (branches depending on conditions
 * comparing registers derived from a load from user-space). 4096 tainted
 * branches use 512 bytes of stack space.
 */
#define DO_ON_CPU_TAINTED_BRANCH_MAX	4096

/*
 * The interpreter is done in two passes: the first pass gets references
 * to all user-space pages that need to be accessed, and the second pass
 * performs store side-effects.
 */
enum on_cpu_pass {
	ON_CPU_PASS_PIN_PAGES,
	ON_CPU_PASS_STORES,
	_NR_ON_CPU_PASSES,
};

enum do_on_cpu_rw {
	DO_ON_CPU_READ,
	DO_ON_CPU_WRITE,
};

struct do_on_cpu_page {
	unsigned long uaddr_base;
	struct page *page;
	enum do_on_cpu_rw rw;
	int used;
};

struct do_on_cpu_vmap {
	unsigned long kaddr_base;
	unsigned long uaddr_base;
	unsigned long uaddr_end;
	unsigned int nr_pages;
	int used;
};

/*
 * Translation between user-space addresses and kernel virtual mapping.
 * Pages which are contiguous in the user-space mapping are mapped into the
 * same kernel virtual mapping.
 * Access permission checks (read vs write) need to be performed using the
 * pages rw field. The permissions are derived from those of the userspace's
 * vma returned by get_user_pages() along with the pages.
 */
struct do_on_cpu_map {
	struct do_on_cpu_page doc_page[DO_ON_CPU_PAGES_MAX];
	struct do_on_cpu_vmap vmap[DO_ON_CPU_PAGES_MAX];
	size_t nr_pages;
	size_t nr_vmaps;
};

struct do_on_cpu_mem_op {
	unsigned long addr;
	size_t len;
	enum do_on_cpu_rw rw;
};

struct do_on_cpu_ipi_args {
	struct bpf_insn *bytecode;		/* input */
	u32 len;				/* input: bytecode length */
	struct do_on_cpu_map *map;		/* input: memory translation */
	struct do_on_cpu_mem_op *next_pin;	/* output */
	int ret;				/* output: return code */
	int64_t *result;			/* output: interpreter result */
};

/*
 * Interpreter context for validation of memory accesses to tainted addresses
 * and conditional branches depending on tainted conditions.
 */
struct do_on_cpu_ctx {
	unsigned long tainted_branches[
		DO_ON_CPU_TAINTED_BRANCH_MAX / 8 / sizeof(unsigned long)];
	size_t nr_tainted_branches[_NR_ON_CPU_PASSES];
	struct do_on_cpu_mem_op tainted_mem_ops[DO_ON_CPU_TAINTED_MEM_OPS_MAX];
	size_t nr_tainted_mem_ops[_NR_ON_CPU_PASSES];
	size_t nr_stores;
};

int do_on_cpu_validate(struct bpf_insn *bytecode, size_t len);
int do_on_cpu_interpreter(const struct bpf_insn *bytecode, size_t len,
			  struct do_on_cpu_map *map,
			  struct do_on_cpu_mem_op *next_pin,
			  struct do_on_cpu_ctx *ctx,
			  int64_t *result,
			  enum on_cpu_pass pass);

#endif /* _DO_ON_CPU_PRIVATE_H */
