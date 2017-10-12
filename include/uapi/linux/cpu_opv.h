/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CPU_OPV_H
#define _UAPI_LINUX_CPU_OPV_H

/*
 * linux/cpu_opv.h
 *
 * Per-CPU-atomic operation vector system call API
 *
 * Copyright (c) 2017-2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/types.h>

#define CPU_OP_VEC_LEN_MAX		16
#define CPU_OP_ARG_LEN_MAX		24
/* Maximum data len per operation. */
#define CPU_OP_DATA_LEN_MAX		4096
/*
 * Maximum data len for overall vector. Restrict the amount of user-space
 * data touched by the kernel in interrupt-off or IPI handler context, so it
 * does not introduce long interrupt latencies.
 * This allows one copy of up to 4096 bytes, and 15 operations touching 8
 * bytes each.
 * This limit is applied to the sum of length specified for all operations
 * in a vector.
 */
#define CPU_OP_MEMCPY_EXPECT_LEN	4096
#define CPU_OP_EXPECT_LEN		8
#define CPU_OP_VEC_DATA_LEN_MAX		\
	(CPU_OP_MEMCPY_EXPECT_LEN +	\
	 (CPU_OP_VEC_LEN_MAX - 1) * CPU_OP_EXPECT_LEN)

enum cpu_op_flags {
	CPU_OP_NR_FLAG =	(1U << 0),
};

enum cpu_op_type {
	/* compare */
	CPU_COMPARE_EQ_OP,
	CPU_COMPARE_NE_OP,
	/* memcpy */
	CPU_MEMCPY_OP,
	/* arithmetic */
	CPU_ADD_OP,
	/* bitwise */
	CPU_OR_OP,
	CPU_AND_OP,
	CPU_XOR_OP,
	/* shift */
	CPU_LSHIFT_OP,
	CPU_RSHIFT_OP,
	/* memory barrier */
	CPU_MB_OP,

	NR_CPU_OPS,
};

/* Vector of operations to perform. Limited to 16. */
struct cpu_op {
	/* enum cpu_op_type. */
	__s32 op;
	/* data length, in bytes. */
	__u32 len;
	union {
		struct {
			__u64 a;
			__u64 b;
			__u8 expect_fault_a;
			__u8 expect_fault_b;
		} compare_op;
		struct {
			__u64 dst;
			__u64 src;
			__u8 expect_fault_dst;
			__u8 expect_fault_src;
		} memcpy_op;
		struct {
			__u64 p;
			__s64 count;
			__u8 expect_fault_p;
		} arithmetic_op;
		struct {
			__u64 p;
			__u64 mask;
			__u8 expect_fault_p;
		} bitwise_op;
		struct {
			__u64 p;
			__u32 bits;
			__u8 expect_fault_p;
		} shift_op;
		char __padding[CPU_OP_ARG_LEN_MAX];
	} u;
};

#endif /* _UAPI_LINUX_CPU_OPV_H */
