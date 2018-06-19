// SPDX-License-Identifier: LGPL-2.1
/*
 * Basic test coverage for do_on_cpu system call.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sched.h>
#include <linux/bpf.h>

#include "../kselftest.h"

#include "cpu-op.h"
#include "do-on-cpu-insn.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define TESTBUFLEN	4096
#define TESTBUFLEN_CMP	16

/* Maximum page size on Linux for normal pages. */
#define TESTBUFLEN_PAGE_MAX	65536

#define NR_PF_ARRAY	16384
#define PF_ARRAY_LEN	4096

#define NR_HUGE_ARRAY	512
#define HUGEMAPLEN	(NR_HUGE_ARRAY * PF_ARRAY_LEN)

#define DO_ON_CPU_RETIRED_INSN_MAX	8192
#define DO_ON_CPU_LEN_MAX		32
#define DO_ON_CPU_PAGES_MAX		8

/* 64 MB arrays for page fault testing. */
char pf_array_dst[NR_PF_ARRAY][PF_ARRAY_LEN];
char pf_array_src[NR_PF_ARRAY][PF_ARRAY_LEN];

struct unaligned_test {
	char padding[PF_ARRAY_LEN - 2];
	uint32_t data;
} __attribute__ ((packed, aligned(PF_ARRAY_LEN)));

static int test_ops_supported(void)
{
	const char *test_name = "test_ops_supported";
	const char *subtest;
	int ret;

	subtest = "bytecode length test";
	/* Bytecode length. */
	ret = do_on_cpu(NULL, 0, NULL, -1, DO_ON_CPU_LEN_MAX_FLAG);
	if (ret < 0) {
		ksft_test_result_fail("%s %s: returned with %d, errno = %s\n",
				      test_name, subtest, ret, strerror(errno));
		return -1;
	}
	if (ret < DO_ON_CPU_LEN_MAX) {
		ksft_test_result_fail("%s %s: only %d instruction supported, expecting at least %d\n",
				      test_name, subtest, ret, DO_ON_CPU_LEN_MAX);
		return -1;
	}

	subtest = "retired instructions test";
	/* Number of retired instructions. */
	ret = do_on_cpu(NULL, 0, NULL, -1, DO_ON_CPU_RETIRED_INSN_MAX_FLAG);
	if (ret < 0) {
		ksft_test_result_fail("%s %s: returned with %d, errno = %s\n",
				      test_name, subtest, ret, strerror(errno));
		return -1;
	}
	if (ret < DO_ON_CPU_RETIRED_INSN_MAX) {
		ksft_test_result_fail("%s %s: only %d instructions retired supported, expecting at least %d\n",
				      test_name, subtest, ret, DO_ON_CPU_RETIRED_INSN_MAX);
		return -1;
	}

	subtest = "number of pages test";
	/* Number of pages touched. */
	ret = do_on_cpu(NULL, 0, NULL, -1, DO_ON_CPU_PAGES_MAX_FLAG);
	if (ret < 0) {
		ksft_test_result_fail("%s %s: returned with %d, errno = %s\n",
				      test_name, subtest, ret, strerror(errno));
		return -1;
	}
	if (ret < DO_ON_CPU_PAGES_MAX) {
		ksft_test_result_fail("%s %s: only %d pages accesses supported, expecting at least %d\n",
				      test_name, subtest, ret, DO_ON_CPU_PAGES_MAX);
		return -1;
	}

	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_eq_len_op(char *a, char *b, size_t len)
{
	int64_t res;
	int ret, cpu;

	enum {
		BPF_LABEL_LOOP8 = 8,
		BPF_LABEL_BRANCH8_1 = 9,
		BPF_LABEL_BRANCH8_2 = 13,
		BPF_LABEL_LOOP1 = 16,
		BPF_LABEL_BRANCH1_1 = 17,
		BPF_LABEL_BRANCH1_2 = 21,
		BPF_LABEL_BRANCH1_3 = 24,
	};

	/*
	 * r1 is temporary register,
	 * r2 is a iterator,
	 * r3 is b iterator,
	 * r4 is b + (len & ~7)		// end of 8-byte copy
	 * r5 is b + len		// end of 1-byte copy
	 */
	struct bpf_insn bytecode[] = {
		[0] = BPFI_LD_IMM64(BPF_REG_2, BPF_PTR_TO_V(a)),
		[2] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(b)),
		[4] = BPFI_LD_IMM64(BPF_REG_4, BPF_PTR_TO_V(b) + (len & ~7)),
		[6] = BPFI_LD_IMM64(BPF_REG_5, BPF_PTR_TO_V(b) + len),

		/* 8-byte loop target. */
		[BPF_LABEL_LOOP8] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_4,
					       BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH8_1),

		[BPF_LABEL_BRANCH8_1] = BPFI_LDX(BPF_DW, BPF_REG_0, BPF_REG_2, 0),
		[10] = BPFI_LDX(BPF_DW, BPF_REG_1, BPF_REG_3, 0),
		[11] = BPFI_SUB64_X(BPF_REG_0, BPF_REG_1),
		[12] = BPFI_JNE_K(BPF_REG_0, 0,
				  BPF_LABEL_BRANCH1_3 - BPF_LABEL_BRANCH8_2),

		/* Same, test next double-word. */
		[BPF_LABEL_BRANCH8_2] = BPFI_ADD64_K(BPF_REG_2, 8),
		[14] = BPFI_ADD64_K(BPF_REG_3, 8),
		[15] = BPFI_JA_K(BPF_LABEL_LOOP8 - BPF_LABEL_LOOP1),

		/* 1-byte loop target. */
		[BPF_LABEL_LOOP1] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_5,
					       BPF_LABEL_BRANCH1_3 - BPF_LABEL_BRANCH1_1),

		[BPF_LABEL_BRANCH1_1] = BPFI_LDX(BPF_B, BPF_REG_0, BPF_REG_2, 0),
		[18] = BPFI_LDX(BPF_B, BPF_REG_1, BPF_REG_3, 0),
		[19] = BPFI_SUB64_X(BPF_REG_0, BPF_REG_1),
		[20] = BPFI_JNE_K(BPF_REG_0, 0, BPF_LABEL_BRANCH1_3 - BPF_LABEL_BRANCH1_2),

		/* Same, test next byte. */
		[BPF_LABEL_BRANCH1_2] = BPFI_ADD64_K(BPF_REG_2, 1),
		[22] = BPFI_ADD64_K(BPF_REG_3, 1),
		[23] = BPFI_JA_K(BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH1_3),

		/* Completed. BPF_REG_0 contains the return value. */
		[BPF_LABEL_BRANCH1_3] = BPFI_EXIT(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				&res, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	if (!ret)
		ret = (int) !!res;

	return ret;
}

static int test_compare_eq_op(void *a, void *b, size_t len)
{
	int64_t res;
	int ret, cpu;
	unsigned int bpf_size;

	switch (len) {
	case 0:
		return 0;
	case 1:	bpf_size = BPF_B;
		break;
	case 2: bpf_size = BPF_H;
		break;
	case 4:	bpf_size = BPF_W;
		break;
	case 8:	bpf_size = BPF_DW;
		break;
	default:
		return test_compare_eq_len_op(a, b, len);
	}

	{
		struct bpf_insn bytecode[] = {
			BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(a)),
			BPFI_LDX(bpf_size, BPF_REG_0, BPF_REG_0, 0),
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(b)),
			BPFI_LDX(bpf_size, BPF_REG_1, BPF_REG_1, 0),
			BPFI_SUB64_X(BPF_REG_0, BPF_REG_1),
		};

		do {
			cpu = cpu_op_get_current_cpu();
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		ret = (int) !!res;
	return ret;
}

static int test_compare_eq_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq same";

	/* Test compare_eq */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;

	/* Start iteration at 0. */
	for (i = 0; i <= TESTBUFLEN; i++) {
		ret = test_compare_eq_op(buf2, buf1, i);
		if (ret < 0) {
			ksft_test_result_fail("%s test len=%d: returned with %d, errno = %s\n",
					      test_name, i, ret, strerror(errno));
			return -1;
		}
		if (ret > 0) {
			ksft_test_result_fail("%s test len=%d: unexpected value %d. Should be %d.\n",
					      test_name, i, ret, 0);
			return -1;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_eq_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq different";

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i == 0 ? 1 : (char) i;
	memset(buf2, 0, TESTBUFLEN);

	/* Start iteration at 1. Last is different. */
	for (i = 1; i <= TESTBUFLEN; i++) {
		if (i > 1)
			buf2[i - 2] = (char)(i - 2) == 0 ? 1 : (char) (i - 2);
		ret = test_compare_eq_op(buf2, buf1, i);
		if (ret < 0) {
			ksft_test_result_fail("%s test len=%d: returned with %d, errno = %s\n",
					      test_name, i, ret, strerror(errno));
			return -1;
		}
		if (ret == 0) {
			ksft_test_result_fail("%s test len=%d: unexpected value %d. Should be %d.\n",
					      test_name, i, ret, 1);
			return -1;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_len_op(char *dst, char *src, size_t len)
{
	int ret, cpu;

	enum {
		BPF_LABEL_LOOP8 = 8,
		BPF_LABEL_BRANCH8_1 = 9,
		BPF_LABEL_LOOP1 = 14,
		BPF_LABEL_BRANCH1_1 = 15,
		BPF_LABEL_BRANCH1_2 = 20,
	};

	/*
	 * r1 is temporary register,
	 * r2 is dst iterator,
	 * r3 is src iterator,
	 * r4 is src + (len & ~7)	// end of 8-byte copy
	 * r5 is src + len		// end of 1-byte copy
	 */
	struct bpf_insn bytecode[] = {
		[0] = BPFI_LD_IMM64(BPF_REG_2, BPF_PTR_TO_V(dst)),
		[2] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(src)),
		[4] = BPFI_LD_IMM64(BPF_REG_4, BPF_PTR_TO_V(src) + (len & ~7)),
		[6] = BPFI_LD_IMM64(BPF_REG_5, BPF_PTR_TO_V(src) + len),

		/* 8-byte copy loop target. */
		[BPF_LABEL_LOOP8] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_4,
					       BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH8_1),

		[BPF_LABEL_BRANCH8_1] = BPFI_LDX(BPF_DW, BPF_REG_1, BPF_REG_3, 0),
		[10] = BPFI_STX(BPF_DW, BPF_REG_2, BPF_REG_1, 0),

		[11] = BPFI_ADD64_K(BPF_REG_2, 8),
		[12] = BPFI_ADD64_K(BPF_REG_3, 8),
		[13] = BPFI_JA_K(BPF_LABEL_LOOP8 - BPF_LABEL_LOOP1),

		/* 1-byte copy loop target. */
		[BPF_LABEL_LOOP1] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_5,
					       BPF_LABEL_BRANCH1_2 - BPF_LABEL_BRANCH1_1),

		[BPF_LABEL_BRANCH1_1] = BPFI_LDX(BPF_B, BPF_REG_1, BPF_REG_3, 0),
		[16] = BPFI_STX(BPF_B, BPF_REG_2, BPF_REG_1, 0),

		[17] = BPFI_ADD64_K(BPF_REG_2, 1),
		[18] = BPFI_ADD64_K(BPF_REG_3, 1),
		[19] = BPFI_JA_K(BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH1_2),

		/* Completed. */
		[BPF_LABEL_BRANCH1_2] = BPFI_EXIT(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_op(void *dst, void *src, size_t len)
{
	int ret, cpu;
	unsigned int bpf_size;

	switch (len) {
	case 0:
		return 0;
	case 1:	bpf_size = BPF_B;
		break;
	case 2: bpf_size = BPF_H;
		break;
	case 4:	bpf_size = BPF_W;
		break;
	case 8:	bpf_size = BPF_DW;
		break;
	default:
		return test_memcpy_len_op(dst, src, len);
	}

	{
		struct bpf_insn bytecode[] = {
			BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(dst)),
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(src)),
			BPFI_LDX(bpf_size, BPF_REG_1, BPF_REG_1, 0),
			BPFI_STX(bpf_size, BPF_REG_0, BPF_REG_1, 0),
		};

		do {
			cpu = cpu_op_get_current_cpu();
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					NULL, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	return ret;
}

static int test_memcpy(void)
{
	int i, j, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy";

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++) {
		memset(buf1, 0, TESTBUFLEN);
		memset(buf2, 0, TESTBUFLEN);

		for (j = 0; j < TESTBUFLEN; j++)
			buf1[j] = (char)j;

		ret = test_memcpy_op(buf2, buf1, i);
		if (ret) {
			ksft_test_result_fail("%s test len=%d: returned with %d, errno = %s\n",
					      test_name, i, ret, strerror(errno));
			return -1;
		}
		for (j = 0; j < i; j++) {
			if (buf2[j] != (char)j) {
				ksft_test_result_fail("%s test len=%d: unexpected value at offset %d. Found %d. Should be %d.\n",
						      test_name, i, j, buf2[j], (char)j);
				return -1;
			}
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_store_release_len_op(
		void *dst1, void *src1, size_t len1,
		void *dst2, void *src2, size_t len2)
{
	int ret, cpu;
	unsigned int bpf_size2;

	switch (len2) {
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	enum {
		BPF_LABEL_LOOP8 = 8,
		BPF_LABEL_BRANCH8_1 = 9,
		BPF_LABEL_LOOP1 = 14,
		BPF_LABEL_BRANCH1_1 = 15,
		BPF_LABEL_BRANCH1_2 = 20,
	};

	struct bpf_insn bytecode[] = {
		/*
		 * r1 is temporary register,
		 * r2 is dst1 iterator,
		 * r3 is src1 iterator,
		 * r4 is src1 + (len1 & ~7)	// end of 8-byte copy
		 * r5 is src1 + len1		// end of 1-byte copy
		 * r6 is v
		 */
		[0] = BPFI_LD_IMM64(BPF_REG_2, BPF_PTR_TO_V(dst1)),
		[2] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(src1)),
		[4] = BPFI_LD_IMM64(BPF_REG_4, BPF_PTR_TO_V(src1) + (len1 & ~7)),
		[6] = BPFI_LD_IMM64(BPF_REG_5, BPF_PTR_TO_V(src1) + len1),

		/* 8-byte copy loop target. */
		[BPF_LABEL_LOOP8] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_4,
					       BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH8_1),

		[BPF_LABEL_BRANCH8_1] = BPFI_LDX(BPF_DW, BPF_REG_1, BPF_REG_3, 0),
		[10] = BPFI_STX(BPF_DW, BPF_REG_2, BPF_REG_1, 0),

		[11] = BPFI_ADD64_K(BPF_REG_2, 8),
		[12] = BPFI_ADD64_K(BPF_REG_3, 8),
		[13] = BPFI_JA_K(BPF_LABEL_LOOP8 - BPF_LABEL_LOOP1),

		/* 1-byte copy loop target. */
		[BPF_LABEL_LOOP1] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_5,
					       BPF_LABEL_BRANCH1_2 - BPF_LABEL_BRANCH1_1),

		[BPF_LABEL_BRANCH1_1] = BPFI_LDX(BPF_B, BPF_REG_1, BPF_REG_3, 0),
		[16] = BPFI_STX(BPF_B, BPF_REG_2, BPF_REG_1, 0),

		[17] = BPFI_ADD64_K(BPF_REG_2, 1),
		[18] = BPFI_ADD64_K(BPF_REG_3, 1),
		[19] = BPFI_JA_K(BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH1_2),

		/* Completed, do store-release. */

		[BPF_LABEL_BRANCH1_2] = BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(dst2)),
		[22] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(src2)),
		[24] = BPFI_LDX(bpf_size2, BPF_REG_1, BPF_REG_1, 0),
		[25] = BPFI_STX_RELEASE(bpf_size2, BPF_REG_0, BPF_REG_1, 0),

		[26] = BPFI_EXIT(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_store_release_op(void *dst1, void *src1, size_t len1,
		void *dst2, void *src2, size_t len2)
{
	int ret, cpu;
	unsigned int bpf_size1, bpf_size2;

	switch (len1) {
	case 1:	bpf_size1 = BPF_B;
		break;
	case 2: bpf_size1 = BPF_H;
		break;
	case 4:	bpf_size1 = BPF_W;
		break;
	case 8:	bpf_size1 = BPF_DW;
		break;
	default:
		return test_memcpy_store_release_len_op(dst1, src1, len1,
							dst2, src2, len2);
	}

	switch (len2) {
	case 0:
		return -EINVAL;
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	{
		struct bpf_insn bytecode[] = {
			BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(dst1)),
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(src1)),
			BPFI_LDX(bpf_size1, BPF_REG_1, BPF_REG_1, 0),
			BPFI_STX(bpf_size1, BPF_REG_0, BPF_REG_1, 0),
			BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(dst2)),
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(src2)),
			BPFI_LDX(bpf_size2, BPF_REG_1, BPF_REG_1, 0),
			BPFI_STX_RELEASE(bpf_size2, BPF_REG_0, BPF_REG_1, 0),
		};

		do {
			cpu = cpu_op_get_current_cpu();
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					NULL, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	return ret;

}

static int test_memcpy_store_release(void)
{
	int i, j, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	int v1, v2;
	const char *test_name = "test_memcpy_store_release";

	/* Test memcpy store release */
	for (i = 0; i < TESTBUFLEN; i++) {
		v1 = 42;
		v2 = 0;
		memset(buf1, 0, TESTBUFLEN);
		memset(buf2, 0, TESTBUFLEN);

		for (j = 0; j < TESTBUFLEN; j++)
			buf1[j] = (char)j;

		ret = test_memcpy_store_release_op(buf2, buf1, i, &v2, &v1, sizeof(v1));
		if (ret) {
			ksft_test_result_fail("%s test len=%d: returned with %d, errno = %s\n",
					      test_name, i, ret, strerror(errno));
			return -1;
		}
		for (j = 0; j < i; j++) {
			if (buf2[j] != (char)j) {
				ksft_test_result_fail("%s test len=%d: unexpected value at offset %d. Found %d. Should be %d.\n",
						      test_name, i, j, buf2[j], (char)j);
				return -1;
			}
		}
		if (v2 != v1) {
			ksft_test_result_fail("%s test len=%d: unexpected value %d. Should be %d.\n",
					      test_name, i, v2, v1);
			return -1;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_add(void)
{
	int orig_v = 42, v, ret;
	int increment = 1;
	const char *test_name = "test_add";

	v = orig_v;
	ret = cpu_op_add(&v, increment, sizeof(v), cpu_op_get_current_cpu());
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increment) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v,
				      orig_v + increment);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_add_release(void)
{
	int orig_v = 42, v, ret;
	int increment = 1;
	const char *test_name = "test_add_release";

	v = orig_v;
	ret = cpu_op_add_release(&v, increment, sizeof(v), cpu_op_get_current_cpu());
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increment) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v,
				      orig_v + increment);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_two_add_op(void *v, size_t len, int64_t *increments)
{
	int ret, cpu;
	unsigned int bpf_size;

	switch (len) {
	case 1:	bpf_size = BPF_B;
		break;
	case 2: bpf_size = BPF_H;
		break;
	case 4:	bpf_size = BPF_W;
		break;
	case 8:	bpf_size = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	{
		struct bpf_insn bytecode[] = {
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			BPFI_LDX(bpf_size, BPF_REG_0, BPF_REG_1, 0),
			BPFI_LD_IMM64(BPF_REG_2, increments[0]),
			BPFI_ADD64_X(BPF_REG_0, BPF_REG_2),
			BPFI_LD_IMM64(BPF_REG_2, increments[1]),
			BPFI_ADD64_X(BPF_REG_0, BPF_REG_2),
			BPFI_STX(bpf_size, BPF_REG_1, BPF_REG_0, 0),
		};

		do {
			cpu = cpu_op_get_current_cpu();
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					NULL, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	return ret;
}

static int test_two_add(void)
{
	int orig_v = 42, v, ret;
	int64_t increments[2] = { 99, 123 };
	const char *test_name = "test_two_add";

	v = orig_v;
	ret = test_two_add_op(&v, sizeof(v), increments);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increments[0] + increments[1]) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v,
				      orig_v + increments[0] + increments[1]);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_cmpxchg_op(void *v, void *expect, void *old, void *n,
		size_t len)
{
	return cpu_op_cmpxchg(v, expect, old, n, len, cpu_op_get_current_cpu());
}

static int test_cmpxchg_success(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_cmpxchg success";

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret) {
		ksft_test_result_fail("%s returned %d, expecting %d\n",
				      test_name, ret, 0);
		return -1;
	}
	if (v != n) {
		ksft_test_result_fail("%s v is %lld, expecting %lld\n",
				      test_name, (long long)v, (long long)n);
		return -1;
	}
	if (old != orig_v) {
		ksft_test_result_fail("%s old is %lld, expecting %lld\n",
				      test_name, (long long)old,
				      (long long)orig_v);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_cmpxchg_fail(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 123, old = 0, n = 3;
	const char *test_name = "test_cmpxchg fail";

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret) {
		ksft_test_result_fail("%s returned %d, expecting %d\n",
				      test_name, ret, 0);
		return -1;
	}
	if (v == n) {
		ksft_test_result_fail("%s returned %lld, expecting %lld\n",
				      test_name, (long long)v,
				      (long long)orig_v);
		return -1;
	}
	if (old != orig_v) {
		ksft_test_result_fail("%s old is %lld, expecting %lld\n",
				      test_name, (long long)old,
				      (long long)orig_v);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_mb_op(void)
{
	int ret, cpu;

	struct bpf_insn bytecode[] = {
		BPFI_MB(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_mb(void)
{
	int ret;
	const char *test_name = "test_mb";

	ret = test_mb_op();
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_unaligned_insn(void)
{
	uint32_t orig_v = 1, expect = 1, old = 0, n = 3;
	const char *test_name = "test_unaligned_insn";
	struct unaligned_test test;
	int ret;

	test.data = orig_v;
	ret = test_cmpxchg_op(&test.data, &expect, &old, &n, sizeof(uint32_t));
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret) {
		ksft_test_result_fail("%s returned %d, expecting %u\n",
				      test_name, ret, 0);
		return -1;
	}
	if (test.data != n) {
		ksft_test_result_fail("%s v is %u expecting %u\n",
				      test_name, test.data, n);
		return -1;
	}
	if (old != orig_v) {
		ksft_test_result_fail("%s old is %u, expecting %u\n",
				      test_name, old, orig_v);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_unknown_insn(void)
{
	struct bpf_insn bytecode[] = {
		{
			.code = BPF_CALL,
			.dst_reg = BPF_REG_0,
			.src_reg = BPF_REG_0,
			.off = 0,
			.imm = 0,
		}
	};
	int cpu, ret;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);
	return ret;
}

static int test_unknown_insn(void)
{
	int ret;
	const char *test_name = "test_unknown_insn";

	ret = do_test_unknown_insn();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_max_insn(void)
{
	struct bpf_insn bytecode[] = {
		BPFI_ADD64_K(BPF_REG_0, 1),
		BPFI_ADD64_K(BPF_REG_0, 2),
		BPFI_ADD64_K(BPF_REG_0, 3),
		BPFI_ADD64_K(BPF_REG_0, 4),
		BPFI_ADD64_K(BPF_REG_0, 5),
		BPFI_ADD64_K(BPF_REG_0, 6),
		BPFI_ADD64_K(BPF_REG_0, 7),
		BPFI_ADD64_K(BPF_REG_0, 8),
		BPFI_ADD64_K(BPF_REG_0, 9),
		BPFI_ADD64_K(BPF_REG_0, 10),
		BPFI_ADD64_K(BPF_REG_0, 11),
		BPFI_ADD64_K(BPF_REG_0, 12),
		BPFI_ADD64_K(BPF_REG_0, 13),
		BPFI_ADD64_K(BPF_REG_0, 14),
		BPFI_ADD64_K(BPF_REG_0, 15),
		BPFI_ADD64_K(BPF_REG_0, 16),
		BPFI_ADD64_K(BPF_REG_0, 17),
		BPFI_ADD64_K(BPF_REG_0, 18),
		BPFI_ADD64_K(BPF_REG_0, 19),
		BPFI_ADD64_K(BPF_REG_0, 20),
		BPFI_ADD64_K(BPF_REG_0, 21),
		BPFI_ADD64_K(BPF_REG_0, 22),
		BPFI_ADD64_K(BPF_REG_0, 23),
		BPFI_ADD64_K(BPF_REG_0, 24),
		BPFI_ADD64_K(BPF_REG_0, 25),
		BPFI_ADD64_K(BPF_REG_0, 26),
		BPFI_ADD64_K(BPF_REG_0, 27),
		BPFI_ADD64_K(BPF_REG_0, 28),
		BPFI_ADD64_K(BPF_REG_0, 29),
		BPFI_ADD64_K(BPF_REG_0, 30),
		BPFI_ADD64_K(BPF_REG_0, 31),
		BPFI_ADD64_K(BPF_REG_0, 32),
	};
	int cpu, ret;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);
	return ret;
}

static int test_max_insn(void)
{
	int ret;
	const char *test_name = "test_max_insn";

	ret = do_test_max_insn();
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_too_many_insn(void)
{
	struct bpf_insn bytecode[] = {
		BPFI_ADD64_K(BPF_REG_0, 1),
		BPFI_ADD64_K(BPF_REG_0, 2),
		BPFI_ADD64_K(BPF_REG_0, 3),
		BPFI_ADD64_K(BPF_REG_0, 4),
		BPFI_ADD64_K(BPF_REG_0, 5),
		BPFI_ADD64_K(BPF_REG_0, 6),
		BPFI_ADD64_K(BPF_REG_0, 7),
		BPFI_ADD64_K(BPF_REG_0, 8),
		BPFI_ADD64_K(BPF_REG_0, 9),
		BPFI_ADD64_K(BPF_REG_0, 10),
		BPFI_ADD64_K(BPF_REG_0, 11),
		BPFI_ADD64_K(BPF_REG_0, 12),
		BPFI_ADD64_K(BPF_REG_0, 13),
		BPFI_ADD64_K(BPF_REG_0, 14),
		BPFI_ADD64_K(BPF_REG_0, 15),
		BPFI_ADD64_K(BPF_REG_0, 16),
		BPFI_ADD64_K(BPF_REG_0, 17),
		BPFI_ADD64_K(BPF_REG_0, 18),
		BPFI_ADD64_K(BPF_REG_0, 19),
		BPFI_ADD64_K(BPF_REG_0, 20),
		BPFI_ADD64_K(BPF_REG_0, 21),
		BPFI_ADD64_K(BPF_REG_0, 22),
		BPFI_ADD64_K(BPF_REG_0, 23),
		BPFI_ADD64_K(BPF_REG_0, 24),
		BPFI_ADD64_K(BPF_REG_0, 25),
		BPFI_ADD64_K(BPF_REG_0, 26),
		BPFI_ADD64_K(BPF_REG_0, 27),
		BPFI_ADD64_K(BPF_REG_0, 28),
		BPFI_ADD64_K(BPF_REG_0, 29),
		BPFI_ADD64_K(BPF_REG_0, 30),
		BPFI_ADD64_K(BPF_REG_0, 31),
		BPFI_ADD64_K(BPF_REG_0, 32),
		BPFI_ADD64_K(BPF_REG_0, 33),
	};
	int cpu, ret;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);
	return ret;
}

static int test_too_many_insn(void)
{
	int ret;
	const char *test_name = "test_too_many_insn";

	ret = do_test_too_many_insn();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/* Infinite loop. */
static int do_test_too_many_retired_insn(void)
{
	int ret, cpu;

	enum {
		BPF_LABEL_LOOP = 0,
		BPF_LABEL_BRANCH1 = 2,
	};

	struct bpf_insn bytecode[] = {
		/* Loop target. */
		[BPF_LABEL_LOOP] = BPFI_ADD64_K(BPF_REG_0, 1),
		[1] = BPFI_JA_K(BPF_LABEL_LOOP - BPF_LABEL_BRANCH1),
		[BPF_LABEL_BRANCH1] = BPFI_EXIT(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_too_many_retired_insn(void)
{
	int ret;
	const char *test_name = "test_too_many_retired_insn";

	ret = do_test_too_many_retired_insn();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_too_many_pages(void)
{
	char buf1[DO_ON_CPU_PAGES_MAX + 1][TESTBUFLEN_PAGE_MAX];
	int ret, cpu;

	enum {
		BPF_LABEL_LOOP = 2,
		BPF_LABEL_BRANCH1 = 5,
	};

	struct bpf_insn bytecode[] = {
		/* Loop target. */
		[0] = BPFI_LD_IMM64(BPF_REG_0, BPF_PTR_TO_V(&buf1[0][0])),
		[BPF_LABEL_LOOP] = BPFI_LDX(BPF_B, BPF_REG_1, BPF_REG_0, 0),
		[3] = BPFI_ADD64_K(BPF_REG_0, TESTBUFLEN_PAGE_MAX),
		[4] = BPFI_JNE_K(BPF_REG_0, (DO_ON_CPU_PAGES_MAX + 1) *
					    TESTBUFLEN_PAGE_MAX,
				 BPF_LABEL_LOOP - BPF_LABEL_BRANCH1),
		[BPF_LABEL_BRANCH1] = BPFI_EXIT(),
	};

	do {
		cpu = cpu_op_get_current_cpu();
		ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
				NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_too_many_pages(void)
{
	int ret;
	const char *test_name = "test_too_many_pages";

	ret = do_test_too_many_pages();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/*
 * Iterate over large uninitialized arrays to trigger page faults.
 * This includes reading from zero pages.
 */
int test_page_fault(void)
{
	int ret = 0;
	uint64_t i;
	const char *test_name = "test_page_fault";

	for (i = 0; i < NR_PF_ARRAY; i++) {
		ret = test_memcpy_op(pf_array_dst[i],
				     pf_array_src[i],
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/*
 * Try to use 2MB huge pages.
 */
int test_hugetlb(void)
{
	int ret = 0;
	uint64_t i;
	const char *test_name = "test_hugetlb";
	int *dst, *src;

	dst = mmap(NULL, HUGEMAPLEN, PROT_READ | PROT_WRITE,
		   MAP_HUGETLB | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (dst == MAP_FAILED) {
		switch (errno) {
		case ENOMEM:
		case ENOENT:
		case EINVAL:
			ksft_test_result_skip("%s test.\n", test_name);
			goto end;
		default:
			break;
		}
		perror("mmap");
		abort();
	}
	src = mmap(NULL, HUGEMAPLEN, PROT_READ | PROT_WRITE,
		   MAP_HUGETLB | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (src == MAP_FAILED) {
		if (errno == ENOMEM) {
			ksft_test_result_skip("%s test.\n", test_name);
			goto unmap_dst;
		}
		perror("mmap");
		abort();
	}

	/* Read/write from/to huge zero pages. */
	for (i = 0; i < NR_HUGE_ARRAY; i++) {
		ret = test_memcpy_op(dst + (i * PF_ARRAY_LEN / sizeof(int)),
				     src + (i * PF_ARRAY_LEN / sizeof(int)),
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}
	for (i = 0; i < NR_HUGE_ARRAY * (PF_ARRAY_LEN / sizeof(int)); i++)
		src[i] = i;

	for (i = 0; i < NR_HUGE_ARRAY; i++) {
		ret = test_memcpy_op(dst + (i * PF_ARRAY_LEN / sizeof(int)),
				     src + (i * PF_ARRAY_LEN / sizeof(int)),
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}

	for (i = 0; i < NR_HUGE_ARRAY * (PF_ARRAY_LEN / sizeof(int)); i++) {
		if (dst[i] != i) {
			ksft_test_result_fail("%s mismatch, expect %d, got %d\n",
					      test_name, i, dst[i]);
			return ret;
		}
	}

	ksft_test_result_pass("%s test\n", test_name);

	if (munmap(src, HUGEMAPLEN)) {
		perror("munmap");
		abort();
	}
unmap_dst:
	if (munmap(dst, HUGEMAPLEN)) {
		perror("munmap");
		abort();
	}
end:
	return 0;
}

static int test_cmpxchg_op_cpu(void *v, void *expect, void *old, void *n,
		size_t len, int cpu)
{
	int ret;

	do {
		ret = cpu_op_cmpxchg(v, expect, old, n, len, cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_over_possible_cpu(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_over_possible_cpu";

	v = orig_v;
	ret = test_cmpxchg_op_cpu(&v, &expect, &old, &n, sizeof(uint64_t),
				  0xFFFFFFFF);
	if (ret == 0) {
		ksft_test_result_fail("%s test: ret = %d\n",
				      test_name, ret);
		return -1;
	}
	if (ret < 0 && errno == EINVAL) {
		ksft_test_result_pass("%s test\n", test_name);
		return 0;
	}
	ksft_test_result_fail("%s returned %d, errno %s, expecting %d, errno %s\n",
			      test_name, ret, strerror(errno),
			      0, strerror(EINVAL));
	return -1;
}

static int test_allowed_affinity(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_allowed_affinity";
	cpu_set_t allowed_cpus, cpuset;

	ret = sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus);
	if (ret) {
		ksft_test_result_fail("%s returned %d, errno %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (!(CPU_ISSET(0, &allowed_cpus) && CPU_ISSET(1, &allowed_cpus))) {
		ksft_test_result_skip("%s test. Requiring allowed CPUs 0 and 1.\n",
				      test_name);
		return 0;
	}
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
		ksft_test_result_fail("%s test. Unable to set affinity. errno = %s\n",
				      test_name, strerror(errno));
		return -1;
	}
	v = orig_v;
	ret = test_cmpxchg_op_cpu(&v, &expect, &old, &n, sizeof(uint64_t),
				  1);
	if (sched_setaffinity(0, sizeof(allowed_cpus), &allowed_cpus) != 0) {
		ksft_test_result_fail("%s test. Unable to set affinity. errno = %s\n",
				      test_name, strerror(errno));
		return -1;
	}
	if (ret == 0) {
		ksft_test_result_fail("%s test: ret = %d\n",
				      test_name, ret);
		return -1;
	}

	if (ret < 0 && errno == EINVAL) {
		ksft_test_result_pass("%s test\n", test_name);
		return 0;
	}
	ksft_test_result_fail("%s returned %d, errno %s, expecting %d, errno %s\n",
			      test_name, ret, strerror(errno),
			      0, strerror(EINVAL));
	return -1;
}

int main(int argc, char **argv)
{
	ksft_print_header();
	ksft_set_plan(21);

	test_ops_supported();

	test_compare_eq_same();
	test_compare_eq_diff();
	test_memcpy();
	test_memcpy_store_release();
	test_add();
	test_add_release();
	test_two_add();
	test_cmpxchg_success();
	test_cmpxchg_fail();
	test_mb();
	test_unaligned_insn();
	test_unknown_insn();
	test_max_insn();
	test_too_many_insn();
	test_too_many_retired_insn();
	test_too_many_pages();
	test_page_fault();
	test_hugetlb();
	test_over_possible_cpu();
	test_allowed_affinity();

	return ksft_exit_pass();
}
