// SPDX-License-Identifier: LGPL-2.1
/*
 * rseq.c
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <signal.h>
#include <limits.h>

#include "rseq.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

__thread volatile struct rseq __rseq_abi = {
	.cpu_id = RSEQ_CPU_ID_UNINITIALIZED,
};

__thread volatile struct rseq_lib_abi __rseq_lib_abi;

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

int rseq_register_current_thread(void)
{
	int rc, ret = 0;

	/*
	 * Nested signal handlers need to check whether registration is
	 * allowed.
	 */
	if (__rseq_lib_abi.register_state != RSEQ_REGISTER_ALLOWED)
		return -1;
	__rseq_lib_abi.register_state = RSEQ_REGISTER_ONGOING;
	if (__rseq_lib_abi.refcount == UINT_MAX) {
		ret = -1;
		goto end;
	}
	if (__rseq_lib_abi.refcount++)
		goto end;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
	if (!rc) {
		assert(rseq_current_cpu_raw() >= 0);
		goto end;
	}
	if (errno != EBUSY)
		__rseq_abi.cpu_id = RSEQ_CPU_ID_REGISTRATION_FAILED;
	ret = -1;
	__rseq_lib_abi.refcount--;
end:
	__rseq_lib_abi.register_state = RSEQ_REGISTER_ALLOWED;
	return ret;
}

int rseq_unregister_current_thread(void)
{
	int rc, ret = 0;

	if (__rseq_lib_abi.register_state != RSEQ_REGISTER_ALLOWED)
		return -1;
	__rseq_lib_abi.register_state = RSEQ_REGISTER_ONGOING;
	if (!__rseq_lib_abi.refcount) {
		ret = -1;
		goto end;
	}
	if (--__rseq_lib_abi.refcount)
		goto end;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq),
		      RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
	if (!rc)
		goto end;
	ret = -1;
end:
	__rseq_lib_abi.register_state = RSEQ_REGISTER_ALLOWED;
	return ret;
}

int32_t rseq_fallback_current_cpu(void)
{
	int32_t cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}
