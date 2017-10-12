/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DO_ON_CPU_H
#define _UAPI_LINUX_DO_ON_CPU_H

/*
 * linux/do_on_cpu.h
 *
 * do_on_cpu system call API
 *
 * Copyright (c) 2017-2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/bpf.h>

enum do_on_cpu_flags {
	DO_ON_CPU_LEN_MAX_FLAG =		(1U << 0),
	DO_ON_CPU_RETIRED_INSN_MAX_FLAG =	(1U << 1),
	DO_ON_CPU_PAGES_MAX_FLAG =		(1U << 2),
};

#endif /* _UAPI_LINUX_DO_ON_CPU_H */
