/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_SYNC_CORE_H
#define _ASM_GENERIC_SYNC_CORE_H
/*
 * This is a dummy sync_core_before_usermode() implementation that can be used
 * on all architectures which return to user-space through core serializing
 * instructions.
 * If your architecture returns to user-space through non-core-serializing
 * instructions, you need to write your own functions.
 */
#ifdef CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE
#error need to implement an architecture specific asm/sync_core.h
#endif

static inline void sync_core_before_usermode(void)
{
}

#endif /* _ASM_GENERIC_SYNC_CORE_H */
