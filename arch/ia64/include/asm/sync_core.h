/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_IA64_SYNC_CORE_H
#define _ASM_IA64_SYNC_CORE_H

/*
 * TODO: ia64 may need to implement its own sync_core_before_usermode()
 * if it returns to user-space without issuing a core serializing
 * instruction. Simply including the generic header for now.
 */
#include <asm-generic/sync_core.h>

#endif /* _ASM_IA64_SYNC_CORE_H */
