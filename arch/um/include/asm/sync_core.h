/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_UM_SYNC_CORE_H
#define _ASM_UM_SYNC_CORE_H

/*
 * TODO: UM may need to implement its own sync_core().
 * Simply including the generic header for now, as
 * otherwise it would use the x86 sync_core.h, which
 * depends on cpu features which are not implemented
 * in UM.
 */
#include <asm-generic/sync_core.h>

#endif /* _ASM_UM_SYNC_CORE_H */
