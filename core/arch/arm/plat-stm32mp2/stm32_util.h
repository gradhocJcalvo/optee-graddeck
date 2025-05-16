/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <drivers/stm32mp2_rcc_util.h>
#include <kernel/spinlock.h>
#include <stdint.h>
#include <types_ext.h>

#define may_spin_lock(lock)		  cpu_spin_lock_xsave(lock)
#define may_spin_unlock(lock, exceptions) cpu_spin_unlock_xrestore(lock, \
								   exceptions)

void __noreturn do_reset(const char *str);

#ifdef CFG_STM32_CPU_OPP
bool stm32mp_supports_cpu_opp(uint32_t opp_id);
#endif /*CFG_STM32_CPU_OPP*/

#ifdef CFG_STPMIC2
bool stm32_stpmic2_is_present(void);
#else
static inline bool stm32_stpmic2_is_present(void)
{
	return false;
}
#endif

void stm32_debug_suspend(unsigned long a0);

bool stm32mp_allow_probe_shared_device(const void *fdt, int node);

/* Get device ID from SYSCFG registers */
uint32_t stm32mp_syscfg_get_chip_dev_id(void);
#endif /*__STM32_UTIL_H__*/
