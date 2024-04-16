/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_RISAB_H__
#define __DRIVERS_STM32_RISAB_H__

#include <trace.h>

#define RISAB_NB_MAX_CID_SUPPORTED		U(7)

struct mem_region {
	uintptr_t base;
	size_t size;
};

void stm32_risab_clear_illegal_access_flags(void);

#ifdef CFG_TEE_CORE_DEBUG
void stm32_risab_dump_erroneous_data(void);
#else /* CFG_TEE_CORE_DEBUG */
static inline void stm32_risab_dump_erroneous_data(void)
{
}
#endif /* CFG_TEE_CORE_DEBUG */

#endif /*__DRIVERS_STM32_RISAB_H__*/
