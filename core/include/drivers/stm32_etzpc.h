/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2014, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2018-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_ETZPC_H
#define __DRIVERS_STM32_ETZPC_H

#include <util.h>
#include <types_ext.h>

enum etzpc_decprot_attributes {
	ETZPC_DECPROT_S_RW = 0,
	ETZPC_DECPROT_NS_R_S_W = 1,
	ETZPC_DECPROT_MCU_ISOLATION = 2,
	ETZPC_DECPROT_NS_RW = 3,
	ETZPC_DECPROT_MAX = 4,
};

#define ETZPC_TZMA_ALL_SECURE		GENMASK_32(9, 0)
#define ETZPC_TZMA_ALL_NO_SECURE	0x0

#ifdef CFG_STM32_ETZPC
void stm32_etzpc_init(paddr_t base);
#else
static inline void stm32_etzpc_init(paddr_t __unused base) {}
#endif
#endif /*__DRIVERS_STM32_ETZPC_H*/
