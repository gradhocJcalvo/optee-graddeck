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

#if defined(CFG_STM32_ETZPC)
TEE_Result stm32_etzpc_check_ns_access(unsigned int id);
#else
static inline TEE_Result stm32_etzpc_check_ns_access(unsigned int id __unused)
{
	return TEE_ERROR_ACCESS_DENIED;
}
#endif

#endif /*__DRIVERS_STM32_ETZPC_H*/
