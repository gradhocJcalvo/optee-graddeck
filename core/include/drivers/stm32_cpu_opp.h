/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, STMicroelectronics
 */

#ifndef DRIVERS_STM32_CPU_OPP_H
#define DRIVERS_STM32_CPU_OPP_H

#include <tee_api_types.h>

struct regulator;
struct clk;

#ifndef CFG_SCPFW_MOD_DVFS
/* Return the number of CPU operating points */
size_t stm32_cpu_opp_count(void);
#endif

bool opp_voltage_is_supported(struct regulator *regul, uint32_t *volt_uv);

/* Get level value identifying CPU operating point @opp_index */
unsigned int stm32_cpu_opp_level(size_t opp_index);

#ifdef CFG_SCPFW_MOD_DVFS
/* Provide CPU clock and regulator reference for CPU DVFS with SCMI */
void scmi_server_set_cpu_resources(struct regulator *regulator, struct clk *clk,
				   unsigned int *dvfs_khz,
				   unsigned int *dvfs_mv, size_t dvfs_count);
#else
/* Request to switch to CPU operating point related to @level */
TEE_Result stm32_cpu_opp_set_level(unsigned int level);

/* Get level related to current CPU operating point */
TEE_Result stm32_cpu_opp_read_level(unsigned int *level);
#endif /*CFG_SCPFW_MOD_DVFS*/
#endif /*DRIVERS_STM32_CPU_OPP_H*/
