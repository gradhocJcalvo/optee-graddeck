/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2023, STMicroelectronics
 */

#include <drivers/rstctrl.h>

/* Exposed rstctrl instance */
struct stm32_rstline {
	unsigned int id;
	struct rstctrl rstctrl;
	SLIST_ENTRY(stm32_rstline)link;
};

struct stm32_rstline *to_rstline(struct rstctrl *rstctrl);

struct stm32_reset_data {
	struct rstctrl_ops * (*get_rstctrl_ops)(unsigned int id);
};

TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					const void *compat_data);
