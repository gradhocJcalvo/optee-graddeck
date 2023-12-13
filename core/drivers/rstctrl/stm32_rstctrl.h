/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2023, STMicroelectronics
 */

#include <drivers/rstctrl.h>

/* Exposed rstctrl instance */
struct stm32_rstline {
	unsigned int id;
	struct rstctrl rstctrl;
	const struct stm32_reset_data *data;
	SLIST_ENTRY(stm32_rstline)link;
};

struct stm32_rstline *to_rstline(struct rstctrl *rstctrl);

struct stm32_reset_cfg {
	uint16_t offset;
	uint8_t bit_idx;
	bool set_clr;
	bool inverted;
	bool no_deassert;
	bool no_timeout;
};

struct stm32_reset_data {
	unsigned int nb_lines;
	const struct stm32_reset_cfg **rst_lines;
	struct rstctrl_ops * (*get_rstctrl_ops)(unsigned int id);
};

TEE_Result stm32_rstctrl_provider_probe(const void *fdt, int offs,
					const void *compat_data);
