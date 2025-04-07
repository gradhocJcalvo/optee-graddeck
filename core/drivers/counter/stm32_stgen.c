// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_rtc.h>
#include <drivers/stm32_stgen.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <util.h>

#define STGENC_CNTCR				U(0x0)
#define STGENC_CNTSR				U(0x4)
#define STGENC_CNTCVL				U(0x8)
#define STGENC_CNTCVU				U(0xC)
#define STGENC_CNTFID0				U(0x20)

/*
 * SMC function ID for STM32MP/TF-A monitor to set CNTFRQ to STGEN frequency.
 * No arguments.
 */
#define STM32_SIP_SMC_STGEN_SET_RATE		0x82000000

struct stm32_stgen_compat_data {
	bool intermediate_clock_parent;
};

struct stgen_pdata {
	struct clk *stgen_clock;
	struct clk *bus_clock;
	struct stm32_rtc_calendar *calendar;
	uint32_t cnt_h;
	uint32_t cnt_l;
	vaddr_t base;
};

static struct stgen_pdata stgen_d;

static void set_counter_value(uint64_t counter)
{
	io_write64(stgen_d.base + STGENC_CNTCVL, counter);
}

uint64_t stm32_stgen_get_counter_value(void)
{
	return io_read64(stgen_d.base + STGENC_CNTCVL);
}

/*
 * This function invokes EL3 monitor to update CNTFRQ with STGEN
 * frequency. Updating the CP15 register can only be done by the
 * highest EL on Armv8-A.
 */
static TEE_Result stm32mp_stgen_smc_config(void)
{
	/*
	 * STM32_SIP_SMC_STGEN_SET_RATE call API
	 *
	 * Argument a0: (input) SMCC ID
	 *		(output) status return code
	 */
	struct thread_smc_args stgen_conf_args = {
		.a0 = STM32_SIP_SMC_STGEN_SET_RATE
	};

	thread_smccc(&stgen_conf_args);

	if (stgen_conf_args.a0) {
		EMSG("STGEN configuration failed, error code: %llu",
		     (unsigned long long)stgen_conf_args.a0);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void stm32_stgen_pm_suspend(void)
{
	uint64_t counter_val = 0;

	/*
	 * Disable STGEN counter. At this point, it should be stopped by
	 * software.
	 */
	io_clrbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	/* Save current time from the RTC */
	if (stm32_rtc_get_calendar(stgen_d.calendar))
		panic("Could not get RTC calendar at suspend");

	/* Save current counter value */
	counter_val = stm32_stgen_get_counter_value();
	stgen_d.cnt_h = (uint32_t)(counter_val >> 32);
	stgen_d.cnt_l = (uint32_t)counter_val;

	/* Re-enable STGEN as generic timer can be used later */
	io_setbits32(stgen_d.base + STGENC_CNTCR, BIT(0));
}

static void stm32_stgen_pm_resume(void)
{
	unsigned long clock_src_rate = clk_get_rate(stgen_d.stgen_clock);
	uint64_t counter_val = ((uint64_t)stgen_d.cnt_h << 32) | stgen_d.cnt_l;
	struct stm32_rtc_calendar cur_calendar = { };
	uint64_t nb_pm_count_ticks = 0;

	/* STGEN clocks are already restored by the clock driver */
	io_clrbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	/* Read the current time from the RTC to update system counter */
	if (stm32_rtc_get_calendar(&cur_calendar))
		panic("Could not get RTC calendar at resume");

	nb_pm_count_ticks = stm32_rtc_diff_calendar_tick(&cur_calendar,
							 stgen_d.calendar,
							 clock_src_rate);

	DMSG("Time spent in low-power: %ld ms",
	     (nb_pm_count_ticks * 1000U) / clock_src_rate);

	/* Update the counter value with the number of pm ticks */
	if (ADD_OVERFLOW(counter_val, nb_pm_count_ticks, &counter_val))
		panic("STGEN counter overflow");

	io_write32(stgen_d.base + STGENC_CNTFID0, clock_src_rate);
	if (io_read32(stgen_d.base + STGENC_CNTFID0) != clock_src_rate)
		panic("Couldn't modify STGEN clock rate");

	set_counter_value(counter_val);

	/* Set the correct clock frequency in the ARM CP15 register */
	if (IS_ENABLED(CFG_WITH_ARM_TRUSTED_FW))
		stm32mp_stgen_smc_config();

	io_setbits32(stgen_d.base + STGENC_CNTCR, BIT(0));
}

static TEE_Result
stm32_stgen_pm(enum pm_op op, unsigned int pm_hint __unused,
	       const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_RESUME)
		stm32_stgen_pm_resume();
	else
		stm32_stgen_pm_suspend();

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct io_pa_va base = { };
	size_t reg_size = 0;

	cuint = fdt_getprop(fdt, node, "reg", NULL);
	if (!cuint)
		panic();

	base.pa = fdt_reg_base_address(fdt, node);
	reg_size = fdt_reg_size(fdt, node);
	stgen_d.base = io_pa_or_va_secure(&base, reg_size);

	assert(stgen_d.base != 0);

	res = clk_dt_get_by_name(fdt, node, "bus", &stgen_d.bus_clock);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		return TEE_ERROR_DEFER_DRIVER_INIT;
	else if (res)
		panic("No stgen bus clock available in device tree");

	res = clk_dt_get_by_name(fdt, node, "stgen_clk", &stgen_d.stgen_clock);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		return TEE_ERROR_DEFER_DRIVER_INIT;
	else if (res)
		panic("No stgen clock available in device tree");

	return TEE_SUCCESS;
}

static TEE_Result stgen_probe(const void *fdt, int node,
			      const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t stgen_counter = 0;
	unsigned long previous_source_rate = 0;
	unsigned long stgen_rate = 0;

	res = parse_dt(fdt, node);
	if (res)
		return res;

	stgen_d.calendar = calloc(1, sizeof(*stgen_d.calendar));
	if (!stgen_d.calendar)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = clk_enable(stgen_d.bus_clock);
	if (res)
		panic();

	/*
	 * Read current source rate before configuration of the flexgen to
	 * update STGEN counter.
	 */
	previous_source_rate = clk_get_rate(stgen_d.stgen_clock);

	/*
	 * Disable STGEN counter. At cold boot, we accept the counter delta
	 * due to STGEN reconfiguration
	 */
	io_clrbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	/*
	 * Flexgen for stgen_clock is skip during RCC probe.
	 * Enabling stgen_clock configure the flexgen.
	 */
	res = clk_enable(stgen_d.stgen_clock);
	if (res)
		panic();

	stgen_rate = clk_get_rate(stgen_d.stgen_clock);

	io_write32(stgen_d.base + STGENC_CNTFID0, stgen_rate);
	if (io_read32(stgen_d.base + STGENC_CNTFID0) != stgen_rate)
		panic("Couldn't modify STGEN clock rate");

	/* Update counter value according to the new STGEN clock frequency */
	stgen_counter = stm32_stgen_get_counter_value();
	stgen_counter = stgen_counter * stgen_rate / previous_source_rate;
	set_counter_value(stgen_counter);

	if (IS_ENABLED(CFG_WITH_ARM_TRUSTED_FW))
		stm32mp_stgen_smc_config();

	io_setbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	register_pm_core_service_cb(stm32_stgen_pm, NULL, "stm32-stgen");

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_stgen_match_table[] = {
	{
		.compatible = "st,stm32mp25-stgen"
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_stgen_dt_driver) = {
	.name = "stm32_stgen",
	.match_table = stm32_stgen_match_table,
	.probe = stgen_probe,
};
