// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2021, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <config.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <io.h>
#include <libfdt.h>
#include <stm32_util.h>
#include <stm32mp_pm.h>
#include <trace.h>
#include <util.h>

#include "context.h"
#include "power.h"

#define DT_PWR_COMPAT			"st,stm32mp1-pwr-reg"
#define SYSTEM_SUSPEND_SUPPORTED_MODES	"system_suspend_supported_soc_modes"
#define SYSTEM_OFF_MODE			"system_off_soc_mode"
#define RETRAM_ENABLED			"st,retram-enabled-in-standby-ddr-sr"

static uint32_t deepest_suspend_mode;
static uint32_t system_off_mode;
static bool retram_enabled;
static uint8_t stm32mp1_supported_soc_modes[STM32_PM_MAX_SOC_MODE];

bool stm32mp1_is_retram_during_standby(void)
{
	return retram_enabled;
}

bool need_to_backup_cpu_context(unsigned int soc_mode)
{
	switch (soc_mode) {
	case STM32_PM_CSTOP_ALLOW_LPLV_STOP2:
	case STM32_PM_CSTOP_ALLOW_STANDBY_DDR_SR:
		return true;
	case STM32_PM_CSLEEP_RUN:
	case STM32_PM_CSTOP_ALLOW_STOP:
	case STM32_PM_CSTOP_ALLOW_LP_STOP:
	case STM32_PM_CSTOP_ALLOW_LPLV_STOP:
	case STM32_PM_CSTOP_ALLOW_STANDBY_DDR_OFF:
	case STM32_PM_SHUTDOWN:
		return false;
	default:
		EMSG("Invalid mode 0x%x", soc_mode);
		panic();
	}
}

bool need_to_backup_stop_context(unsigned int soc_mode)
{
	switch (soc_mode) {
	case STM32_PM_CSTOP_ALLOW_STOP:
	case STM32_PM_CSTOP_ALLOW_LP_STOP:
	case STM32_PM_CSTOP_ALLOW_LPLV_STOP:
		return true;
	default:
		return false;
	}
}

#ifdef CFG_STM32_LOWPOWER_SIP
/* Boot with all domains ON, false means in use */
static bool stm32mp1_pm_dom[STM32MP1_PD_MAX_PM_DOMAIN] = {
	[STM32MP1_PD_VSW] = false,
	[STM32MP1_PD_CORE_RET] = false,
	[STM32MP1_PD_CORE] = false
};

static bool get_pm_domain_state(uint8_t mode)
{
	bool res = true;
	enum stm32mp1_pm_domain id = STM32MP1_PD_MAX_PM_DOMAIN;

	while (res && (id > mode)) {
		id--;
		res &= stm32mp1_pm_dom[id];
	}

	return res;
}

int stm32mp1_set_pm_domain_state(enum stm32mp1_pm_domain domain, bool status)
{
	if (domain >= STM32MP1_PD_MAX_PM_DOMAIN)
		return -1;

	stm32mp1_pm_dom[domain] = status;

	return 0;
}

static void dump_pm_domain_state(uint8_t domain __unused)
{
}
#else /* CFG_STM32_LOWPOWER_SIP */

#define EXTI_BANK_NR		3U
#define EXTI_C1IMR(n)		(0x080U + (n) * 0x10U)

#ifdef CFG_STM32MP13
/*
 * Implementation of  PWR Table 35. Functionalities depending on system
 * operating mode
 *
 * Valid wake-up source from LP-Stop modes are:
 * USBH  42, 43
 * OTG   44
 * ETH   68..71
 */
#define IMR1_PD_CORE_MASK 0
#define IMR2_PD_CORE_MASK (GENMASK_32(12, 10))
#define IMR3_PD_CORE_MASK (GENMASK_32(7, 4))

/*
 * Valid wake-up source from LPLV-Stop modes are:
 * GPIO     0..15
 * PVD/AVD  16
 * I2C      21..25
 * USART    26..33
 * SPI      36..40
 * LPTIM    47,48,50,52,53
 */
#define IMR1_PD_CORE_RET_MASK (GENMASK_32(15, 0) | BIT(16) | \
			       GENMASK_32(25, 21) | GENMASK_32(31, 26))
#define IMR2_PD_CORE_RET_MASK (GENMASK_32(8, 4) | GENMASK_32(16, 15) | \
			       BIT(18) | GENMASK_32(21, 20))
#define IMR3_PD_CORE_RET_MASK 0

#endif /* CFG_STM32MP13 */

#ifdef CFG_STM32MP15
/*
 * Implementation of  Table 34. Functionalities depending on system
 * operating mode
 *
 * Valid wake-up source from LP-Stop mode are:
 * I2C   21..25
 * USART 26..33
 * SPI   36..41
 * MDIOS 42
 * USBH  43
 * OTG   44
 * LPTIM 47,48
 * I2C6  54
 * IPCC  61,62
 * HSEM  63,64
 * SEV   65,66
 * HDMI  69
 * ETH   70,71
 * DTS   72
 * CPU2  73
 * CDBG  75
 */
#define IMR1_PD_CORE_MASK (GENMASK_32(31, 21))
#define IMR2_PD_CORE_MASK (GENMASK_32(1, 0) | GENMASK_32(16, 4) | BIT(18) | \
			   GENMASK_32(22, 20) | GENMASK_32(31, 29))
#define IMR3_PD_CORE_MASK (GENMASK_32(1, 0) | GENMASK_32(9, 4) | BIT(11))

/*
 * Valid wake-up source from LPLV-Stop modes are:
 * GPIOs   0..15
 * PVD/AVD 16
 */
#define IMR1_PD_CORE_RET_MASK (GENMASK_32(15, 0) | BIT(16))
#define IMR2_PD_CORE_RET_MASK 0
#define IMR3_PD_CORE_RET_MASK 0

#endif /* CFG_STM32MP15 */

static uint32_t imr_pd_core_mask[EXTI_BANK_NR] = {
	IMR1_PD_CORE_MASK,
	IMR2_PD_CORE_MASK,
	IMR3_PD_CORE_MASK,
};

static uint32_t imr_pd_core_ret_mask[EXTI_BANK_NR] = {
	IMR1_PD_CORE_RET_MASK,
	IMR2_PD_CORE_RET_MASK,
	IMR3_PD_CORE_RET_MASK,
};

static uint32_t exti_read_imr(unsigned int bank)
{
	return io_read32(stm32_exti_base() + EXTI_C1IMR(bank));
}

static bool get_domain_state_from_exti(uint8_t domain)
{
	unsigned int i = 0;

	for (i = 0; i < EXTI_BANK_NR; i++) {
		uint32_t imr_mask = imr_pd_core_mask[i];
		uint32_t imr = exti_read_imr(i);

		if (domain == STM32MP1_PD_CORE_RET)
			imr_mask |= imr_pd_core_ret_mask[i];

		if (imr & imr_mask)
			return true;
	}

	return false;
}

/* The function returns FALSE if the domain is in use. */
static bool get_pm_domain_state(uint8_t domain)
{
	return get_domain_state_from_exti(domain) == false;
}

static void dump_pm_domain_state(uint8_t __maybe_unused domain)
{
#ifdef POWER_DEBUG
	unsigned int i = 0;

	for (i = 0; i < EXTI_BANK_NR; i++) {
		uint32_t imr = exti_read_imr(i);
		uint32_t imr_mask = imr_pd_core_mask[i];
		const char *name = "PD_CORE";

		if (domain == STM32MP1_PD_CORE_RET) {
			imr_mask = imr_pd_core_ret_mask[i];
			name = "PD_CORE_RET";
		}

		if (imr & imr_mask) {
			unsigned int bit = 0;

			/* Log EXTI numbers using domain */
			for (bit = 0; bit < 32; bit++) {
				if ((imr & imr_mask) & BIT(bit))
					IMSG("Domain %s needed for EXTI %u",
					     name, i * U(32) + bit);
			}
		}
	}
#endif
}

#endif  /* CFG_STM32_LOWPOWER_SIP */

#ifdef CFG_EMBED_DTB
static void save_supported_mode(void *fdt, int pwr_node)
{
	int len = 0;
	uint32_t count = 0;
	unsigned int i = 0;
	uint32_t supported[ARRAY_SIZE(stm32mp1_supported_soc_modes)] = { };
	const void *prop = 0;

	prop = fdt_getprop(fdt, pwr_node, SYSTEM_SUSPEND_SUPPORTED_MODES, &len);
	if (!prop)
		panic();

	count = (uint32_t)len / sizeof(uint32_t);
	if (count > STM32_PM_MAX_SOC_MODE)
		panic();

	if (fdt_read_uint32_array(fdt, pwr_node,
				  SYSTEM_SUSPEND_SUPPORTED_MODES,
				  &supported[0], count) < 0)
		panic("PWR DT");

	for (i = 0; i < count; i++) {
		if (supported[i] >= STM32_PM_MAX_SOC_MODE)
			panic("Invalid mode");

		stm32mp1_supported_soc_modes[supported[i]] = true;
	}
}
#endif

static bool is_supported_mode(uint32_t soc_mode)
{
	assert(soc_mode < ARRAY_SIZE(stm32mp1_supported_soc_modes));
	return stm32mp1_supported_soc_modes[soc_mode] == 1;
}

uint32_t stm32mp1_get_lp_soc_mode(uint32_t psci_mode)
{
	uint32_t mode = 0;

	if (psci_mode == PSCI_MODE_SYSTEM_OFF)
		return system_off_mode;

	mode = deepest_suspend_mode;

	dump_pm_domain_state(STM32MP1_PD_CORE);
	dump_pm_domain_state(STM32MP1_PD_CORE_RET);

	/* if PD_CORE_RET is in use don't allow deeper than Standby */
	if (mode == STM32_PM_CSTOP_ALLOW_STANDBY_DDR_SR &&
	    (!get_pm_domain_state(STM32MP1_PD_CORE_RET) ||
	     !is_supported_mode(mode)))
		mode = STM32_PM_CSTOP_ALLOW_LPLV_STOP2;

	/* if PD_CORE is in use don't allow deeper than LPLV-Stop */
	if (mode == STM32_PM_CSTOP_ALLOW_LPLV_STOP2 &&
	    (!get_pm_domain_state(STM32MP1_PD_CORE) ||
	     !is_supported_mode(mode)))
		mode = STM32_PM_CSTOP_ALLOW_LPLV_STOP;

	if (mode == STM32_PM_CSTOP_ALLOW_LPLV_STOP &&
	    (!get_pm_domain_state(STM32MP1_PD_CORE) ||
	     !is_supported_mode(mode)))
		mode = STM32_PM_CSTOP_ALLOW_LP_STOP;

	if (mode == STM32_PM_CSTOP_ALLOW_LP_STOP &&
	    !is_supported_mode(mode))
		mode = STM32_PM_CSTOP_ALLOW_STOP;

	if (mode == STM32_PM_CSTOP_ALLOW_STOP &&
	    !is_supported_mode(mode))
		mode = STM32_PM_CSLEEP_RUN;

	return mode;
}

int stm32mp1_set_lp_deepest_soc_mode(uint32_t psci_mode, uint32_t soc_mode)
{
	if (soc_mode >= STM32_PM_MAX_SOC_MODE)
		return -1;

	if (psci_mode == PSCI_MODE_SYSTEM_SUSPEND) {
		deepest_suspend_mode = soc_mode;

#ifdef CFG_STM32MP1_OPTEE_IN_SYSRAM
		if (!stm32mp_supports_hw_cryp() &&
		    deepest_suspend_mode == STM32_PM_CSTOP_ALLOW_STANDBY_DDR_SR)
			deepest_suspend_mode = STM32_PM_CSTOP_ALLOW_LPLV_STOP;
#endif
	}

	if (psci_mode == PSCI_MODE_SYSTEM_OFF)
		system_off_mode = soc_mode;

	return 0;
}

#ifdef CFG_EMBED_DTB
static int dt_get_pwr_node(void *fdt)
{
	return fdt_node_offset_by_compatible(fdt, -1, DT_PWR_COMPAT);
}

static TEE_Result stm32mp1_init_lp_states(void)
{
	void *fdt = NULL;
	int pwr_node = -1;
	const fdt32_t *cuint = NULL;
	TEE_Result __maybe_unused res = TEE_ERROR_GENERIC;

	fdt = get_embedded_dt();
	if (fdt)
		pwr_node = dt_get_pwr_node(fdt);

	if (pwr_node >= 0) {
		if (fdt_getprop(fdt, pwr_node, RETRAM_ENABLED, NULL))
			retram_enabled = true;

		cuint = fdt_getprop(fdt, pwr_node, SYSTEM_OFF_MODE, NULL);
	}

	if (!fdt || pwr_node < 0 || !cuint) {
		DMSG("No power configuration found in DT");
		return TEE_SUCCESS;
	}

	system_off_mode = fdt32_to_cpu(*cuint);

	/* Initialize suspend support to the deepest possible mode */
	deepest_suspend_mode = STM32_PM_CSTOP_ALLOW_STANDBY_DDR_SR;

#ifdef CFG_STM32MP1_OPTEE_IN_SYSRAM
	if (!stm32mp_supports_hw_cryp())
		deepest_suspend_mode = STM32_PM_CSTOP_ALLOW_LPLV_STOP;
#endif

	save_supported_mode(fdt, pwr_node);

	DMSG("Power configuration: shutdown to %u, suspend to %u",
	     stm32mp1_get_lp_soc_mode(PSCI_MODE_SYSTEM_OFF),
	     stm32mp1_get_lp_soc_mode(PSCI_MODE_SYSTEM_SUSPEND));

	return TEE_SUCCESS;
}
#else
static TEE_Result stm32mp1_init_lp_states(void)
{
	deepest_suspend_mode = STM32_PM_CSTOP_ALLOW_STANDBY_DDR_SR;

#ifdef CFG_STM32MP1_OPTEE_IN_SYSRAM
	if (!stm32mp_supports_hw_cryp())
		deepest_suspend_mode = STM32_PM_CSTOP_ALLOW_LPLV_STOP;
#endif

	system_off_mode = STM32_PM_SHUTDOWN;

	DMSG("Power configuration: shutdown to %u, suspend to %u",
	     stm32mp1_get_lp_soc_mode(PSCI_MODE_SYSTEM_OFF),
	     stm32mp1_get_lp_soc_mode(PSCI_MODE_SYSTEM_SUSPEND));

	return TEE_SUCCESS;
}
#endif
driver_init_late(stm32mp1_init_lp_states);
