// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#include <config.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_bsec.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32mp1_rcc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <string.h>

/*
 * Once one starts to get the resource registering state, one cannot register
 * new resources. This ensures resource state cannot change.
 */
static bool registering_locked;

/*
 * Shared peripherals and resources registration
 *
 * Each resource assignation is stored in a table. The state defaults
 * to PERIPH_UNREGISTERED if the resource is not explicitly assigned.
 *
 * Resource driver that as not embedded (a.k.a their related CFG_xxx build
 * directive is disabled) are assigned to the non-secure world.
 *
 * Each IO of the GPIOZ IO can be secure or non-secure.
 *
 * It is the platform responsibility the ensure resource assignation
 * matches the access permission firewalls configuration.
 */
enum shres_state {
	SHRES_UNREGISTERED = 0,
	SHRES_SECURE,
	SHRES_NON_SECURE,
};

/* Use a byte array to store each resource state */
static uint8_t shres_state[STM32MP1_SHRES_COUNT] = {
#if !defined(CFG_STM32_IWDG)
	[STM32MP1_SHRES_IWDG1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_UART)
	[STM32MP1_SHRES_USART1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_SPI)
	[STM32MP1_SHRES_SPI6] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_I2C)
	[STM32MP1_SHRES_I2C4] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_I2C6] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_GPIO)
	[STM32MP1_SHRES_GPIOZ(0)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(1)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(2)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(3)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(4)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(5)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(6)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(7)] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_RNG)
	[STM32MP1_SHRES_RNG1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_HASH)
	[STM32MP1_SHRES_HASH1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_CRYP)
	[STM32MP1_SHRES_CRYP1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_RTC)
	[STM32MP1_SHRES_RTC] = SHRES_NON_SECURE,
#endif
};

static const char __maybe_unused *shres2str_id_tbl[STM32MP1_SHRES_COUNT] = {
	[STM32MP1_SHRES_GPIOZ(0)] = "GPIOZ0",
	[STM32MP1_SHRES_GPIOZ(1)] = "GPIOZ1",
	[STM32MP1_SHRES_GPIOZ(2)] = "GPIOZ2",
	[STM32MP1_SHRES_GPIOZ(3)] = "GPIOZ3",
	[STM32MP1_SHRES_GPIOZ(4)] = "GPIOZ4",
	[STM32MP1_SHRES_GPIOZ(5)] = "GPIOZ5",
	[STM32MP1_SHRES_GPIOZ(6)] = "GPIOZ6",
	[STM32MP1_SHRES_GPIOZ(7)] = "GPIOZ7",
	[STM32MP1_SHRES_IWDG1] = "IWDG1",
	[STM32MP1_SHRES_USART1] = "USART1",
	[STM32MP1_SHRES_SPI6] = "SPI6",
	[STM32MP1_SHRES_I2C4] = "I2C4",
	[STM32MP1_SHRES_RNG1] = "RNG1",
	[STM32MP1_SHRES_HASH1] = "HASH1",
	[STM32MP1_SHRES_CRYP1] = "CRYP1",
	[STM32MP1_SHRES_I2C6] = "I2C6",
	[STM32MP1_SHRES_RTC] = "RTC",
	[STM32MP1_SHRES_MCU] = "MCU",
	[STM32MP1_SHRES_PLL3] = "PLL3",
	[STM32MP1_SHRES_MDMA] = "MDMA",
	[STM32MP1_SHRES_SRAM1] = "SRAM1",
	[STM32MP1_SHRES_SRAM2] = "SRAM2",
	[STM32MP1_SHRES_SRAM3] = "SRAM3",
	[STM32MP1_SHRES_SRAM4] = "SRAM4",
};

static __maybe_unused const char *shres2str_id(enum stm32mp_shres id)
{
	return shres2str_id_tbl[id];
}

static const char *shres2str_state_tbl[4] __maybe_unused = {
	[SHRES_UNREGISTERED] = "unregistered",
	[SHRES_NON_SECURE] = "non-secure",
	[SHRES_SECURE] = "secure",
};

static __maybe_unused const char *shres2str_state(enum shres_state id)
{
	return shres2str_state_tbl[id];
}

/* GPIOZ bank pin count depends on SoC variants */
/* A light count routine for unpaged context to not depend on DTB support */
static int gpioz_nbpin = -1;

static unsigned int get_gpioz_nbpin(void)
{
	if (gpioz_nbpin < 0)
		panic();

	return gpioz_nbpin;
}

void stm32mp_register_gpioz_pin_count(size_t count)
{
	assert(gpioz_nbpin == -1);

	gpioz_nbpin = count;
}

static void register_periph(enum stm32mp_shres id, enum shres_state state)
{
	assert(id < STM32MP1_SHRES_COUNT &&
	       (state == SHRES_SECURE || state == SHRES_NON_SECURE));

	if (registering_locked)
		panic();

	if (shres_state[id] != SHRES_UNREGISTERED &&
	    shres_state[id] != state) {
		DMSG("Cannot change %s from %s to %s",
		     shres2str_id(id),
		     shres2str_state(shres_state[id]),
		     shres2str_state(state));
		panic();
	}

	if (shres_state[id] == SHRES_UNREGISTERED)
		DMSG("Register %s as %s",
		     shres2str_id(id), shres2str_state(state));

	switch (id) {
	case STM32MP1_SHRES_GPIOZ(0):
	case STM32MP1_SHRES_GPIOZ(1):
	case STM32MP1_SHRES_GPIOZ(2):
	case STM32MP1_SHRES_GPIOZ(3):
	case STM32MP1_SHRES_GPIOZ(4):
	case STM32MP1_SHRES_GPIOZ(5):
	case STM32MP1_SHRES_GPIOZ(6):
	case STM32MP1_SHRES_GPIOZ(7):
		if ((id - STM32MP1_SHRES_GPIOZ(0)) >= get_gpioz_nbpin()) {
			EMSG("Invalid GPIO %u >= %u",
			     id - STM32MP1_SHRES_GPIOZ(0), get_gpioz_nbpin());
			panic();
		}
		break;
	default:
		break;
	}

	shres_state[id] = state;

	/* Explore clock tree to lock secure clock dependencies */
	if (state == SHRES_SECURE) {
		switch (id) {
		case STM32MP1_SHRES_GPIOZ(0):
		case STM32MP1_SHRES_GPIOZ(1):
		case STM32MP1_SHRES_GPIOZ(2):
		case STM32MP1_SHRES_GPIOZ(3):
		case STM32MP1_SHRES_GPIOZ(4):
		case STM32MP1_SHRES_GPIOZ(5):
		case STM32MP1_SHRES_GPIOZ(6):
		case STM32MP1_SHRES_GPIOZ(7):
			stm32mp_register_clock_parents_secure(GPIOZ);
			break;
		case STM32MP1_SHRES_IWDG1:
			stm32mp_register_clock_parents_secure(IWDG1);
			break;
		case STM32MP1_SHRES_USART1:
			stm32mp_register_clock_parents_secure(USART1_K);
			break;
		case STM32MP1_SHRES_SPI6:
			stm32mp_register_clock_parents_secure(SPI6_K);
			break;
		case STM32MP1_SHRES_I2C4:
			stm32mp_register_clock_parents_secure(I2C4_K);
			break;
		case STM32MP1_SHRES_RNG1:
			stm32mp_register_clock_parents_secure(RNG1_K);
			break;
		case STM32MP1_SHRES_HASH1:
			stm32mp_register_clock_parents_secure(HASH1);
			break;
		case STM32MP1_SHRES_CRYP1:
			stm32mp_register_clock_parents_secure(CRYP1);
			break;
		case STM32MP1_SHRES_I2C6:
			stm32mp_register_clock_parents_secure(I2C6_K);
			break;
		case STM32MP1_SHRES_RTC:
			stm32mp_register_clock_parents_secure(RTC);
			break;
		default:
			/* No expected resource dependency */
			break;
		}
	}
}

/* Register resource by ID */
void stm32mp_register_secure_periph(enum stm32mp_shres id)
{
	register_periph(id, SHRES_SECURE);
}

void stm32mp_register_non_secure_periph(enum stm32mp_shres id)
{
	register_periph(id, SHRES_NON_SECURE);
}

/* Register resource by IO memory base address */
static void register_periph_iomem(vaddr_t base, enum shres_state state)
{
	enum stm32mp_shres id = STM32MP1_SHRES_COUNT;

	switch (base) {
	case IWDG1_BASE:
		id = STM32MP1_SHRES_IWDG1;
		break;
	case USART1_BASE:
		id = STM32MP1_SHRES_USART1;
		break;
	case SPI6_BASE:
		id = STM32MP1_SHRES_SPI6;
		break;
	case I2C4_BASE:
		id = STM32MP1_SHRES_I2C4;
		break;
	case I2C6_BASE:
		id = STM32MP1_SHRES_I2C6;
		break;
	case RTC_BASE:
		id = STM32MP1_SHRES_RTC;
		break;
	case RNG1_BASE:
		id = STM32MP1_SHRES_RNG1;
		break;
	case CRYP1_BASE:
		id = STM32MP1_SHRES_CRYP1;
		break;
	case HASH1_BASE:
		id = STM32MP1_SHRES_HASH1;
		break;
	case SRAM1_BASE:
		id = STM32MP1_SHRES_SRAM1;
		break;
	case SRAM2_BASE:
		id = STM32MP1_SHRES_SRAM2;
		break;
	case SRAM3_BASE:
		id = STM32MP1_SHRES_SRAM3;
		break;
	case SRAM4_BASE:
		id = STM32MP1_SHRES_SRAM4;
		break;

	/* Always non-secure resource cases */
#ifdef CFG_WITH_NSEC_GPIOS
	case GPIOA_BASE:
	case GPIOB_BASE:
	case GPIOC_BASE:
	case GPIOD_BASE:
	case GPIOE_BASE:
	case GPIOF_BASE:
	case GPIOG_BASE:
	case GPIOH_BASE:
	case GPIOI_BASE:
	case GPIOJ_BASE:
	case GPIOK_BASE:
	fallthrough;
#endif
#ifdef CFG_WITH_NSEC_UARTS
	case USART2_BASE:
	case USART3_BASE:
	case UART4_BASE:
	case UART5_BASE:
	case USART6_BASE:
	case UART7_BASE:
	case UART8_BASE:
	fallthrough;
#endif
#ifdef CFG_WITH_NSEC_I2CS
	case I2C5_BASE:
	fallthrough;
#endif
	case IWDG2_BASE:
		/* Allow drivers to register some non-secure resources */
		DMSG("IO for non-secure resource 0x%lx", base);
		if (state != SHRES_NON_SECURE)
			panic();

		return;

	default:
		panic();
		break;
	}

	register_periph(id, state);
}

void stm32mp_register_secure_periph_iomem(vaddr_t base)
{
	register_periph_iomem(base, SHRES_SECURE);
}

void stm32mp_register_non_secure_periph_iomem(vaddr_t base)
{
	register_periph_iomem(base, SHRES_NON_SECURE);
}

/* Register GPIO resource */
void stm32mp_register_secure_gpio(unsigned int bank, unsigned int pin)
{
	switch (bank) {
	case GPIO_BANK_Z:
		assert(pin < get_gpioz_nbpin());
		register_periph(STM32MP1_SHRES_GPIOZ(pin), SHRES_SECURE);
		break;
	default:
		EMSG("GPIO bank %u cannot be secured", bank);
		panic();
	}
}

void stm32mp_register_non_secure_gpio(unsigned int bank, unsigned int pin)
{
	switch (bank) {
	case GPIO_BANK_Z:
		assert(pin < get_gpioz_nbpin());
		register_periph(STM32MP1_SHRES_GPIOZ(pin), SHRES_NON_SECURE);
		break;
	default:
		break;
	}
}

void stm32mp_register_secure_pinctrl(struct pinctrl_state *pinctrl)
{
	unsigned int *bank = NULL;
	unsigned int *pin = NULL;
	size_t count = 0;
	size_t n = 0;

	stm32_gpio_pinctrl_bank_pin(pinctrl, NULL, NULL, &count);
	if (!count)
		return;

	bank = calloc(count, sizeof(*bank));
	pin = calloc(count, sizeof(*pin));
	if (!bank || !pin)
		panic();

	stm32_gpio_pinctrl_bank_pin(pinctrl, bank, pin, &count);
	for (n = 0; n < count; n++)
		stm32mp_register_secure_gpio(bank[n], pin[n]);

	free(bank);
	free(pin);
}

void stm32mp_register_non_secure_pinctrl(struct pinctrl_state *pinctrl)
{
	unsigned int *bank = NULL;
	unsigned int *pin = NULL;
	size_t count = 0;
	size_t n = 0;

	stm32_gpio_pinctrl_bank_pin(pinctrl, NULL, NULL, &count);
	if (!count)
		return;

	bank = calloc(count, sizeof(*bank));
	pin = calloc(count, sizeof(*pin));
	if (!bank || !pin)
		panic();

	stm32_gpio_pinctrl_bank_pin(pinctrl, bank, pin, &count);
	for (n = 0; n < count; n++)
		stm32mp_register_non_secure_gpio(bank[n], pin[n]);

	free(bank);
	free(pin);
}

static void lock_registering(void)
{
	registering_locked = true;
}

bool stm32mp_periph_is_secure(enum stm32mp_shres id)
{
	lock_registering();

	return shres_state[id] == SHRES_SECURE;
}

bool stm32mp_gpio_bank_is_non_secure(unsigned int bank)
{
	unsigned int not_secure = 0;
	unsigned int pin = 0;

	lock_registering();

	if (bank != GPIO_BANK_Z)
		return true;

	for (pin = 0; pin < get_gpioz_nbpin(); pin++)
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_GPIOZ(pin)))
			not_secure++;

	return not_secure > 0 && not_secure == get_gpioz_nbpin();
}

bool stm32mp_gpio_bank_is_secure(unsigned int bank)
{
	unsigned int secure = 0;
	unsigned int pin = 0;

	lock_registering();

	if (bank != GPIO_BANK_Z)
		return false;

	for (pin = 0; pin < get_gpioz_nbpin(); pin++)
		if (stm32mp_periph_is_secure(STM32MP1_SHRES_GPIOZ(pin)))
			secure++;

	return secure > 0 && secure == get_gpioz_nbpin();
}

static bool mckprot_resource(enum stm32mp_shres id)
{
	switch (id) {
	case STM32MP1_SHRES_MCU:
	case STM32MP1_SHRES_PLL3:
		return true;
	default:
		return false;
	}
}

static void check_rcc_secure_configuration(void)
{
	bool secure = stm32_rcc_is_secure();
	bool mckprot = stm32_rcc_is_mckprot();
	enum stm32mp_shres id = STM32MP1_SHRES_COUNT;
	bool need_secure = false;
	bool need_mckprot = false;

	for (id = 0; id < STM32MP1_SHRES_COUNT; id++) {
		if  (shres_state[id] != SHRES_SECURE)
			continue;

		/* SRAMs have no constraints on RCC configuration */
		if (id == STM32MP1_SHRES_SRAM1 ||
		    id == STM32MP1_SHRES_SRAM2 ||
		    id == STM32MP1_SHRES_SRAM3 ||
		    id == STM32MP1_SHRES_SRAM4)
			continue;

		need_secure = true;
		if (mckprot_resource(id))
			need_mckprot = true;

		if (!secure || (need_mckprot && !mckprot))
			EMSG("Error RCC TZEN=%u MCKPROT=%u and %s (%u) secure",
			      secure, mckprot, shres2str_id(id), id);
	}


	if ((need_secure && !secure) || (need_mckprot && !mckprot)) {
		if (IS_ENABLED(CFG_INSECURE))
			EMSG("WARNING: CFG_INSECURE allows insecure RCC configuration");
		else
			panic();
	}
}

static TEE_Result stm32mp1_init_final_shres(void)
{
	enum stm32mp_shres id = STM32MP1_SHRES_COUNT;

	lock_registering();

	for (id = (enum stm32mp_shres)0; id < STM32MP1_SHRES_COUNT; id++) {
		uint8_t __maybe_unused *state = &shres_state[id];

		DMSG("stm32mp %-8s (%2u): %-14s",
		     shres2str_id(id), id, shres2str_state(*state));
	}

	check_rcc_secure_configuration();

	return TEE_SUCCESS;
}
/* Finalize shres after drivers initialization, hence driver_init_late() */
driver_init_late(stm32mp1_init_final_shres);
