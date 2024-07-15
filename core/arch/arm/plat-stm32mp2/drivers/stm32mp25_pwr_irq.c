// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2024, STMicroelectronics
 */

#include <config.h>
#include <drivers/gpio.h>
#include <drivers/stm32_exti.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32mp25_pwr.h>
#include <initcall.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdio.h>
#include <stm32_util.h>
#include <sys/queue.h>

#define VERBOSE_PWR FMSG

#define PWR_IRQ_MAX_PROP_LENGTH	U(18)

/* PWR Registers */
#define PWR_WKUPCR1		0x60
/* WKUPCR bit definition */
#define WKUPC			BIT(0)
#define WKUPP			BIT(8)
#define WKUPPUPD		GENMASK_32(13, 12)
#define WKUPENCPU1		BIT(16)
#define WKUPENCPU2		BIT(17)
#define WKUPF			BIT(31)

#define WKUPPUPD_MASK		GENMASK_32(1, 0)
#define WKUPPUPD_SHIFT		U(12)

/* EXTI line number for PWR Wakeup pin 1 */
#define PWR_EXTI_WKUP1		52

enum wkup_pull_setting {
	WKUP_NO_PULL = 0,
	WKUP_PULL_UP,
	WKUP_PULL_DOWN,
	WKUP_PULL_RESERVED
};

struct pwr_wkup_data {
	struct stm32_pinctrl_list *pinctrl_list;
	struct itr_handler *hdl[PWR_NB_WAKEUPPINS];
	struct itr_handler *gic_hdl;
	struct stm32_exti_pdata *exti;
	bool threaded[PWR_NB_WAKEUPPINS];
	bool pending[PWR_NB_WAKEUPPINS];
	unsigned int spinlock;
};

static struct pwr_wkup_data *pwr_wkup_d;

static inline vaddr_t pwr_wkupcr_base(uint32_t pin)
{
	return stm32_pwr_base() + PWR_WKUPCR1 + pin * 4;
}

/* WAKEUP pins */
#define GPIO_BANK(port)	((port) - 'A')
#define GPIO_PORT(bank)	((bank) + 'A')

struct stm32_pwr_pin_map {
	uint8_t bank;
	uint8_t pin;
};

static const struct stm32_pwr_pin_map pin_map[PWR_NB_WAKEUPPINS] = {
	{ .bank = GPIO_BANK('A'), .pin = 0, },
	{ .bank = GPIO_BANK('H'), .pin = 5, },
	{ .bank = GPIO_BANK('G'), .pin = 1, },
	{ .bank = GPIO_BANK('I'), .pin = 6, },
	{ .bank = GPIO_BANK('G'), .pin = 2, },
	{ .bank = GPIO_BANK('G'), .pin = 3, },
};

static enum itr_return pwr_it_call_handler(struct pwr_wkup_data *priv,
					   uint32_t pin)
{
	uint32_t wkupcr = io_read32(pwr_wkupcr_base(pin));

	if (wkupcr & WKUPENCPU1) {
		VERBOSE_PWR("call wkup handler irq:%"PRIu32, pin);

		if (priv->hdl[pin]) {
			struct itr_handler *h = priv->hdl[pin];

			if (h->handler(h) != ITRR_HANDLED) {
				EMSG("Disabling unhandled IT %"PRIu32, pin);
				stm32mp25_pwr_itr_disable(pin);
			}
		}
	}

	return ITRR_HANDLED;
}

static enum itr_return pwr_it_threaded_handler(void)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;
	uint32_t i = 0;

	VERBOSE_PWR("threaded_handler");

	for (i = 0; i < PWR_NB_WAKEUPPINS; i++) {
		if (priv->pending[i]) {
			VERBOSE_PWR("handle pending wkup irq:%"PRIu32, i);
			priv->pending[i] = false;
			pwr_it_call_handler(priv, i);
		}
	}

	return ITRR_HANDLED;
}

static void yielding_stm32_pwr_notif(struct notif_driver *ndrv __unused,
				     enum notif_event ev)
{
	switch (ev) {
	case NOTIF_EVENT_DO_BOTTOM_HALF:
		VERBOSE_PWR("PWR Bottom half");
		pwr_it_threaded_handler();
		break;
	case NOTIF_EVENT_STOPPED:
		VERBOSE_PWR("PWR notif stopped");
		break;
	default:
		EMSG("Unknown event %d", ev);
		panic();
	}
}

struct notif_driver stm32_pwr_notif = {
	.yielding_cb = yielding_stm32_pwr_notif,
};

static enum itr_return pwr_it_handler(struct itr_handler *handler)
{
	struct pwr_wkup_data *priv = (struct pwr_wkup_data *)handler->data;
	uint32_t i = 0;

	VERBOSE_PWR("it_handler");

	interrupt_disable(interrupt_get_main_chip(), priv->gic_hdl->it);

	for (i = 0; i < PWR_NB_WAKEUPPINS; i++) {
		uint32_t wkupcr = 0;

		wkupcr = io_read32(pwr_wkupcr_base(i));
		if (wkupcr & WKUPF) {
			VERBOSE_PWR("handle wkup irq:%"PRIu32, i);

			/* Ack IRQ */
			io_setbits32(pwr_wkupcr_base(i), WKUPC);

			if (priv->threaded[i] && notif_async_is_started()) {
				priv->pending[i] = true;
				notif_send_async(NOTIF_VALUE_DO_BOTTOM_HALF);
			} else {
				pwr_it_call_handler(priv, i);
			}
		}
	}

	interrupt_enable(interrupt_get_main_chip(), priv->gic_hdl->it);

	return ITRR_HANDLED;
}

static TEE_Result
stm32_pwr_irq_set_pull_config(size_t it, enum wkup_pull_setting config)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;
	uint32_t exceptions = 0;

	VERBOSE_PWR("irq:%zu pull config:%#x", it, config);

	if (config >= WKUP_PULL_RESERVED) {
		EMSG("bad irq pull config");
		return TEE_ERROR_GENERIC;
	}

	exceptions = cpu_spin_lock_xsave(&priv->spinlock);

	io_mask32(pwr_wkupcr_base(it),
		  (config & WKUPPUPD_MASK) << (WKUPPUPD_SHIFT),
		  (WKUPPUPD_MASK) << (WKUPPUPD_SHIFT));

	cpu_spin_unlock_xrestore(&priv->spinlock, exceptions);

	return TEE_SUCCESS;
}

static void stm32mp25_pwr_itr_enable_nolock(size_t it)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;

	VERBOSE_PWR("Pwr irq enable %zu", it);

	if (IS_ENABLED(CFG_STM32_EXTI)) {
		stm32_exti_unmask(priv->exti, PWR_EXTI_WKUP1 + it);
		stm32_exti_enable_wake(priv->exti, PWR_EXTI_WKUP1 + it);
	}

	io_setbits32(pwr_wkupcr_base(it), WKUPENCPU1);
}

static void stm32mp25_pwr_itr_disable_nolock(size_t it)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;

	VERBOSE_PWR("Pwr irq disable %zu", it);

	io_clrbits32(pwr_wkupcr_base(it), WKUPENCPU1);

	if (IS_ENABLED(CFG_STM32_EXTI)) {
		stm32_exti_mask(priv->exti, PWR_EXTI_WKUP1 + it);
		stm32_exti_disable_wake(priv->exti, PWR_EXTI_WKUP1 + it);
	}
}

static TEE_Result stm32_pwr_irq_set_trig(size_t it, unsigned int flags)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;
	uint32_t exceptions = 0;
	int en = 0;

	VERBOSE_PWR("irq:%zu %s edge", it,
		    (flags & PWR_WKUP_FLAG_FALLING) ? "falling" : "rising");

	exceptions = cpu_spin_lock_xsave(&priv->spinlock);

	en = io_read32(pwr_wkupcr_base(it)) & WKUPENCPU1;
	/*
	 * Reference manual request to disable the wakeup pin while
	 * changing the edge detection setting.
	 */
	if (en)
		stm32mp25_pwr_itr_disable_nolock(it);

	if (flags & PWR_WKUP_FLAG_FALLING)
		io_setbits32(pwr_wkupcr_base(it), WKUPP);
	else
		io_clrbits32(pwr_wkupcr_base(it), WKUPP);

	if (en)
		stm32mp25_pwr_itr_enable_nolock(it);

	cpu_spin_unlock_xrestore(&priv->spinlock, exceptions);

	return TEE_SUCCESS;
}

void stm32mp25_pwr_itr_enable(size_t it)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&priv->spinlock);
	stm32mp25_pwr_itr_enable_nolock(it);
	cpu_spin_unlock_xrestore(&priv->spinlock, exceptions);
}

void stm32mp25_pwr_itr_disable(size_t it)
{
	struct pwr_wkup_data *priv = pwr_wkup_d;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&priv->spinlock);
	stm32mp25_pwr_itr_disable_nolock(it);
	cpu_spin_unlock_xrestore(&priv->spinlock, exceptions);
}

static TEE_Result stm32mp25_pwr_itr_add(const void *fdt, int wp_node,
					struct itr_handler *hdl)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pwr_wkup_data *priv = pwr_wkup_d;
	int it = hdl->it;
	struct gpio *gpio = NULL;
	uint32_t exceptions = 0;
	bool itr_free = false;
	unsigned int bank = 0;
	unsigned int pin = 0;

	VERBOSE_PWR("Pwr IRQ add");

	if (!priv) {
		DMSG("Pwr IRQs not yet initialized");
		return TEE_ERROR_DEFER_DRIVER_INIT;
	}

	assert(it >= PWR_WKUP_PIN1 && it < PWR_NB_WAKEUPPINS);

	/* Use PWR lock to ensure consistent interrupt registering */
	exceptions = cpu_spin_lock_xsave(&priv->spinlock);
	itr_free = !priv->hdl[it];
	if (itr_free)
		priv->hdl[it] = hdl;
	cpu_spin_unlock_xrestore(&priv->spinlock, exceptions);
	if (!itr_free)
		return TEE_ERROR_GENERIC;

	if (hdl->flags & PWR_WKUP_FLAG_THREADED)
		priv->threaded[it] = true;

	res = gpio_dt_get_by_index(fdt, wp_node, it, "wakeup", &gpio);
	if (res) {
		priv->hdl[it] = NULL;
		return res;
	}
	bank = stm32_gpio_chip_bank_id(gpio->chip);
	pin = gpio->pin;
	if (bank != pin_map[it].bank || pin != pin_map[it].pin) {
		EMSG("Invalid PWR WKUP%d on GPIO%c%"PRIu8" expected GPIO%c%"PRIu8,
		     it + 1, GPIO_PORT(bank), pin, GPIO_PORT(pin_map[it].bank),
		     pin_map[it].pin);
		panic();
	}

	stm32mp25_pwr_itr_disable(it);

	VERBOSE_PWR("Wake-up pin on pin=%"PRIu8, gpio->pin);

	/* use the same pull up configuration than for the gpio */
	if (gpio->dt_flags & GPIO_PULL_UP)
		res = stm32_pwr_irq_set_pull_config(it, WKUP_PULL_UP);
	else if (gpio->dt_flags & GPIO_PULL_DOWN)
		res = stm32_pwr_irq_set_pull_config(it, WKUP_PULL_DOWN);
	else
		res = stm32_pwr_irq_set_pull_config(it, WKUP_NO_PULL);
	if (res)
		return res;

	stm32_pwr_irq_set_trig(it, hdl->flags);

	if (IS_ENABLED(CFG_STM32_EXTI))
		stm32_exti_set_tz(priv->exti, PWR_EXTI_WKUP1 + it);

	return TEE_SUCCESS;
}

TEE_Result
stm32mp25_pwr_itr_alloc_add(const void *fdt, int wp_node, size_t it,
			    itr_handler_t handler, uint32_t flags, void *data,
			    struct itr_handler **phdl)
{
	TEE_Result res = TEE_SUCCESS;
	struct itr_handler *hdl = NULL;

	hdl = calloc(1, sizeof(*hdl));
	if (!hdl)
		return TEE_ERROR_OUT_OF_MEMORY;

	hdl->it = it;
	hdl->handler = handler;
	hdl->flags = flags;
	hdl->data = data;

	res = stm32mp25_pwr_itr_add(fdt, wp_node, hdl);
	if (res) {
		free(hdl);
		return res;
	}

	*phdl = hdl;

	return res;
}

TEE_Result
stm32mp25_pwr_irq_probe(const void *fdt, int node, int interrupt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pwr_wkup_data *priv = NULL;

	VERBOSE_PWR("Init PWR IRQ");

	pwr_wkup_d = calloc(1, sizeof(*pwr_wkup_d));
	if (!pwr_wkup_d)
		return TEE_ERROR_OUT_OF_MEMORY;

	priv = pwr_wkup_d;

	if (IS_ENABLED(CFG_STM32_EXTI)) {
		res = dt_driver_device_from_node_idx_prop("wakeup-parent",
							  fdt, node, 0,
							  DT_DRIVER_INTERRUPT,
							  &priv->exti);
		if (res)
			goto err;
	}

	res = interrupt_alloc_add_handler(interrupt_get_main_chip(),
					  interrupt, pwr_it_handler,
					  ITRF_TRIGGER_LEVEL, pwr_wkup_d,
					  &priv->gic_hdl);
	if (res)
		panic("Could not get wake-up pin IRQ");

	interrupt_enable(interrupt_get_main_chip(), priv->gic_hdl->it);

	if (IS_ENABLED(CFG_CORE_ASYNC_NOTIF))
		notif_register_driver(&stm32_pwr_notif);

	res = dt_driver_register_provider(fdt, node, NULL,
					  NULL, DT_DRIVER_NOTYPE);
	if (res)
		panic("Can't register provider");

	VERBOSE_PWR("Init pwr irq done");

	return TEE_SUCCESS;
err:
	free(pwr_wkup_d);
	pwr_wkup_d = NULL;

	return res;
}

static enum itr_return pwr_it_user_handler(struct itr_handler *handler)
{
	uint32_t *it_id = handler->data;

	VERBOSE_PWR("pwr irq tester handler");

	if (it_id)
		notif_send_it(*it_id);

	return ITRR_HANDLED;
}

static TEE_Result
stm32mp25_pwr_irq_user_dt_probe(const void *fdt, int node,
				const void *compat_data __unused)
{
	TEE_Result res = TEE_SUCCESS;
	struct itr_handler *hdl = NULL;
	const fdt32_t *cuint = NULL;
	int wakeup_parent_node = 0;
	size_t it = 0;
	uint32_t *it_id = NULL;
	int len = 0;
	uint32_t phandle = 0;

	cuint = fdt_getprop(fdt, node, "wakeup-parent", &len);
	if (!cuint || len != sizeof(uint32_t))
		panic("Missing wakeup-parent");

	phandle = fdt32_to_cpu(*cuint);
	if (!dt_driver_get_provider_by_phandle(phandle, DT_DRIVER_NOTYPE))
		return TEE_ERROR_DEFER_DRIVER_INIT;

	wakeup_parent_node = fdt_node_offset_by_phandle(fdt, phandle);

	cuint = fdt_getprop(fdt, node, "st,wakeup-pin-number", NULL);
	if (!cuint)
		panic("Missing wake-up pin number");

	it = fdt32_to_cpu(*cuint) - 1U;

	cuint = fdt_getprop(fdt, node, "st,notif-it-id", NULL);
	if (cuint) {
		it_id = calloc(1, sizeof(*it_id));
		if (!it_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		*it_id = fdt32_to_cpu(*cuint);
	}

	res = stm32mp25_pwr_itr_alloc_add(fdt, wakeup_parent_node, it,
					  pwr_it_user_handler,
					  PWR_WKUP_FLAG_FALLING, it_id, &hdl);
	if (res) {
		free(it_id);
		return res;
	}

	stm32mp25_pwr_itr_enable(hdl->it);

	return TEE_SUCCESS;
}

static const struct dt_device_match pwr_irq_test_match_table[] = {
	{ .compatible = "st,stm32mp21-pwr-irq-user" },
	{ .compatible = "st,stm32mp25-pwr-irq-user" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp25_pwr_irq_dt_tester) = {
	.name = "stm32mp25-pwr-irq-user",
	.match_table = pwr_irq_test_match_table,
	.probe = &stm32mp25_pwr_irq_user_dt_probe,
};
