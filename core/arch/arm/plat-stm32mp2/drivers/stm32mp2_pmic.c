// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2023, STMicroelectronics
 */

#include <config.h>
#include <drivers/regulator.h>
#include <drivers/stm32_exti.h>
#include <drivers/stm32_i2c.h>
#include <drivers/stm32mp25_pwr.h>
#include <drivers/stpmic2.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <stm32mp_pm.h>
#include <trace.h>
#include <util.h>

/* I2C transfer trial configuration */
#define PMIC_I2C_TRIALS			U(1)
#define PMIC_I2C_TIMEOUT_BUSY_MS	U(5)

/*
 * Low power configurations:
 *
 * STM32_PM_DEFAULT
 *   "default" sub nodes in device-tree
 *   is applied at probe, and re-applied at PM resume.
 *   should support STOP1, LP-STOP1, STOP2, LP-STOP2
 *
 * STM32_PM_LPLV
 *   "lplv" sub nodes in device-tree
 *   should support STOP1, LPLV-STOP1, STOP2, LPLV-STOP2
 *
 * STM32_PM_STANDBY
 *   "standby" sub nodes in device-tree
 *   should support STANDBY1-DDR-SR
 *   is applied in pm suspend call back
 *
 * STM32_PM_OFF
 *   "off" sub nodes in device-tree
 *   should support STANDBY-DDR-OFF mode
 *   and should be applied before shutdown
 *
 */
#define STM32_PM_DEFAULT		0
#define STM32_PM_LPLV			1
#define STM32_PM_STANDBY		2
#define STM32_PM_OFF			3
#define STM32_PM_NB_SOC_MODES		4

#define STPMIC2_LP_STATE_OFF		BIT(0)
#define STPMIC2_LP_STATE_ON		BIT(1)
#define STPMIC2_LP_STATE_UNMODIFIED	BIT(2)
#define STPMIC2_LP_STATE_SET_VOLT	BIT(3)

/*
 * struct pmic_regu - STPMIC2 regulator instance
 *
 * @pmic: Handle to PMIC device
 * @id: ID in PMIC device of the regulator controllers
 * @bypass_mv: 0 if not used, else is the voltage level to switch to bypass mode
 * @lp_state: Regulator mode during PM low power state, per PM states
 * @lp_level_uv: Regulator voltage level during PM low power state, per PM state
 * @levels_desc: Description of the supported voltage levels
 * @levels: Voltage level value array related to description @levels_desc
 */
struct pmic_regu {
	struct stpmic2 *pmic;
	uint32_t id;
	uint16_t bypass_mv;
	uint8_t lp_state[STM32_PM_NB_SOC_MODES];
	int lp_level_uv[STM32_PM_NB_SOC_MODES];
	struct regulator_voltages_desc levels_desc;
	int *levels;
};

/*
 * struct regu_dt_property - DT property helper
 * @name: DT property string name
 * @prop: Property decimal identifier
 */
struct regu_dt_property {
	const char *name;
	enum stpmic2_prop_id prop;
};

static const struct regu_dt_property prop_table[] = {
	{
		.name = "st,mask-reset",
		.prop = STPMIC2_MASK_RESET,
	},
	{
		.name = "st,regulator-bypass",
		.prop = STPMIC2_BYPASS,
	},
	{
		.name = "st,pwrctrl_enable",
		.prop = STPMIC2_PWRCTRL_EN,
	},
	{
		.name = "st,pwrctrl_reset",
		.prop = STPMIC2_PWRCTRL_RS,
	},
	{
		.name = "st,pwrctrl_sel",
		.prop = STPMIC2_PWRCTRL_SEL,
	},
};

/*
 * Local platform PM states helper functions
 */
static size_t plat_get_lp_mode_count(void)
{
	return STM32_PM_NB_SOC_MODES;
}

static const char *plat_get_lp_mode_name(int mode)
{
	switch (mode) {
	case STM32_PM_DEFAULT:
		return "default";
	case STM32_PM_LPLV:
		return "lplv";
	case STM32_PM_STANDBY:
		return "standby";
	case STM32_PM_OFF:
		return "off";
	default:
		EMSG("Invalid lp mode %d", mode);
		panic();
	}
}

static void lock_unlock(bool lock_not_unlock)
{
	static struct mutex pmic_mu = MUTEX_INITIALIZER;

	if (thread_get_id_may_fail() != THREAD_ID_INVALID) {
		if (lock_not_unlock)
			mutex_lock(&pmic_mu);
		else
			mutex_unlock(&pmic_mu);
	}
}

static void lock_pmic_access(void)
{
	lock_unlock(true);
}

static void unlock_pmic_access(void)
{
	lock_unlock(false);
}

/*
 * Regulator operation handler
 */
static TEE_Result pmic_set_state(struct regulator *regulator, bool enable)
{
	struct pmic_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set state to %u", regulator_name(regulator), enable);

	lock_pmic_access();
	res = stpmic2_regulator_set_state(regu->pmic, regu->id, enable);
	unlock_pmic_access();

	return res;
}

static TEE_Result pmic_get_state(struct regulator *regulator, bool *enabled)
{
	struct pmic_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: get state", regulator_name(regulator));

	lock_pmic_access();
	res = stpmic2_regulator_get_state(regu->pmic, regu->id, enabled);
	unlock_pmic_access();

	return res;
}

static TEE_Result pmic_get_voltage(struct regulator *regulator, int *level_uv)
{
	struct pmic_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t val = 0;

	lock_pmic_access();

	if (regu->bypass_mv) {
		uint8_t arg = 0;

		/* If the regul is in bypass mode, return bypass value */
		res = stpmic2_regulator_get_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS, &arg);
		if (res)
			goto out;

		if (arg == PROP_BYPASS_SET) {
			*level_uv = (int)regu->bypass_mv * 1000;
			goto out;
		}
	}

	res = stpmic2_regulator_get_voltage(regu->pmic, regu->id, &val);
	if (res)
		goto out;

	*level_uv = (int)val * 1000;

	FMSG("%s: get voltage: %d uV", regulator_name(regulator), *level_uv);
out:
	unlock_pmic_access();

	return res;
}

static TEE_Result pmic_set_voltage(struct regulator *regulator, int level_uv)
{
	struct pmic_regu *regu = regulator->priv;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set volt to %d mV", regulator_name(regulator), level_uv);

	lock_pmic_access();

	if (level_uv == regu->bypass_mv * 1000) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS,
						 PROP_BYPASS_SET);
		/* Do not set voltage in the register */
		goto out;
	}

	res = stpmic2_regulator_set_voltage(regu->pmic, regu->id,
					    level_uv / 1000);
	if (res)
		goto out;

	/* disable bypass after set voltage ; wait settling time ? */
	if (regu->bypass_mv && level_uv != regu->bypass_mv * 1000)
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_BYPASS,
						 PROP_BYPASS_RESET);
out:
	unlock_pmic_access();

	return res;
}

static TEE_Result pmic_list_voltages(struct regulator *regulator,
				     struct regulator_voltages_desc **desc,
				     const int **levels)
{
	struct pmic_regu *regu = regulator->priv;

	FMSG("%s: list volt", regulator_name(regulator));

	if (!regu->levels) {
		TEE_Result res = TEE_ERROR_GENERIC;
		const uint16_t *levels_mv = NULL;
		size_t count = 0;
		size_t n = 0;

		res = stpmic2_regulator_levels_mv(regu->pmic, regu->id,
						  &levels_mv, &count);
		if (res)
			return res;

		n = sizeof(regu->levels_desc) + count * sizeof(*regu->levels);
		regu->levels = calloc(1, n);
		if (!regu->levels)
			return TEE_ERROR_OUT_OF_MEMORY;

		regu->levels_desc.type = VOLTAGE_TYPE_FULL_LIST;
		regu->levels_desc.num_levels = count;
		for (n = 0; n < count; n++)
			regu->levels[n] = (int)levels_mv[n] * 1000;
	}

	*desc = &regu->levels_desc;
	*levels = regu->levels;

	return TEE_SUCCESS;
}

static TEE_Result apply_pm_state(struct regulator *regulator, uint8_t mode)
{
	struct pmic_regu *regu = regulator->priv;
	uint8_t state = regu->lp_state[mode];
	int lp_level_uv = regu->lp_level_uv[mode];
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: suspend state:%#"PRIx8" %d uV",
	     regulator_name(regulator), state, lp_level_uv);

	if (state & STPMIC2_LP_STATE_UNMODIFIED)
		return TEE_SUCCESS;

	if (state & STPMIC2_LP_STATE_OFF) {
		res = stpmic2_lp_set_state(regu->pmic, regu->id, false);
		if (res)
			return res;
	}

	if (state & STPMIC2_LP_STATE_ON) {
		res = stpmic2_lp_set_state(regu->pmic, regu->id, true);
		if (res)
			return res;

		if (state & STPMIC2_LP_STATE_SET_VOLT) {
			res = stpmic2_lp_set_voltage(regu->pmic, regu->id,
						     lp_level_uv / 1000);
			if (res)
				return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result pmic_regu_pm(enum pm_op op, uint32_t pm_hint,
			       const struct pm_callback_handle *pm_handle)
{
	struct regulator *regulator = pm_handle->handle;
	unsigned int pwrlvl = PM_HINT_PLATFORM_STATE(pm_hint);
	uint8_t mode = STM32_PM_DEFAULT;

	if (op == PM_OP_SUSPEND) {
		/* configure PMIC level according MAX PM domain OFF */
		switch (pwrlvl) {
		case PM_D1_LEVEL:
		case PM_D2_LEVEL:
			mode = STM32_PM_LPLV;
			break;
		case PM_D2_LPLV_LEVEL:
			mode = STM32_PM_STANDBY;
			break;
		case PM_MAX_LEVEL:
			mode = STM32_PM_OFF;
			break;
		default:
			mode = STM32_PM_DEFAULT;
			break;
		}
	} else if (op == PM_OP_RESUME) {
		mode = STM32_PM_DEFAULT;
	}

	return apply_pm_state(regulator, mode);
}

static TEE_Result pmic_supplied_init(struct regulator *regulator,
				     const void *fdt, int node)
{
	struct pmic_regu *regu = regulator->priv;
	const struct regu_dt_property *p = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (regulator->flags & REGULATOR_PULL_DOWN) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_PULL_DOWN, 0);
		if (res)
			return res;
	}

	if (regulator->flags & REGULATOR_OVER_CURRENT) {
		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 STPMIC2_OCP, 0);
		if (res)
			return res;
	}

	for (p = prop_table; p < (prop_table + ARRAY_SIZE(prop_table)); p++) {
		const fdt32_t *cuint = NULL;
		uint32_t value = 0;

		cuint = fdt_getprop(fdt, node, p->name, NULL);
		if (!cuint)
			continue;

		value = fdt32_to_cpu(*cuint);
		FMSG("%s: %d, %#"PRIx32, regulator_name(regulator), p->prop,
		     value);

		res = stpmic2_regulator_set_prop(regu->pmic, regu->id,
						 p->prop, value);
		if (res)
			return res;

	}

	res = apply_pm_state(regulator, STM32_PM_DEFAULT);
	if (res) {
		EMSG("Failed to prepare regu suspend %s",
		     regulator_name(regulator));
		free(regu);
		return res;
	}

	register_pm_core_service_cb(pmic_regu_pm, regulator,
				    regulator_name(regulator));

	return TEE_SUCCESS;
}

static const struct regulator_ops pmic_regu_ops = {
	.set_state = pmic_set_state,
	.get_state = pmic_get_state,
	.set_voltage = pmic_set_voltage,
	.get_voltage = pmic_get_voltage,
	.supported_voltages = pmic_list_voltages,
	.supplied_init = pmic_supplied_init,
};

#define DEFINE_REGU(_name) { \
		.name = (_name), \
		.ops = &pmic_regu_ops, \
	}

static const struct regu_dt_desc pmic_reguls[STPMIC2_NB_REG] = {
	[STPMIC2_BUCK1] = DEFINE_REGU("buck1"),
	[STPMIC2_BUCK2] = DEFINE_REGU("buck2"),
	[STPMIC2_BUCK3] = DEFINE_REGU("buck3"),
	[STPMIC2_BUCK4] = DEFINE_REGU("buck4"),
	[STPMIC2_BUCK5] = DEFINE_REGU("buck5"),
	[STPMIC2_BUCK6] = DEFINE_REGU("buck6"),
	[STPMIC2_BUCK7] = DEFINE_REGU("buck7"),

	[STPMIC2_LDO1] = DEFINE_REGU("ldo1"),
	[STPMIC2_LDO2] = DEFINE_REGU("ldo2"),
	[STPMIC2_LDO3] = DEFINE_REGU("ldo3"),
	[STPMIC2_LDO4] = DEFINE_REGU("ldo4"),
	[STPMIC2_LDO5] = DEFINE_REGU("ldo5"),
	[STPMIC2_LDO6] = DEFINE_REGU("ldo6"),
	[STPMIC2_LDO7] = DEFINE_REGU("ldo7"),
	[STPMIC2_LDO8] = DEFINE_REGU("ldo8"),

	[STPMIC2_REFDDR] = DEFINE_REGU("refddr"),
};
DECLARE_KEEP_PAGER(pmic_reguls);

static void pmic_parse_regu_node(struct regu_dt_desc *regu_desc,
				 const void *fdt, int node)
{
	struct pmic_regu *regu = regu_desc->priv;
	const fdt32_t *cuint = NULL;
	uint32_t value = 0;
	const char __maybe_unused *regu_name = pmic_reguls[regu->id].name;

	cuint = fdt_getprop(fdt, node, "st,regulator-bypass-microvolt", NULL);
	if (!cuint)
		return;

	value = fdt32_to_cpu(*cuint);
	FMSG("%s: bypass= %#"PRIx32, regu_name, value);

	assert((value / 1000) <= UINT16_MAX);
	regu->bypass_mv = value / 1000;
}

static void parse_low_power_mode(const void *fdt, int node,
				 struct pmic_regu *regu, int mode)
{
	const fdt32_t *cuint = NULL;
	const char __maybe_unused *regu_name = pmic_reguls[regu->id].name;

	regu->lp_state[mode] = 0;

	if (fdt_getprop(fdt, node, "regulator-off-in-suspend", NULL)) {
		FMSG("%s: mode:%d OFF", regu_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_OFF;
	} else if (fdt_getprop(fdt, node, "regulator-on-in-suspend", NULL)) {
		FMSG("%s: mode:%d ON", regu_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_ON;
	} else {
		regu->lp_state[mode] |= STPMIC2_LP_STATE_UNMODIFIED;
	}

	cuint = fdt_getprop(fdt, node, "regulator-suspend-microvolt", NULL);
	if (cuint) {
		int level_uv = (int)fdt32_to_cpu(*cuint);

		FMSG("%s: mode:%d suspend to %d uV", regu_name, mode, level_uv);

		regu->lp_state[mode] |= STPMIC2_LP_STATE_SET_VOLT;
		regu->lp_level_uv[mode] = level_uv;
	}
}

static void parse_low_power_modes(const void *fdt, int node,
				  struct pmic_regu *regu)
{
	const size_t lp_mode_count = plat_get_lp_mode_count();
	unsigned int mode = 0;

	for (mode = 0; mode < lp_mode_count; mode++) {
		const char *lp_mode_name = plat_get_lp_mode_name(mode);

		if (lp_mode_name) {
			int n = 0;

			/* Get the configs from regulator_state_node subnode */
			n = fdt_subnode_offset(fdt, node, lp_mode_name);
			if (n >= 0)
				parse_low_power_mode(fdt, n, regu, mode);
		}
	}
}

static TEE_Result register_pmic_regulator(const void *fdt, struct stpmic2 *pmic,
					  const char *regu_name, int node,
					  int parent_node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regu_dt_desc desc = { };
	struct pmic_regu *regu = NULL;
	size_t id = 0;

	FMSG("Stpmic2 register %s", regu_name);

	for (id = 0; id < STPMIC2_NB_REG; id++)
		if (!strcmp(pmic_reguls[id].name, regu_name))
			break;
	assert(id < ARRAY_SIZE(pmic_reguls));

	regu = calloc(1, sizeof(*regu));
	if (!regu)
		return TEE_ERROR_OUT_OF_MEMORY;

	regu->pmic = pmic;
	regu->id = id;

	desc = pmic_reguls[id];
	desc.priv = regu;

	pmic_parse_regu_node(&desc, fdt, node);

	res = regulator_dt_register(fdt, node, parent_node, &desc);
	if (res) {
		EMSG("Failed to register %s", regu_name);
		free(regu);
		return res;
	}

	parse_low_power_modes(fdt, node, regu);

	return TEE_SUCCESS;
}

static TEE_Result parse_regulator_fdt_nodes(const void *fdt, int node,
					    struct stpmic2 *pmic)
{
	int regulators_node = 0;
	int regu_node = 0;

	regulators_node = fdt_subnode_offset(fdt, node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		TEE_Result res = TEE_ERROR_GENERIC;
		int status = fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;

		assert(status >= 0);
		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);
		assert(regu_name);

		res = register_pmic_regulator(fdt, pmic, regu_name, regu_node,
					      regulators_node);
		if (res) {
			EMSG("Failed to register %s", regu_name);
			return res;
		}
	}

	return TEE_SUCCESS;
}

#ifdef CFG_STM32_PWR_IRQ
static enum itr_return stpmic2_irq_handler(struct itr_handler *handler)
{
	struct stpmic2 *pmic = handler->data;

	FMSG("Stpmic2 irq");

	stpmic2_handle_irq(pmic);

	return ITRR_HANDLED;
}

static TEE_Result initialize_pmic2_irq(const void *fdt, int node,
				       struct stpmic2 *pmic)
{
	struct itr_handler *hdl = NULL;
	const fdt32_t *cuint = NULL;

	FMSG("Init stpmic2 irq");

	cuint = fdt_getprop(fdt, node, "st,wakeup-pin-number", NULL);
	if (cuint) {
		TEE_Result res = TEE_ERROR_GENERIC;
		size_t it = 0;

		it = fdt32_to_cpu(*cuint) - 1;

		res = stm32mp25_pwr_itr_alloc_add(it, stpmic2_irq_handler,
						  PWR_WKUP_FLAG_FALLING |
						  PWR_WKUP_FLAG_THREADED,
						  pmic, &hdl);
		if (res)
			return res;

		stm32mp25_pwr_itr_enable(hdl->it);
	}

	/* Enable ponkey irq */
	if (stpmic2_set_irq_mask(pmic, IT_PONKEY_F, false))
		return TEE_ERROR_GENERIC;

	if (stpmic2_set_irq_mask(pmic, IT_PONKEY_R, false))
		return TEE_ERROR_GENERIC;

	/* Unmask all over-current interrupts */
	if (stpmic2_register_write(pmic, INT_MASK_R3, 0x00))
		return TEE_ERROR_GENERIC;

	if (stpmic2_register_write(pmic, INT_MASK_R4, 0x00))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

static void initialize_pmic2_i2c(const void *fdt, int node,
				 struct stpmic2 *pmic, struct i2c_handle_s *i2c)
{
	const fdt32_t *cuint = NULL;
	uint32_t pmic_i2c_addr = 0;

	cuint = fdt_getprop(fdt, node, "reg", NULL);
	if (!cuint)
		panic("PMIC configuration failed on reg property");

	pmic_i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (pmic_i2c_addr > UINT16_MAX)
		panic("PMIC configuration failed on i2c address translation");

	if (!stm32_i2c_is_device_ready(i2c, pmic_i2c_addr, PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS))
		panic("PMIC2 I2C init failed");

	pmic->pmic_i2c_handle = i2c;
	pmic->pmic_i2c_addr = pmic_i2c_addr;
}

/*
 * PMIC and resource initialization
 */
static void initialize_pmic2(const void *fdt, int node,
			     struct stpmic2 *pmic, struct i2c_handle_s *i2c)
{
	uint8_t ver = 0;
	uint8_t pid = 0;

	FMSG("Initialize stpmic2");

	initialize_pmic2_i2c(fdt, node, pmic, i2c);

	if (stpmic2_get_product_id(pmic, &pid) ||
	    stpmic2_get_version(pmic, &ver))
		panic("Failed to access PMIC");

	DMSG("PMIC pid=%#"PRIx8" version=%#"PRIx8, pid, ver);
	stpmic2_dump_regulators(pmic);
}

static TEE_Result stm32_pmic2_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	struct stm32_i2c_dev *stm32_i2c_dev = NULL;
	struct i2c_dev *i2c_dev = NULL;
	struct stpmic2 *pmic = NULL;
	TEE_Result res = TEE_SUCCESS;

	FMSG("Probe stpmic2");

	res = i2c_dt_get_dev(fdt, node, &i2c_dev);
	if (res)
		return res;

	stm32_i2c_dev = container_of(i2c_dev, struct stm32_i2c_dev, i2c_dev);

	pmic = calloc(1, sizeof(*pmic));
	if (!pmic)
		panic();

	initialize_pmic2(fdt, node, pmic, stm32_i2c_dev->handle);

#ifdef CFG_STM32_PWR_IRQ
	res = initialize_pmic2_irq(fdt, node, pmic);
	if (res) {
		free(pmic);
		return res;
	}
#endif

	res = parse_regulator_fdt_nodes(fdt, node, pmic);
	if (res)
		panic();

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_pmic2_match_table[] = {
	{ .compatible = "st,stpmic2" },
	{ }
};

DEFINE_DT_DRIVER(stm32_pmic2_dt_driver) = {
	.name = "stm32_pmic2",
	.match_table = stm32_pmic2_match_table,
	.probe = stm32_pmic2_probe,
};

