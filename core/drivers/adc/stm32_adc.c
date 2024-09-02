// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <assert.h>
#include <drivers/adc.h>
#include <drivers/stm32_adc_core.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <trace.h>

/* STM32MP13 - Registers for each ADC instance */
#define STM32MP13_ADC_ISR		U(0x0)
#define STM32MP13_ADC_CR		U(0x8)
#define STM32MP13_ADC_CFGR		U(0xC)
#define STM32MP13_ADC_SMPR1		U(0x14)
#define STM32MP13_ADC_SMPR2		U(0x18)
#define STM32MP13_ADC_TR1		U(0x20)
#define STM32MP13_ADC_TR2		U(0x24)
#define STM32MP13_ADC_TR3		U(0x28)
#define STM32MP13_ADC_SQR1		U(0x30)
#define STM32MP13_ADC_SQR2		U(0x34)
#define STM32MP13_ADC_SQR3		U(0x38)
#define STM32MP13_ADC_SQR4		U(0x3C)
#define STM32MP13_ADC_DR		U(0x40)
#define STM32MP13_ADC_DIFSEL		U(0xB0)
#define STM32MP13_ADC_CALFACT		U(0xB4)
#define STM32MP13_ADC2_OR		U(0xC8)
#define STM32MP13_ADC_AWD2CR		U(0xA0)
#define STM32MP13_ADC_AWD3CR		U(0xA4)

/* STM32MP13_ADC_ISR - bit fields */
#define STM32MP13_AWD3			BIT(9)
#define STM32MP13_AWD2			BIT(8)
#define STM32MP13_AWD1			BIT(7)
#define STM32MP13_OVR			BIT(4)
#define STM32MP13_EOC			BIT(2)
#define STM32MP13_ADRDY			BIT(0)

/* STM32MP13_ADC_CFGR bit fields */
#define STM32MP13_AWD1CH		GENMASK_32(30, 26)
#define STM32MP13_AWD1CH_SHIFT		U(26)
#define STM32MP13_EXTEN			GENMASK_32(11, 10)
#define STM32MP13_AWD1EN		BIT(23)
#define STM32MP13_AWD1SGL		BIT(22)
#define STM32MP13_CONT			BIT(13)
#define STM32MP13_OVRMOD		BIT(12)
#define STM32MP13_RES			GENMASK_32(4, 3)
#define STM32MP13_DMACFG		BIT(1)
#define STM32MP13_DMAEN			BIT(0)

/* STM32MP13_ADC_CR - bit fields */
#define STM32MP13_ADCAL			BIT(31)
#define STM32MP13_ADCALDIF		BIT(30)
#define STM32MP13_DEEPPWD		BIT(29)
#define STM32MP13_ADVREGEN		BIT(28)
#define STM32MP13_ADSTP			BIT(4)
#define STM32MP13_ADSTART		BIT(2)
#define STM32MP13_ADDIS			BIT(1)
#define STM32MP13_ADEN			BIT(0)

/* STM32MP13_ADC_TR1 - bit fields */
#define STM32MP13_HT1			GENMASK_32(27, 16)
#define STM32MP13_HT1_SHIFT		U(16)
#define STM32MP13_LT1			GENMASK_32(11, 0)

/* STM32MP13_ADC_TR2 - bit fields */
#define STM32MP13_HT2			GENMASK_32(23, 16)
#define STM32MP13_HT2_SHIFT		U(16)
#define STM32MP13_LT2			GENMASK_32(7, 0)
#define STM32MP13_LT2_SHIFT		U(4)

/* STM32MP13_ADC_TR3 - bit fields */
#define STM32MP13_HT3			GENMASK_32(23, 16)
#define STM32MP13_HT3_SHIFT		U(16)
#define STM32MP13_LT3			GENMASK_32(7, 0)
#define STM32MP13_LT3_SHIFT		U(4)

/* STM32MP13_ADC_SQR1 - bit fields */
#define STM32MP13_SQ1_SHIFT		U(6)

/* STM32MP13_ADC_DIFSEL - bit fields */
#define STM32MP13_DIFSEL_SHIFT		U(0)
#define STM32MP13_DIFSEL_MASK		GENMASK_32(18, 0)

/* STM32MP13_ADC2_OR - bit fields */
#define STM32MP13_OP0			BIT(0)
#define STM32MP13_OP1			BIT(1)
#define STM32MP13_OP2			BIT(2)

/* STM32MP13_ADC_AWD2CR - bit fields */
#define STM32MP13_AWD2CH		GENMASK_32(18, 0)

/* STM32MP13_ADC_AWD3CR - bit fields */
#define STM32MP13_AWD3CH		GENMASK_32(18, 0)

#define STM32MP13_ADC_MAX_RES		U(12)
#define STM32MP13_ADC_CH_MAX		U(19)
#define STM32MP13_ADC_AWD_NB		U(3)
#define STM32MP13_ADC_MAX_SQ		U(16)	/* SQ1..SQ16 */
#define STM32_ADC_MAX_SMP		U(7)	/* SMPx range is [0..7] */

/* STM32MP25 - Registers for each ADC instance */
#define STM32MP25_ADC_DIFSEL		U(0xC0)
#define STM32MP25_ADC_CALFACT		U(0xC4)
#define STM32MP25_ADC_OR		U(0xD0)
#define STM32MP25_ADC_AWD2CR		U(0xA0)
#define STM32MP25_ADC_AWD3CR		U(0xA4)
#define STM32MP25_ADC_AWD1LTR		U(0xA8)
#define STM32MP25_ADC_AWD1HTR		U(0xAC)
#define STM32MP25_ADC_AWD2LTR		U(0xB0)
#define STM32MP25_ADC_AWD2HTR		U(0xB4)
#define STM32MP25_ADC_AWD3LTR		U(0xB8)
#define STM32MP25_ADC_AWD3HTR		U(0xBC)

#define STM32MP25_ADC_AWD2CH_MASK	GENMASK_32(19, 0)
#define STM32MP25_ADC_AWD3CH_MASK	GENMASK_32(19, 0)
#define STM32MP25_ADC_AWD1LTR_MASK	GENMASK_32(22, 0)
#define STM32MP25_ADC_AWD1HTR_MASK	GENMASK_32(22, 0)
#define STM32MP25_ADC_AWD2LTR_MASK	GENMASK_32(22, 0)
#define STM32MP25_ADC_AWD2HTR_MASK	GENMASK_32(22, 0)
#define STM32MP25_ADC_AWD3LTR_MASK	GENMASK_32(22, 0)
#define STM32MP25_ADC_AWD3HTR_MASK	GENMASK_32(22, 0)

/* STM32MP25_ADC_CFGR bit fields */
#define STM32MP25_RES		GENMASK_32(3, 2)

/* STM32MP25_ADC_OR - bit fields */
#define STM32MP25_OP3			BIT(3)
#define STM32MP25_OP4			BIT(4)

/* STM32MP25_ADC_CALFACT bit fields */
#define STM32MP25_CALADDOS		BIT(31)
#define STM32MP25_CALFACT_S		GENMASK_32(8, 0)
#define STM32MP25_CALFACT_D		GENMASK_32(24, 16)
#define STM32MP25_CALFACT_D_SHIFT	U(16)

#define STM32MP25_DIFSEL_MASK		GENMASK_32(19, 0)

#define STM32MP25_ADC_CH_MAX		U(20)
#define STM32MP25_CALIB_LOOP		U(8)

#define STM32_ADC_TIMEOUT_US		U(100000)
#define STM32_ADC_NSEC_PER_SEC		UL(1000000000)
#define STM32_ADCVREG_STUP_DELAY_US	U(20)

/**
 * Fixed timeout value for ADC calibration.
 * worst cases:
 * - low clock frequency (0.12 MHz min)
 * - maximum prescalers
 * - 20 ADC clock cycle for the offset calibration
 *
 * Set to 40ms for now
 */
#define STM32MP13_ADC_CALIB_TIMEOUT_US	U(40000)
/* max channel name size */
#define STM32_ADC_CH_NAME_SZ		U(16)

enum stm32_adc_int_ch {
	STM32_ADC_INT_CH_NONE = -1,
	STM32_ADC_INT_CH_VDDCORE,
	STM32_ADC_INT_CH_VDDCPU,
	STM32_ADC_INT_CH_VDDQ_DDR,
	STM32_ADC_INT_CH_VREFINT,
	STM32_ADC_INT_CH_VBAT,
	STM32_ADC_INT_CH_VDDGPU,
	STM32_ADC_INT_CH_NB
};

struct stm32_adc_ic {
	const char *name;
	uint32_t idx;
};

struct stm32_adc_data {
	struct adc_device *dev;
	struct stm32_adc_common *common;
	vaddr_t regs;
	uint32_t smpr[2];
	int int_ch[STM32_ADC_INT_CH_NB];
	const struct stm32_adc_cfg *cfg;
};

struct stm32_adc_regs {
	int reg;
	int msk;
	int shift;
};

struct stm32_adc_awd_reginfo {
	const struct stm32_adc_regs awd_ch;
	const struct stm32_adc_regs awd_lt;
	const struct stm32_adc_regs awd_ht;
	const struct stm32_adc_regs awd_en;
	const struct stm32_adc_regs awd_sgl;
};

struct stm32_adc_regspec {
	const unsigned int data_res;
	const struct stm32_adc_regs or_vddcore;
	const struct stm32_adc_regs or_vddcpu;
	const struct stm32_adc_regs or_vddq_ddr;
	const struct stm32_adc_regs ccr_vref;
	const struct stm32_adc_regs ccr_vbat;
	const struct stm32_adc_regs or_vddgpu;
	const struct stm32_adc_awd_reginfo *awd_reginfo;
};

struct stm32_adc_cfg {
	const unsigned int max_channels;
	const unsigned int *min_ts;
	const unsigned int *smp_cycles;
	const struct stm32_adc_regspec *regs;
	bool has_vregen;
	TEE_Result (*hw_start)(struct adc_device *adc_dev);
};

static const struct stm32_adc_ic stm32_adc_ic[STM32_ADC_INT_CH_NB] = {
	{ .name = "vddcore", .idx = STM32_ADC_INT_CH_VDDCORE },
	{ .name = "vddcpu", .idx = STM32_ADC_INT_CH_VDDCPU },
	{ .name = "vddq_ddr", .idx = STM32_ADC_INT_CH_VDDQ_DDR },
	{ .name = "vrefint", .idx = STM32_ADC_INT_CH_VREFINT },
	{ .name = "vbat", .idx = STM32_ADC_INT_CH_VBAT },
	{ .name = "vddgpu", .idx = STM32_ADC_INT_CH_VDDGPU },
};

/* STM32MP13 programmable sampling time (ADC clock cycles, rounded down) */
static const unsigned int
stm32mp13_adc_smp_cycles[STM32_ADC_MAX_SMP + 1] = {
	2, 6, 12, 24, 47, 92, 247, 640
};

static const unsigned int
stm32mp25_adc_smp_cycles[STM32_ADC_MAX_SMP + 1] = {
	2, 3, 7, 12, 24, 47, 247, 1501,
};

/*
 * stm32_adc_smp_bits - describe sampling time register index & bit fields
 * Sorted so it can be indexed by channel number.
 */
static const struct stm32_adc_regs stm32_adc_smp_bits[] = {
	/* ADC_SMPR1, smpr[] index, mask, shift for SMP0 to SMP9 */
	{ 0, GENMASK_32(2, 0), 0 },
	{ 0, GENMASK_32(5, 3), 3 },
	{ 0, GENMASK_32(8, 6), 6 },
	{ 0, GENMASK_32(11, 9), 9 },
	{ 0, GENMASK_32(14, 12), 12 },
	{ 0, GENMASK_32(17, 15), 15 },
	{ 0, GENMASK_32(20, 18), 18 },
	{ 0, GENMASK_32(23, 21), 21 },
	{ 0, GENMASK_32(26, 24), 24 },
	{ 0, GENMASK_32(29, 27), 27 },
	/* ADC_SMPR2, smpr[] index, mask, shift for SMP10 to SMP19 */
	{ 1, GENMASK_32(2, 0), 0 },
	{ 1, GENMASK_32(5, 3), 3 },
	{ 1, GENMASK_32(8, 6), 6 },
	{ 1, GENMASK_32(11, 9), 9 },
	{ 1, GENMASK_32(14, 12), 12 },
	{ 1, GENMASK_32(17, 15), 15 },
	{ 1, GENMASK_32(20, 18), 18 },
	{ 1, GENMASK_32(23, 21), 21 },
	{ 1, GENMASK_32(26, 24), 24 },
	{ 1, GENMASK_32(29, 27), 27 },
};

static const unsigned int stm32mp13_adc_min_ts[] = { 1000, 1000, 1000, 4300,
						     9800, 0};
static_assert(ARRAY_SIZE(stm32mp13_adc_min_ts) == STM32_ADC_INT_CH_NB);
static const unsigned int stm32mp21_adc_min_ts[] = { 34, 34, 0, 34, 34, 0 };
static_assert(ARRAY_SIZE(stm32mp21_adc_min_ts) == STM32_ADC_INT_CH_NB);
static const unsigned int stm32mp25_adc_min_ts[] = { 34, 34, 0, 34, 34, 34 };
static_assert(ARRAY_SIZE(stm32mp25_adc_min_ts) == STM32_ADC_INT_CH_NB);

/**
 * STM32MP13_awd_reginfo[] - Analog watchdog description.
 *
 * two watchdog types are found in stm32mp13 ADC:
 * - AWD1 has en_bits, and can select either a single or all channel(s)
 * - AWD2 & AWD3 are enabled by channel mask (in AWDxCR)
 * Remaining is similar
 */
static const struct stm32_adc_awd_reginfo stm32mp13_awd_reginfo[] = {
	{
		.awd_ch = {STM32MP13_ADC_CFGR, STM32MP13_AWD1CH,
			   STM32MP13_AWD1CH_SHIFT},
		.awd_en = {STM32MP13_ADC_CFGR, STM32MP13_AWD1EN},
		.awd_sgl = {STM32MP13_ADC_CFGR, STM32MP13_AWD1SGL},
		.awd_lt = {STM32MP13_ADC_TR1, STM32MP13_LT1},
		.awd_ht = {STM32MP13_ADC_TR1, STM32MP13_HT1,
			   STM32MP13_HT1_SHIFT},
	}, {
		.awd_ch = {STM32MP13_ADC_AWD2CR, STM32MP13_AWD2CH},
		/* Bit resoluion on 8 bits  */
		.awd_lt = {STM32MP13_ADC_TR2, STM32MP13_LT2,
			   STM32MP13_LT2_SHIFT},
		.awd_ht = {STM32MP13_ADC_TR2, STM32MP13_HT2,
			   STM32MP13_HT2_SHIFT - 4},
	}, {
		.awd_ch = {STM32MP13_ADC_AWD3CR, STM32MP13_AWD3CH},
		.awd_lt = {STM32MP13_ADC_TR3, STM32MP13_LT3,
			   STM32MP13_LT3_SHIFT},
		.awd_ht = {STM32MP13_ADC_TR3, STM32MP13_HT3,
			   STM32MP13_HT3_SHIFT - 4},
	},
};

static const struct stm32_adc_awd_reginfo stm32mp25_awd_reginfo[] = {
	{
		.awd_ch = {STM32MP13_ADC_CFGR, STM32MP13_AWD1CH, 0},
		.awd_en = {STM32MP13_ADC_CFGR, STM32MP13_AWD1EN},
		.awd_sgl = {STM32MP13_ADC_CFGR, STM32MP13_AWD1SGL},
		.awd_lt = {STM32MP25_ADC_AWD1LTR, STM32MP25_ADC_AWD1LTR_MASK,
			   0},
		.awd_ht = {STM32MP25_ADC_AWD1HTR, STM32MP25_ADC_AWD1HTR_MASK,
			   0},
	}, {
		.awd_ch = {STM32MP25_ADC_AWD2CR, STM32MP25_ADC_AWD2CH_MASK},
		.awd_lt = {STM32MP25_ADC_AWD2LTR, STM32MP25_ADC_AWD2LTR_MASK,
			   0},
		.awd_ht = {STM32MP25_ADC_AWD2HTR, STM32MP25_ADC_AWD2HTR_MASK,
			   0},
	}, {
		.awd_ch = {STM32MP25_ADC_AWD3CR, STM32MP25_ADC_AWD3CH_MASK},
		.awd_lt = {STM32MP25_ADC_AWD3LTR, STM32MP25_ADC_AWD3LTR_MASK,
			   0},
		.awd_ht = {STM32MP25_ADC_AWD3HTR, STM32MP25_ADC_AWD3HTR_MASK,
			   0},
	},
};

static const struct stm32_adc_regs stm32_sqr[STM32MP13_ADC_MAX_SQ + 1] = {
	/* L: len bit field description to be kept as first element */
	{ STM32MP13_ADC_SQR1, GENMASK_32(3, 0), 0 },
	/* SQ1..SQ16 registers & bit fields (reg, mask, shift) */
	{ STM32MP13_ADC_SQR1, GENMASK_32(10, 6), 6 },
	{ STM32MP13_ADC_SQR1, GENMASK_32(16, 12), 12 },
	{ STM32MP13_ADC_SQR1, GENMASK_32(22, 18), 18 },
	{ STM32MP13_ADC_SQR1, GENMASK_32(28, 24), 24 },
	{ STM32MP13_ADC_SQR2, GENMASK_32(4, 0), 0 },
	{ STM32MP13_ADC_SQR2, GENMASK_32(10, 6), 6 },
	{ STM32MP13_ADC_SQR2, GENMASK_32(16, 12), 12 },
	{ STM32MP13_ADC_SQR2, GENMASK_32(22, 18), 18 },
	{ STM32MP13_ADC_SQR2, GENMASK_32(28, 24), 24 },
	{ STM32MP13_ADC_SQR3, GENMASK_32(4, 0), 0 },
	{ STM32MP13_ADC_SQR3, GENMASK_32(10, 6), 6 },
	{ STM32MP13_ADC_SQR3, GENMASK_32(16, 12), 12 },
	{ STM32MP13_ADC_SQR3, GENMASK_32(22, 18), 18 },
	{ STM32MP13_ADC_SQR3, GENMASK_32(28, 24), 24 },
	{ STM32MP13_ADC_SQR4, GENMASK_32(4, 0), 0 },
	{ STM32MP13_ADC_SQR4, GENMASK_32(10, 6), 6 },
};

static const struct stm32_adc_regspec stm32mp13_regs = {
	.data_res = STM32MP13_RES,
	.or_vddcore = { STM32MP13_ADC2_OR, STM32MP13_OP0 },
	.or_vddcpu = { STM32MP13_ADC2_OR, STM32MP13_OP1 },
	.or_vddq_ddr = { STM32MP13_ADC2_OR, STM32MP13_OP2 },
	.ccr_vref = { STM32MP13_ADC_CCR, STM32MP13_VREFEN },
	.ccr_vbat = { STM32MP13_ADC_CCR, STM32MP13_VBATEN },
	.awd_reginfo = stm32mp13_awd_reginfo,
};

static const struct stm32_adc_regspec stm32mp25_regs = {
	.data_res = STM32MP25_RES,
	.or_vddcore = { STM32MP25_ADC_OR, STM32MP13_OP2 },
	.or_vddcpu = { STM32MP25_ADC_OR, STM32MP25_OP3 },
	.ccr_vref = { STM32MP13_ADC_CCR, STM32MP13_VREFEN },
	.ccr_vbat = { STM32MP13_ADC_CCR, STM32MP13_VBATEN },
	.or_vddgpu = { STM32MP25_ADC_OR, STM32MP25_OP4},
	.awd_reginfo = stm32mp25_awd_reginfo,
};

static TEE_Result stm32_adc_awd_enable(struct adc_device *adc_dev,
				       struct adc_evt *evt, uint32_t channel)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	const struct stm32_adc_awd_reginfo *awd_reginfo =
		adc->cfg->regs->awd_reginfo;
	unsigned int i = 0;
	uint32_t val = 0;

	if (!evt->id || evt->id > STM32MP13_ADC_AWD_NB) {
		EMSG("AWD index out of valid range [1..%u]", evt->id);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	i = evt->id - 1;

	/*
	 * Watchdog threshold comparison depends on ADC data format
	 * Supported data format:
	 *	resolution: 12 bits (other resolutions not supported)
	 *	alignment: indifferent (applied after comparison)
	 *	offset on:
	 *		- stm32mp13: indifferent (applied after comparison)
	 *		- stm32mp25: applied before comparison
	 */
	val = io_read32(adc->regs + STM32MP13_ADC_CFGR);
	if (val & adc->cfg->regs->data_res)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Set AWD thresholds and enable AWD */
	if (awd_reginfo[i].awd_en.reg) {
		/*
		 * AWD1:
		 * Enable AWD on a single channel. (scan mode not supported)
		 * Thresholds resolution: 12 bits
		 */
		if (!IS_POWER_OF_TWO(channel)) {
			EMSG("AWD1 allows Only single channel, no Channel %d",
			     channel);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		io_clrsetbits32(adc->regs + awd_reginfo[i].awd_lt.reg,
				awd_reginfo[i].awd_lt.msk, evt->lt);
		io_clrsetbits32(adc->regs + awd_reginfo[i].awd_ht.reg,
				awd_reginfo[i].awd_ht.msk,
				evt->ht
				<< awd_reginfo[i].awd_ht.shift);

		io_clrsetbits32(adc->regs + awd_reginfo[i].awd_ch.reg,
				awd_reginfo[i].awd_ch.msk,
				channel
				<< awd_reginfo[i].awd_ch.shift);
		/* Enable AWD on a single channel */
		io_setbits32(adc->regs + awd_reginfo[i].awd_sgl.reg,
			     awd_reginfo[i].awd_sgl.msk);
		/* Enable AWD */
		io_setbits32(adc->regs + awd_reginfo[i].awd_en.reg,
			     awd_reginfo[i].awd_en.msk);
	} else {
		/*
		 * AWD2/3:
		 * Enable AWD through channel mask. (Scan mode supported)
		 * Thresholds resolution on:
		 *	- stm32mp13: 8 bits (MSBs)
		 *	- stm32mp25: 12 bits (LSBs)
		 */
		io_clrsetbits32(adc->regs + awd_reginfo[i].awd_lt.reg,
				awd_reginfo[i].awd_lt.msk,
				evt->lt >> awd_reginfo[i].awd_lt.shift);
		io_clrsetbits32(adc->regs + awd_reginfo[i].awd_ht.reg,
				awd_reginfo[i].awd_ht.msk,
				evt->ht
				<< awd_reginfo[i].awd_ht.shift);

		/* Enable AWD for channel. Do not clear channels already set */
		io_setbits32(adc->regs + awd_reginfo[i].awd_ch.reg,
			     awd_reginfo[i].awd_ch.msk & BIT(channel));
	}

	DMSG("AWD%u config: lt=%#"PRIx32" ht=%#"PRIx32"\n",
	     evt->id, evt->lt, evt->ht);

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_awd_disable(struct adc_device *adc_dev,
					struct adc_evt *evt, uint32_t channel)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	const struct stm32_adc_awd_reginfo *awd_reginfo =
		adc->cfg->regs->awd_reginfo;
	unsigned int i = 0;

	if (!evt->id || evt->id > STM32MP13_ADC_AWD_NB) {
		EMSG("AWD index out of valid range [1..%u]", evt->id);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	i = evt->id - 1;

	if (awd_reginfo[i].awd_en.reg) {
		/* AWD1: Only one channel set. Disable AWD immediately */
		io_clrbits32(adc->regs + awd_reginfo[i].awd_en.reg,
			     awd_reginfo[i].awd_en.msk);
	} else {
		/*
		 * AWD2/3: Clear only the selected channel
		 * Disable AWD if all channels are cleared
		 */
		io_clrbits32(adc->regs + awd_reginfo[i].awd_ch.reg,
			     awd_reginfo[i].awd_ch.msk & BIT(channel));
	}

	return TEE_SUCCESS;
}

static int stm32_adc_conf_scan_seq(struct stm32_adc_data *adc,
				   uint32_t channel_mask)
{
	uint32_t val = 0;
	uint32_t chan_idx = 0, scan_idx = 0;

	io_setbits32(adc->regs + STM32MP13_ADC_SMPR1, adc->smpr[0]);
	io_setbits32(adc->regs + STM32MP13_ADC_SMPR2, adc->smpr[1]);

	do {
		if (channel_mask & 0x1) {
			scan_idx++;

			if (scan_idx > STM32MP13_ADC_MAX_SQ)
				return TEE_ERROR_GENERIC;

			DMSG("SQ%u set to channel %u\n", scan_idx, chan_idx);

			val = io_read32(adc->regs + stm32_sqr[scan_idx].reg);
			val &= ~stm32_sqr[scan_idx].msk;
			val |= chan_idx << stm32_sqr[scan_idx].shift;
			io_write32(adc->regs + stm32_sqr[scan_idx].reg, val);
		}
		channel_mask >>= 1;
	} while (chan_idx++ < adc->cfg->max_channels);

	/* Sequence len */
	val = io_read32(adc->regs + stm32_sqr[0].reg);
	val &= ~stm32_sqr[0].msk;
	val |= (scan_idx << stm32_sqr[0].shift);
	io_write32(adc->regs + stm32_sqr[0].reg, val);

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_start_conv(struct adc_device *adc_dev,
				       uint32_t channel_mask)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);

	stm32_adc_conf_scan_seq(adc, channel_mask);

	/*
	 * Trigger disabled. Conversion launched in sw. Continuous mode set
	 * overrun mode set. Data not read but always updated in data register
	 */
	io_clrsetbits32(adc->regs + STM32MP13_ADC_CFGR,
			STM32MP13_EXTEN | STM32MP13_DMAEN | STM32MP13_DMACFG,
			STM32MP13_OVRMOD | STM32MP13_CONT);

	/* Start conversion */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADSTART);

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_stop_conv(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0;

	/* Leave right now if already stopped */
	if (!(io_read32(adc->regs + STM32MP13_ADC_CR) & STM32MP13_ADSTART))
		return TEE_ERROR_BAD_STATE;

	/* Stop conversion */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADSTP);

	/* Wait conversion stop*/
	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
				   !(val & STM32MP13_ADSTART), 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("conversion stop timed out");
		return TEE_ERROR_BAD_STATE;
	}

	/* Disable continuous and overrun modes */
	io_clrbits32(adc->regs + STM32MP13_ADC_CFGR,
		     STM32MP13_CONT | STM32MP13_OVRMOD);

	/* Clear EOC and OVR bits by setting these bits in ISR register  */
	io_setbits32(adc->regs + STM32MP13_ADC_ISR,
		     STM32MP13_OVR | STM32MP13_EOC);

	return TEE_SUCCESS;
}
static void stm32_adc_int_ch_enable(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t i = 0;

	for (i = 0; i < STM32_ADC_INT_CH_NB; i++) {
		if (adc->int_ch[i] == STM32_ADC_INT_CH_NONE)
			continue;

		switch (i) {
		case STM32_ADC_INT_CH_VDDCORE:
			DMSG("Enable VDDCore");
			io_setbits32(adc->regs + adc->cfg->regs->or_vddcore.reg,
				     adc->cfg->regs->or_vddcore.msk);
			break;
		case STM32_ADC_INT_CH_VDDCPU:
			DMSG("Enable VDDCPU");
			io_setbits32(adc->regs + adc->cfg->regs->or_vddcpu.reg,
				     adc->cfg->regs->or_vddcpu.msk);
			break;
		case STM32_ADC_INT_CH_VDDQ_DDR:
			DMSG("Enable VDDQ_DDR");
			io_setbits32(adc->regs
				     + adc->cfg->regs->or_vddq_ddr.reg,
				     adc->cfg->regs->or_vddq_ddr.msk);
			break;
		case STM32_ADC_INT_CH_VREFINT:
			DMSG("Enable VREFInt");
			io_setbits32(adc->common->regs
				     + adc->cfg->regs->ccr_vref.reg,
				     adc->cfg->regs->ccr_vref.msk);
			break;
		case STM32_ADC_INT_CH_VBAT:
			DMSG("Enable VBAT");
			io_setbits32(adc->common->regs
				     + adc->cfg->regs->ccr_vbat.reg,
				     adc->cfg->regs->ccr_vbat.msk);
			break;
		case STM32_ADC_INT_CH_VDDGPU:
			DMSG("Enable VDDGPU");
			io_setbits32(adc->regs + adc->cfg->regs->or_vddgpu.reg,
				     adc->cfg->regs->or_vddgpu.msk);
			break;
		default:
			break;
		}
	}
}

static void stm32_adc_int_ch_disable(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t i = 0;

	for (i = 0; i < STM32_ADC_INT_CH_NB; i++) {
		if (adc->int_ch[i] == STM32_ADC_INT_CH_NONE)
			continue;

		switch (i) {
		case STM32_ADC_INT_CH_VDDCORE:
			io_clrbits32(adc->regs + adc->cfg->regs->or_vddcore.reg,
				     adc->cfg->regs->or_vddcore.msk);
			break;
		case STM32_ADC_INT_CH_VDDCPU:
			io_clrbits32(adc->regs + adc->cfg->regs->or_vddcpu.reg,
				     adc->cfg->regs->or_vddcpu.msk);
			break;
		case STM32_ADC_INT_CH_VDDQ_DDR:
			io_clrbits32(adc->regs
				     + adc->cfg->regs->or_vddq_ddr.reg,
				     adc->cfg->regs->or_vddq_ddr.msk);
			break;
		case STM32_ADC_INT_CH_VREFINT:
			io_clrbits32(adc->common->regs
				     + adc->cfg->regs->ccr_vref.reg,
				     adc->cfg->regs->ccr_vref.msk);
			break;
		case STM32_ADC_INT_CH_VBAT:
			io_clrbits32(adc->common->regs
				     + adc->cfg->regs->ccr_vbat.reg,
				     adc->cfg->regs->ccr_vbat.msk);
			break;
		case STM32_ADC_INT_CH_VDDGPU:
			io_clrbits32(adc->regs + adc->cfg->regs->or_vddgpu.reg,
				     adc->cfg->regs->or_vddgpu.msk);
			break;
		default:
			break;
		}
	}
}

static void stm32_adc_enter_pwr_down(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);

	/* Return immediately if ADC is already in deep power down mode */
	if (io_read32(adc->regs + STM32MP13_ADC_CR) & STM32MP13_DEEPPWD)
		return;

	/* Setting DEEPPWD disables ADC vreg and clears ADVREGEN */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_DEEPPWD);
}

static TEE_Result stm32_adc_exit_pwr_down(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);

	/* Return immediately if ADC is not in deep power down mode */
	if (!(io_read32(adc->regs + STM32MP13_ADC_CR) & STM32MP13_DEEPPWD))
		return TEE_SUCCESS;

	/* Exit deep power down, then enable ADC voltage regulator */
	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_DEEPPWD);
	if (adc->cfg->has_vregen)
		io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADVREGEN);

	/* Wait for ADC LDO startup time (tADCVREG_STUP in datasheet) */
	udelay(STM32_ADCVREG_STUP_DELAY_US);

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_disable(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0;

	/* Leave right now if already disabled */
	if (!(io_read32(adc->regs + STM32MP13_ADC_CR) & STM32MP13_ADEN))
		return TEE_SUCCESS;

	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADDIS);

	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
				   !(val & STM32MP13_ADEN), 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("Failed to disable ADC. Timeout elapsed");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_hw_stop(struct adc_device *adc_dev)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_adc_disable(adc_dev);
	if (res)
		return res;

	stm32_adc_int_ch_disable(adc_dev);

	stm32_adc_enter_pwr_down(adc_dev);

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_enable(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0;

	/* Clear ADRDY by writing one */
	io_setbits32(adc->regs + STM32MP13_ADC_ISR, STM32MP13_ADRDY);
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADEN);

	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_ISR, val,
				   val & STM32MP13_ADRDY, 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("Failed to enable ADC. Timeout elapsed");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_adc_selfcalib(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* ADC must be disabled for calibration */
	res = stm32_adc_disable(adc_dev);
	if (res)
		return res;

	/* Offset calibration for single ended inputs */
	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);

	/* Start calibration, then wait for completion */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCAL);

	/*
	 * Wait for offset calibration completion. This calibration takes
	 * 1280 ADC clock cycles, which corresponds to 50us at 24MHz.
	 */
	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
				   !(val & STM32MP13_ADCAL), 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("ADC offset calibration (se) failed. Timeout elapsed");
		return TEE_ERROR_BAD_STATE;
	}

	DMSG("Calibration factors single-ended %#"PRIx32,
	     io_read32(adc->regs + STM32MP13_ADC_CALFACT));

	/* Offset calibration for differential input */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);

	/* Start calibration, then wait for completion */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCAL);

	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
				   !(val & STM32MP13_ADCAL), 0,
				   STM32MP13_ADC_CALIB_TIMEOUT_US)) {
		EMSG("ADC offset calibration (diff) failed. Timeout elapsed");
		return TEE_ERROR_BAD_STATE;
	}

	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);

	DMSG("Calibration factors differential %#"PRIx32,
	     io_read32(adc->regs + STM32MP13_ADC_CALFACT));

	return TEE_SUCCESS;
}

static TEE_Result stm32mp25_adc_calfact_data(struct adc_device *adc_dev,
					     unsigned int *average_data)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0, val_sum = 0, i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < STM32MP25_CALIB_LOOP; i++) {
		io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADSTART);

		/*
		 * Wait for end of conversion by polling ADSTART bit until it
		 * is cleared. Also work if waiting for EOC to be set in
		 * STM32MP25_ADC_ISR.
		 */
		if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
					   !(val & STM32MP13_ADSTART), 0,
					   STM32_ADC_TIMEOUT_US)) {
			res = TEE_ERROR_TIME_NOT_SET;
			EMSG("Conversion failed: %d\n", res);
			return res;
		}

		val = io_read32(adc->regs + STM32MP13_ADC_DR);
		val_sum += val;
	}

	*average_data = UDIV_ROUND_NEAREST(val_sum, STM32MP25_CALIB_LOOP);
	DMSG("calibration average data = %#x", *average_data);

	return TEE_SUCCESS;
}

static TEE_Result stm32mp25_adc_calib(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t average_data = 0, calfact = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCAL);
	/* Clears CALADDOS (and old calibration data if any) */
	io_clrbits32(adc->regs + STM32MP25_ADC_CALFACT, UINT32_MAX);
	/* Select single ended input calibration */
	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);
	/* Use default resolution (e.g. 12 bits) */
	io_clrbits32(adc->regs + STM32MP13_ADC_CFGR, adc->cfg->regs->data_res);

retry:
	res = stm32mp25_adc_calfact_data(adc_dev, &average_data);
	if (res)
		goto out;

	/*
	 * If the averaged data is zero, retry with additional
	 * offset (set CALADDOS)
	 */
	if (!average_data) {
		if (!calfact) {
			/*
			 * Averaged data is zero, retry with
			 * additional offset
			 */
			calfact = STM32MP25_CALADDOS;
			io_setbits32(adc->regs + STM32MP25_ADC_CALFACT,
				     STM32MP25_CALADDOS);
			goto retry;
		}
		/*
		 * Averaged data is still zero with additional offset,
		 * just warn about it
		 */
		IMSG("Single-ended calibration average: 0\n");
	}

	calfact |= average_data & STM32MP25_CALFACT_S;

	/*
	 * Select differential input calibration
	 * (keep previous CALADDOS value)
	 */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);

	res = stm32mp25_adc_calfact_data(adc_dev, &average_data);
	if (res)
		goto out;

	/*
	 * If the averaged data is below 0x800 (half value in 12-bits mode),
	 * retry with additional offset
	 */
	if (average_data < 0x800U) {
		if (!(calfact & STM32MP25_CALADDOS)) {
			/* Retry the calibration with additional offset */
			io_clrbits32(adc->regs + STM32MP13_ADC_CR,
				     STM32MP13_ADCALDIF);
			calfact = STM32MP25_CALADDOS;
			io_clrsetbits32(adc->regs + STM32MP25_ADC_CALFACT,
					UINT32_MAX, calfact);
			goto retry;
		}
		/*
		 * Averaged data is still below center value.
		 * It needs to be clamped to zero, so don't use the result
		 * here, warn about it.
		 */
		IMSG("Differential calibration clamped(0): %#x\n",
		     average_data);
	} else {
		calfact |= (average_data << STM32MP25_CALFACT_D_SHIFT)
			    & STM32MP25_CALFACT_D;
	}

	io_clrsetbits32(adc->regs + STM32MP25_ADC_CALFACT, UINT32_MAX,
			calfact);

	DMSG("Set calfact_s=%#x, calfact_d=%#x, calados=%#x\n",
	     STM32MP25_CALFACT_S & calfact,
	     STM32MP25_CALFACT_D & calfact,
	     STM32MP25_CALADDOS & calfact);

out:
	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCALDIF);
	io_clrbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADCAL);

	return res;
}

static TEE_Result stm32mp13_adc_hw_start(struct adc_device *adc_dev)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_adc_exit_pwr_down(adc_dev);
	if (res)
		return res;

	res = stm32_adc_selfcalib(adc_dev);
	if (res)
		goto err_pwr;

	stm32_adc_int_ch_enable(adc_dev);

	res = stm32_adc_enable(adc_dev);
	if (res)
		goto err_ena;

	return TEE_SUCCESS;

err_ena:
	stm32_adc_int_ch_disable(adc_dev);

err_pwr:
	stm32_adc_enter_pwr_down(adc_dev);

	return res;
}

static TEE_Result stm32mp25_adc_hw_start(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_adc_exit_pwr_down(adc_dev);
	if (res)
		return res;

	res = stm32_adc_enable(adc_dev);
	if (res)
		goto err_ena;

	res = stm32mp25_adc_calib(adc_dev);
	if (res)
		goto err_cal;

	stm32_adc_int_ch_enable(adc_dev);

	/* Only use single ended channels */
	io_clrbits32(adc->regs + STM32MP25_ADC_DIFSEL, STM32MP25_DIFSEL_MASK);

	return res;

err_cal:
	stm32_adc_disable(adc_dev);

err_ena:
	stm32_adc_enter_pwr_down(adc_dev);

	return res;
}

static TEE_Result stm32_adc_read_channel(struct adc_device *adc_dev,
					 uint32_t channel, uint32_t *data)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	uint32_t val = 0;

	/* Set sampling time to max value by default */
	io_setbits32(adc->regs + STM32MP13_ADC_SMPR1, adc->smpr[0]);
	io_setbits32(adc->regs + STM32MP13_ADC_SMPR2, adc->smpr[1]);

	/* Program regular sequence: chan in SQ1 & len = 0 for one channel */
	io_clrsetbits32(adc->regs + STM32MP13_ADC_SQR1, UINT32_MAX,
			channel << STM32MP13_SQ1_SHIFT);

	/* Trigger detection disabled (conversion can be launched in SW) */
	io_clrbits32(adc->regs + STM32MP13_ADC_CFGR, STM32MP13_EXTEN
				 | STM32MP13_DMAEN | STM32MP13_DMACFG);

	/* Start conversion */
	io_setbits32(adc->regs + STM32MP13_ADC_CR, STM32MP13_ADSTART);

	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_ISR, val,
				   val & STM32MP13_EOC, 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("conversion timed out");
		return TEE_ERROR_BAD_STATE;
	}

	*data = io_read32(adc->regs + STM32MP13_ADC_DR);

	/* Stop conversion */
	if (IO_READ32_POLL_TIMEOUT(adc->regs + STM32MP13_ADC_CR, val,
				   !(val & STM32MP13_ADSTART), 0,
				   STM32_ADC_TIMEOUT_US)) {
		EMSG("conversion stop timed out");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void stm32_adc_smpr_init(struct adc_device *dev,
				int channel, uint32_t smp_ns)
{
	const struct stm32_adc_regs *smpr = &stm32_adc_smp_bits[channel];
	struct stm32_adc_data *adc = adc_get_drv_data(dev);
	unsigned int r = smpr->reg;
	unsigned int period_ns = 0;
	unsigned int i = 0;
	unsigned int smp = 0;

	/*
	 * For internal channels, ensure that the sampling time cannot
	 * be lower than the one specified in the datasheet
	 */
	for (i = 0; i < STM32_ADC_INT_CH_NB; i++)
		if (channel == adc->int_ch[i] &&
		    adc->int_ch[i] != STM32_ADC_INT_CH_NONE)
			smp_ns = MAX(smp_ns, adc->cfg->min_ts[i]);

	/* Determine sampling time (ADC clock cycles) */
	period_ns = STM32_ADC_NSEC_PER_SEC / adc->common->rate;
	for (smp = 0; smp <= STM32_ADC_MAX_SMP; smp++)
		if ((period_ns * adc->cfg->smp_cycles[smp]) >= smp_ns)
			break;
	if (smp > STM32_ADC_MAX_SMP)
		smp = STM32_ADC_MAX_SMP;

	/* Pre-build sampling time registers (e.g. smpr1, smpr2) */
	adc->smpr[r] = (adc->smpr[r] & ~smpr->msk) | (smp << smpr->shift);
}

static TEE_Result stm32_adc_fdt_chan_init(struct adc_device *adc_dev,
					  const void *fdt, int node)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);
	TEE_Result res = TEE_ERROR_GENERIC;
	const char *name = NULL;
	uint32_t ch_nb = 0;
	int subnode = 0;
	uint32_t ch_id = 0;
	int rc = 0;
	uint32_t i = 0;
	uint32_t smp_ns = 0;
	uint32_t smp_def = UINT32_MAX;
	int len = 0;

	adc_dev->channel_mask = 0;
	for (i = 0; i < STM32_ADC_INT_CH_NB; i++)
		adc->int_ch[i] = STM32_ADC_INT_CH_NONE;

	/*
	 * Parse ADC channels. In the generic IO channels dt-bindings,
	 * each channel is described through a sub-node, where reg property
	 * corresponds to the channel index, and label to the channel name.
	 */
	fdt_for_each_subnode(subnode, fdt, node)
		ch_nb++;

	if (!ch_nb) {
		EMSG("No channel found");
		return TEE_ERROR_NO_DATA;
	}

	if (ch_nb > adc->cfg->max_channels) {
		EMSG("too many channels: %"PRIu32, ch_nb);
		return TEE_ERROR_EXCESS_DATA;
	}

	adc_dev->channels = calloc(ch_nb, sizeof(*adc_dev->channels));
	if (!adc_dev->channels)
		return TEE_ERROR_OUT_OF_MEMORY;

	adc_dev->channels_nb = ch_nb;
	adc_dev->data_mask = GENMASK_32(STM32MP13_ADC_MAX_RES - 1, 0);

	ch_nb = 0;
	fdt_for_each_subnode(subnode, fdt, node) {
		rc = fdt_read_uint32(fdt, subnode, "reg", &ch_id);
		if (rc < 0) {
			EMSG("Invalid or missing reg property: %d", rc);
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		if (ch_id >= adc->cfg->max_channels) {
			EMSG("Invalid channel index: %"PRIu32, ch_id);
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		/* 'label' property is optional */
		name = fdt_getprop(fdt, subnode, "label", &len);
		if (name) {
			for (i = 0; i < STM32_ADC_INT_CH_NB; i++) {
				/* Populate internal channels */
				if (!strncmp(stm32_adc_ic[i].name,
					     name, STM32_ADC_CH_NAME_SZ)) {
					adc->int_ch[i] = ch_id;
					smp_def = 0;
				}
			}
		}

		/*
		 * 'st,min-sample-time-ns is optional.
		 * If property is not defined, sampling time set is as follows:
		 * - Internal channels: default value from stm32mp13_adc_min_ts
		 * - Other channels: set to max by default
		 */
		smp_ns = fdt_read_uint32_default(fdt, subnode,
						 "st,min-sample-time-ns",
						 smp_def);

		stm32_adc_smpr_init(adc_dev, ch_id, smp_ns);

		adc_dev->channel_mask |= BIT(ch_id);

		adc_dev->channels[ch_nb].id = ch_id;
		if (name) {
			adc_dev->channels[ch_nb].name = strdup(name);
			if (!adc_dev->channels[ch_nb].name) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto err;
			}
		}

		ch_nb++;
	}

	DMSG("%"PRIu32" channels found: Mask %#"PRIx32,
	     (uint32_t)adc_dev->channels_nb, adc_dev->channel_mask);

	return TEE_SUCCESS;

err:
	for (i = 0; i < adc_dev->channels_nb; i++)
		free(adc_dev->channels[i].name);

	free(adc_dev->channels);
	adc_dev->channels = NULL;
	adc_dev->channels_nb = 0;
	return res;
}

static TEE_Result stm32_adc_pm_resume(struct adc_device *adc_dev)
{
	struct stm32_adc_data *adc = adc_get_drv_data(adc_dev);

	return adc->cfg->hw_start(adc_dev);
}

static TEE_Result stm32_adc_pm_suspend(struct adc_device *adc_dev)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * If there are on-going conversions, return an error.
	 * Else the ADC can be stopped safely.
	 * No need to protect status check against race conditions here,
	 * as we are no more in a multi-threading context.
	 */
	if (adc_dev->state)
		return TEE_ERROR_BUSY;

	res = stm32_adc_hw_stop(adc_dev);

	return res;
}

static TEE_Result
stm32_adc_pm(enum pm_op op, unsigned int pm_hint __unused,
	     const struct pm_callback_handle *pm_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct adc_device *dev =
		(struct adc_device *)PM_CALLBACK_GET_HANDLE(pm_handle);

	if (op == PM_OP_RESUME)
		res = stm32_adc_pm_resume(dev);
	else
		res = stm32_adc_pm_suspend(dev);

	return res;
}

static TEE_Result
stm32_adc_register_cons(struct dt_pargs *pargs __unused, void *data,
			struct adc_consumer **adc_cons)
{
	struct stm32_adc_data *adc = data;
	struct adc_device *adc_dev = adc->dev;
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t channel = 0;
	uint32_t mask = 0;

	if (!pargs)
		return res;

	if (!pargs->args_count)
		return res;

	channel = pargs->args[0];
	mask = BIT(channel);

	if (!(adc_dev->channel_mask & mask)) {
		EMSG("Channel %"PRIu32" not available", channel);
		return res;
	}

	return adc_consumer_register(adc_dev, channel, adc_cons);
}

static struct adc_ops stm32_adc_ops = {
	.read_channel = stm32_adc_read_channel,
	.set_event = stm32_adc_awd_enable,
	.clr_event = stm32_adc_awd_disable,
	.start_conv = stm32_adc_start_conv,
	.stop_conv = stm32_adc_stop_conv,
};

static TEE_Result stm32_adc_probe(const void *fdt, int node,
				  const void *compat_data)
{
	struct dt_node_info dt_info = { };
	struct adc_device *adc_dev = NULL;
	struct stm32_adc_data *adc = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	const char *name = NULL;
	const char *pname = NULL;
	char *p = NULL;
	int pnode = 0;

	adc_dev = calloc(1, sizeof(*adc_dev));
	if (!adc_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	adc = calloc(1, sizeof(*adc));
	if (!adc) {
		free(adc_dev);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	adc_set_drv_data(adc_dev, adc);

	fdt_fill_device_info(fdt, &dt_info, node);

	if (dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		goto err;

	pnode = fdt_parent_offset(fdt, node);
	assert(pnode >= 0);

	res = dt_driver_device_from_parent(fdt, node, DT_DRIVER_NOTYPE,
					   &adc->common);
	if (res)
		goto err;

	adc->regs = adc->common->regs + dt_info.reg;
	adc->dev = adc_dev;
	adc->cfg = compat_data;
	adc_dev->vref_uv = adc->common->vref_uv;

	name = fdt_get_name(fdt, node, NULL);
	pname = fdt_get_name(fdt, pnode, NULL);
	adc_dev->name = calloc(1, sizeof(adc_dev->name) *
			       (strlen(name) + strlen(pname) + 2));
	if (!adc_dev->name) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	p = adc_dev->name;
	memcpy(p, pname, strlen(pname));
	memcpy(p + strlen(pname), ":", 1);
	memcpy(p + strlen(pname) + 1, name, strlen(name) + 1);

	res = stm32_adc_fdt_chan_init(adc_dev, fdt, node);
	if (res)
		goto err_name;

	adc_register(adc_dev, &stm32_adc_ops);

	res = adc->cfg->hw_start(adc_dev);
	if (res)
		goto err_start;

	res = dt_driver_register_provider(fdt, node,
					  (get_of_device_func)
					  stm32_adc_register_cons,
					  (void *)adc, DT_DRIVER_ADC);
	if (res) {
		EMSG("Couldn't register ADC IO channels");
		if (stm32_adc_hw_stop(adc_dev))
			panic();
		goto err_start;
	}

	register_pm_core_service_cb(stm32_adc_pm, adc_dev, "stm32-adc");
	DMSG("adc %s probed", fdt_get_name(fdt, node, NULL));

	return TEE_SUCCESS;

err_start:
	adc_unregister(adc_dev);

err_name:
	free(adc_dev->name);

err:
	free(adc_dev);
	free(adc);

	return res;
}

static const struct stm32_adc_cfg stm32mp13_adc_cfg = {
	.max_channels = STM32MP13_ADC_CH_MAX,
	.hw_start = stm32mp13_adc_hw_start,
	.has_vregen = true,
	.min_ts = stm32mp13_adc_min_ts,
	.smp_cycles = stm32mp13_adc_smp_cycles,
	.regs = &stm32mp13_regs,
};

static const struct stm32_adc_cfg stm32mp21_adc_cfg = {
	.max_channels = STM32MP25_ADC_CH_MAX,
	.hw_start = stm32mp25_adc_hw_start,
	.min_ts = stm32mp21_adc_min_ts,
	.smp_cycles = stm32mp25_adc_smp_cycles,
	.regs = &stm32mp25_regs,
};

static const struct stm32_adc_cfg stm32mp25_adc_cfg = {
	.max_channels = STM32MP25_ADC_CH_MAX,
	.hw_start = stm32mp25_adc_hw_start,
	.min_ts = stm32mp25_adc_min_ts,
	.smp_cycles = stm32mp25_adc_smp_cycles,
	.regs = &stm32mp25_regs,
};

static const struct dt_device_match stm32_adc_match_table[] = {
	{ .compatible = "st,stm32mp13-adc", .compat_data = &stm32mp13_adc_cfg },
	{ .compatible = "st,stm32mp21-adc", .compat_data = &stm32mp21_adc_cfg },
	{ .compatible = "st,stm32mp23-adc", .compat_data = &stm32mp25_adc_cfg },
	{ .compatible = "st,stm32mp25-adc", .compat_data = &stm32mp25_adc_cfg },
	{ }
};

DEFINE_DT_DRIVER(stm32_adc_dt_driver) = {
	.name = "stm32-adc",
	.match_table = stm32_adc_match_table,
	.probe = stm32_adc_probe,
};
