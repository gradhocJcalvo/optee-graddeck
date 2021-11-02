/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __DRIVERS_GIC_H
#define __DRIVERS_GIC_H
#include <types_ext.h>
#include <kernel/interrupt.h>

/* Constants to categorize priorities */
#define GIC_HIGHEST_SEC_PRIORITY	0x0U
#define GIC_LOWEST_SEC_PRIORITY		0x7fU
#define GIC_HIGHEST_NS_PRIORITY		0x80U
#define GIC_LOWEST_NS_PRIORITY		0xfeU
/* 0xff would disable all interrupts */

#if defined(CFG_ARM_GICV3)
#define GIC_DIST_REG_SIZE	0x10000
#define GIC_CPU_REG_SIZE	0x10000
#else
#define GIC_DIST_REG_SIZE	0x1000
#define GIC_CPU_REG_SIZE	0x1000
#endif

#define GIC_PPI_BASE		U(16)
#define GIC_SPI_BASE		U(32)

#define GIC_SGI_TO_ITNUM(x)	(x)
#define GIC_PPI_TO_ITNUM(x)	((x) + GIC_PPI_BASE)
#define GIC_SPI_TO_ITNUM(x)	((x) + GIC_SPI_BASE)

/*
 * The two gic_init_* functions initializes the struct gic_data which is
 * then used by the other functions.
 */

/* Initialize GIC */
void gic_init(paddr_t gicc_base_pa, paddr_t gicd_base_pa);

/* Only initialize CPU GIC interface, mainly use for secondary CPUs */
void gic_cpu_init(void);

/* Print GIC state to console */
void gic_dump_state(void);

/* Set the Priority Mask Regarding and return its previous value */
uint8_t gic_set_pmr(uint8_t mask);

/* Set the targe tinterrupt priority mask and return its previous value */
uint8_t gic_set_ipriority(size_t it, uint8_t mask);
#endif /*__DRIVERS_GIC_H*/
