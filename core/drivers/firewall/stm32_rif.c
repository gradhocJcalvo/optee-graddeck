// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, STMicroelectronics
 */

#include <drivers/stm32_rif.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <kernel/panic.h>
#include <util.h>

TEE_Result stm32_rif_check_access(uint32_t cidcfgr,
				  uint32_t semcr,
				  unsigned int nb_cid_supp,
				  unsigned int cid_to_check)
{
	uint32_t scid_mask = 0;
	uint32_t msb_nb_cid_supp = sizeof(nb_cid_supp) * 8 -
				   __builtin_clz(nb_cid_supp | 1) - 1;

	/*
	 * SCID bitfield highend can't be > _CIDCFGR_SCID_SHIFT +
	 * MAX_CID_BITFIELD
	 */
	assert(msb_nb_cid_supp < MAX_CID_BITFIELD);

	scid_mask = GENMASK_32(_CIDCFGR_SCID_SHIFT + msb_nb_cid_supp,
			       _CIDCFGR_SCID_SHIFT);

	if (!(cidcfgr & _CIDCFGR_CFEN))
		return TEE_SUCCESS;

	if (SCID_OK(cidcfgr, scid_mask, cid_to_check))
		return TEE_SUCCESS;

	if (SEM_EN_AND_OK(cidcfgr, cid_to_check)) {
		if (!(semcr & _SEMCR_MUTEX) ||
		    ((semcr & scid_mask) >> _CIDCFGR_SCID_SHIFT) ==
		    cid_to_check) {
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

void stm32_rif_parse_cfg(uint32_t rif_conf,
			 struct rif_conf_data *conf_data,
			 unsigned int nb_cid_supp,
			 unsigned int nb_resource)
{
	uint32_t resource_id = 0;
	unsigned int conf_index = 0;

	if (nb_cid_supp > MAX_CID_SUPPORTED)
		panic();

	/* Shift corresponding to the desired resources */
	resource_id = rif_conf & RIF_PER_ID_MASK;
	if (resource_id >= nb_resource)
		panic("Bad RIF controllers number");

	/*
	 * Make sure we set the bits in the right sec and priv conf register.
	 * This is done to support IPS having more than 32 channels.
	 */
	conf_index = resource_id / 32;

	/* Privilege configuration */
	if (rif_conf & BIT(RIF_PRIV_SHIFT))
		conf_data->priv_conf[conf_index] |= BIT(resource_id);

	/* Security RIF configuration */
	if (rif_conf & BIT(RIF_SEC_SHIFT))
		conf_data->sec_conf[conf_index] |= BIT(resource_id);

	/* RIF configuration lock */
	if (rif_conf & BIT(RIF_LOCK_SHIFT) && conf_data->lock_conf)
		conf_data->lock_conf[conf_index] |= BIT(resource_id);

	/* CID configuration */
	conf_data->cid_confs[resource_id] = (rif_conf & RIF_PERx_CID_MASK) >>
					     RIF_PERx_CID_SHIFT;

	/* This resource will be configured */
	conf_data->access_mask[conf_index] |= BIT(resource_id);
}

bool stm32_rif_is_semaphore_available(vaddr_t addr)
{
	return !(io_read32(addr) & _SEMCR_MUTEX);
}

TEE_Result stm32_rif_acquire_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp)
{
	uint32_t msb_nb_cid_supp = sizeof(nb_cid_supp) * 8 -
				   __builtin_clz(nb_cid_supp | 1) - 1;
	uint32_t scid_mask = 0;

	/*
	 * SCID bitfield highend can't be > _CIDCFGR_SCID_SHIFT +
	 * MAX_CID_BITFIELD
	 */
	assert(msb_nb_cid_supp < MAX_CID_BITFIELD);

	scid_mask = GENMASK_32(_CIDCFGR_SCID_SHIFT + msb_nb_cid_supp,
			       _CIDCFGR_SCID_SHIFT);

	io_setbits32(addr, _SEMCR_MUTEX);

	/* Check that cortex A has the semaphore */
	if (stm32_rif_is_semaphore_available(addr) ||
	    ((io_read32(addr) & scid_mask) >> _CIDCFGR_SCID_SHIFT) != RIF_CID1)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

TEE_Result stm32_rif_release_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp)
{
	unsigned int msb_nb_cid_supp = sizeof(nb_cid_supp) * 8 -
				       __builtin_clz(nb_cid_supp | 1) - 1;
	uint32_t scid_mask = 0;

	/*
	 * SCID bitfield highend can't be > _CIDCFGR_SCID_SHIFT +
	 * MAX_CID_BITFIELD
	 */
	assert(msb_nb_cid_supp <= MAX_CID_BITFIELD);

	if (stm32_rif_is_semaphore_available(addr))
		return TEE_SUCCESS;

	scid_mask = GENMASK_32(_CIDCFGR_SCID_SHIFT + msb_nb_cid_supp,
			       _CIDCFGR_SCID_SHIFT);

	io_clrbits32(addr, _SEMCR_MUTEX);

	/* Ok if another compartment takes the semaphore before the check */
	if (!stm32_rif_is_semaphore_available(addr) &&
	    ((io_read32(addr) & scid_mask) >> _CIDCFGR_SCID_SHIFT) == RIF_CID1)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}
