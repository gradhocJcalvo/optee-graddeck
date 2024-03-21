/*
 * Copyright (c) 2024, STMicroelectronics and the Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mod_power_domain.h>
#include <mod_stm32_pd.h>
#include <scmi_agent_configuration.h>
#include <drivers/stm32mp_dt_bindings.h>

#include <fwk_id.h>
#include <fwk_log.h>
#include <fwk_mm.h>
#include <fwk_module.h>

struct mod_stm32_pd {
    const struct mod_stm32_pd_config *config;
    unsigned int current_state;
};

static struct mod_stm32_pd *mod_stm32_pd_ctx;

static int stm32_pd_get_state(fwk_id_t pd_id, unsigned int *state)
{
    struct mod_stm32_pd *ctx = mod_stm32_pd_ctx + fwk_id_get_element_idx(pd_id);

    *state = ctx->current_state;
    return FWK_SUCCESS;
}

static int stm32_pd_set_state(fwk_id_t pd_id, unsigned int state)
{
    struct mod_stm32_pd *ctx = mod_stm32_pd_ctx + fwk_id_get_element_idx(pd_id);

    ctx->current_state = state;
    return FWK_SUCCESS;
}

static int stm32_pd_reset(fwk_id_t pd_id)
{
    FWK_LOG_DEBUG("Power domain %s reset not supported",
                  fwk_module_get_element_name(pd_id));
    return FWK_E_SUPPORT;
}

static int stm32_pd_bind(fwk_id_t id, unsigned int round)
{
    return FWK_SUCCESS;
}

static int stm32_pd_element_init(fwk_id_t element_id,
                                 unsigned int unused,
                                 const void *data)
{
    struct mod_stm32_pd *ctx =
                        mod_stm32_pd_ctx + fwk_id_get_element_idx(element_id);

    ctx->config = (const struct mod_stm32_pd_config *)data;

    ctx->current_state = MOD_PD_STATE_ON;
    return FWK_SUCCESS;
}

static const struct mod_pd_driver_api stm32_pd_api = {
    .set_state = stm32_pd_set_state,
    .get_state = stm32_pd_get_state,
    .reset = stm32_pd_reset,
};

static int stm32_pd_process_bind_request(fwk_id_t requester_id,
                                         fwk_id_t target_id,
                                         fwk_id_t api_type,
                                         const void **api)
{
    *api = &stm32_pd_api;
    return FWK_SUCCESS;
}

static int stm32_pd_init(fwk_id_t module_id,
    unsigned int element_count, const void *data)
{
    mod_stm32_pd_ctx = fwk_mm_calloc(element_count, sizeof(*mod_stm32_pd_ctx));

    return FWK_SUCCESS;
}

const struct fwk_module module_stm32_pd = {
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .init = stm32_pd_init,
    .element_init = stm32_pd_element_init,
    .bind = stm32_pd_bind,
    .process_bind_request = stm32_pd_process_bind_request,
};