/*
 * Arm SCP/MCP Software
 * Copyright (c) 2022-2023, Linaro Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_arch.h>
#include <fwk_core.h>
#include <fwk_id.h>
#include <fwk_log.h>
#include <fwk_noreturn.h>
#include <fwk_status.h>
#include <internal/fwk_context.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include <mod_optee_mbx.h>

#include <arch_interrupt.h>
#include <arch_main.h>

#include <kernel/mutex.h>

static struct mutex process_lock = MUTEX_INITIALIZER;

static const struct fwk_arch_init_driver scmi_init_driver = {
    .interrupt = arch_interrupt_init,
};

int scmi_arch_init(void)
{
    int status;

    status = fwk_arch_init(&scmi_init_driver);

    fwk_log_flush();

    return status;
}

int scmi_arch_deinit(void)
{
    return fwk_arch_deinit();
}

int scmi_get_devices_count(void)
{
    return optee_mbx_get_devices_count();
}

int scmi_get_device(unsigned int id)
{
    fwk_id_t device_id;

    device_id = optee_mbx_get_device(id);

    if (fwk_id_is_type(device_id, FWK_ID_TYPE_NONE)) {
        return -1;
    }

    return (int)device_id.value;
}

void scmi_process_mbx_smt(unsigned int fwk_id)
{
#ifdef BUILD_HAS_MOD_OPTEE_SMT
    fwk_id_t device_id;

    device_id.value = fwk_id;

    mutex_lock(&process_lock);

    optee_mbx_signal_smt_message(device_id);

    fwk_process_event_queue();

    fwk_log_flush();

    mutex_unlock(&process_lock);
#endif
}

void scmi_process_mbx_msg(unsigned int fwk_id, void *in_buf, size_t in_size,
                          void *out_buf, size_t *out_size)
{
#ifdef BUILD_HAS_MOD_MSG_SMT
    fwk_id_t device_id;

    device_id.value = fwk_id;

    mutex_lock(&process_lock);

    optee_mbx_signal_msg_message(device_id, in_buf, in_size, out_buf, out_size);

    fwk_process_event_queue();

    fwk_log_flush();

    mutex_unlock(&process_lock);
#endif
}

int scmi_tee_result_to_fwk_status(TEE_Result tee_error_code)
{
    switch (tee_error_code) {
    case TEE_SUCCESS:
        return FWK_SUCCESS;
    case TEE_ERROR_BAD_PARAMETERS:
        return FWK_E_PARAM;
    case TEE_ERROR_SHORT_BUFFER:
    case TEE_ERROR_EXCESS_DATA:
        return FWK_E_SIZE;
    case TEE_ERROR_ACCESS_CONFLICT:
    case TEE_ERROR_ACCESS_DENIED:
        return FWK_E_ACCESS;
    case TEE_ERROR_TIMEOUT:
        return FWK_E_TIMEOUT;
    case TEE_ERROR_OUT_OF_MEMORY:
        return FWK_E_NOMEM;
    case TEE_ERROR_UNSUPPORTED_VERSION:
    case TEE_ERROR_NOT_IMPLEMENTED:
    case TEE_ERROR_NOT_SUPPORTED:
        return FWK_E_SUPPORT;
    case TEE_ERROR_BUSY:
        return FWK_E_BUSY;
    case TEE_ERROR_BAD_STATE:
        return FWK_E_STATE;
    default:
        return FWK_E_DEVICE;
    }
}
