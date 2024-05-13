// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics International N.V.
 */

#include <drivers/mailbox.h>
#include <drivers/scmi-msg.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/notif.h>
#include <libfdt.h>
#include <tee/cache.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <scmi_agent_configuration.h>

struct scmi_cortexm_agent {
	const char *dt_name;
	struct shared_mem shm;
	struct mbox_chan *chan;
	struct notif_driver mailbox_notif;
	unsigned int agent_id;
	unsigned int channel_id;
	bool event_waiting;
	TEE_Result (*process)(unsigned int chan_id);
	unsigned int process_arg;
};

static void yielding_mailbox_notif(struct notif_driver *ndrv,
				   enum notif_event ev)
{
	struct scmi_cortexm_agent *ctx = container_of(ndrv,
		struct scmi_cortexm_agent, mailbox_notif);

	if (ev == NOTIF_EVENT_DO_BOTTOM_HALF && ctx->event_waiting) {
		ctx->event_waiting = false;

		/* Ack notification */
		if (mbox_recv(ctx->chan, false, NULL, 0))
			panic();

		/* Let SCP handle the message and the answer */
		if (ctx->process(ctx->process_arg)) {
			/*
			 * It should force the SMT_CHANNEL_STATUS_ERROR in the
			 * mailbox header channel_status_field and notify the
			 * Cortex-M the response sent.
			 * For now just panic().
			 */
			panic();
		}

		/* Notify requester that an answer is ready */
		if (mbox_send(ctx->chan, false, NULL, 0))
			panic();
	}
}

static void mailbox_rcv_callback(void *cookie)
{
	struct scmi_cortexm_agent *ctx = cookie;

	if (notif_async_is_started()) {
		ctx->event_waiting = true;
		notif_send_async(NOTIF_VALUE_DO_BOTTOM_HALF);
	} else {
		panic("no bottom half");
	};
}

static TEE_Result scmi_cortexm_agent_shm_map(struct shared_mem *shm)
{
	int ipc_node = 0;
	void *fdt = NULL;

	fdt = get_embedded_dt();
	assert(fdt);

	ipc_node = fdt_path_offset(fdt, "/reserved-memory/ipc-shmem");
	shm->size = fdt_reg_size(fdt, ipc_node);
	shm->pa = fdt_reg_base_address(fdt, ipc_node);

	if (ipc_node < 0 ||
	    shm->pa == DT_INFO_INVALID_REG ||
	    shm->size == DT_INFO_INVALID_REG_SIZE) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	shm->va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_NSEC,
						shm->pa, shm->size);

	if (!shm->va)
		return TEE_ERROR_BAD_PARAMETERS;

	return cache_operation(TEE_CACHEINVALIDATE,
			       (void *)shm->va,
			       shm->size);
}

static TEE_Result scmi_cortexm_agent_probe(const void *fdt, int node,
					   const void *compat_data __unused)
{
	struct scmi_cortexm_agent *ctx = NULL;
	TEE_Result res = TEE_SUCCESS;
	const fdt32_t *cuint = NULL;

	ctx = calloc(1, sizeof(*ctx));
	ctx->dt_name = fdt_get_name(fdt, node, NULL);

	cuint = fdt_getprop(fdt, node, "scmi-agent-id", NULL);
	if (!cuint) {
		EMSG("%s Missing property scmi-agent-id", ctx->dt_name);
		panic();
	}
	ctx->agent_id = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "scmi-channel-id", NULL);
	if (!cuint) {
		EMSG("%s Missing property scmi-channel-id", ctx->dt_name);
		panic();
	}
	ctx->channel_id = fdt32_to_cpu(*cuint);

	res = scmi_cortexm_agent_shm_map(&ctx->shm);
	if (res) {
		EMSG("%s Failed to map shared memory.", ctx->dt_name);
		free(ctx);
		return res;
	}

	res = scmi_scpfw_attach_notif(ctx->agent_id, ctx->channel_id, &ctx->shm,
				      &ctx->process, &ctx->process_arg);

	if (res) {
		EMSG("%s Failed to bind driver with scmi agent %d",
		     ctx->dt_name, ctx->agent_id);
		free(ctx);
		return res;
	}

	ctx->event_waiting = false;

	res = mbox_dt_register_chan(mailbox_rcv_callback, NULL, ctx, fdt, node,
				    &ctx->chan);
	if (res) {
		if (res != TEE_ERROR_DEFER_DRIVER_INIT)
			EMSG("%s Failed to register mailbox channel",
			     ctx->dt_name);
		free(ctx);
		return res;
	}

	ctx->mailbox_notif.yielding_cb = yielding_mailbox_notif;
	notif_register_driver(&ctx->mailbox_notif);

	return TEE_SUCCESS;
}

#if CFG_EMBED_DTB
static const struct dt_device_match scmi_cortexm_agent_table[] = {
	{ .compatible = "st,scmi-cortexm-agent" },
	{ }
};

DEFINE_DT_DRIVER(scmi_cortexm_agent) = {
	.name = "scmi-cortexm-agent",
	.match_table = scmi_cortexm_agent_table,
	.probe = &scmi_cortexm_agent_probe,
};
#endif
