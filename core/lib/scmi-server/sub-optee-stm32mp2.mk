scpfw-incdirs-y += $(scpfw-path)/product/optee-stm32mp2/include

srcs-y += $(scpfw-path)/product/optee-stm32mp2/fw/config_all.c

ifeq ($(CFG_SCPFW_MOD_PSU_OPTEE_REGULATOR),y)
$(eval $(call scpfw-embed-product-module,psu_optee_regulator))
endif

ifeq ($(CFG_SCPFW_MOD_STM32_PD),y)
$(eval $(call scpfw-embed-product-module,stm32_pd))
endif

