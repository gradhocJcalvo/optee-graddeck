global-incdirs-y += .

srcs-y += main.c
srcs-y += stm32mp_pm.c
subdirs-y += drivers

srcs-$(CFG_DISPLAY) += display.c
srcs-$(CFG_SCMI_SCPFW) += scmi_server_scpfw.c
