flavor_dts_file-257F_DK = stm32mp257f-dk.dts
flavor_dts_file-257F_EV1 = stm32mp257f-ev1.dts

flavorlist-MP25 = $(flavor_dts_file-257F_DK) \
		  $(flavor_dts_file-257F_EV1)

# Check if device-tree exist in OP-TEE source code, else search it in external
# device tree repository
ifeq ($(wildcard $(arch-dir)/dts/$(CFG_EMBED_DTB_SOURCE_FILE)),)
# External device tree default path
CFG_EXT_DTS ?= $(arch-dir)/dts/external-dt/optee
ifneq ($(wildcard $(CFG_EXT_DTS)/$(CFG_EMBED_DTB_SOURCE_FILE)),)
override dts-source-path := $(CFG_EXT_DTS)
-include $(CFG_EXT_DTS)/conf.mk
else
$(error Cannot find DTS file $(CFG_EXT_DTS)/$(CFG_EMBED_DTB_SOURCE_FILE))
endif
endif

ifneq ($(PLATFORM_FLAVOR),)
ifeq ($(flavor_dts_file-$(PLATFORM_FLAVOR)),)
$(error Invalid platform flavor $(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= $(flavor_dts_file-$(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= stm32mp257f-ev1.dts

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-MP25)),)
$(call force,CFG_STM32MP25,y)
endif

ifneq ($(CFG_STM32MP25),y)
$(error STM32 Platform must be defined)
endif

include core/arch/arm/cpu/cortex-armv8-0.mk
supported-ta-targets ?= ta_arm64

$(call force,CFG_ARM64_core,y)
$(call force,CFG_DRIVERS_CLK,y)
$(call force,CFG_DRIVERS_CLK_DT,y)
$(call force,CFG_DRIVERS_GPIO,y)
$(call force,CFG_DRIVERS_PINCTRL,y)
$(call force,CFG_DT,y)
$(call force,CFG_GIC,y)
$(call force,CFG_HALT_CORES_ON_PANIC_SGI,15)
$(call force,CFG_INIT_CNTVOFF,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_STM32_SHARED_IO,y)
$(call force,CFG_STM32_FIREWALL,y)
$(call force,CFG_STM32MP_CLK_CORE,y)
$(call force,CFG_STM32MP25_CLK,y)
$(call force,CFG_STM32MP25_RSTCTRL,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_WITH_LPAE,y)

CFG_TZDRAM_START ?= 0x82000000
CFG_TZDRAM_SIZE  ?= 0x02000000

CFG_CORE_HEAP_SIZE ?= 262144
CFG_CORE_RESERVED_SHM ?= n
CFG_DTB_MAX_SIZE ?= 262144
CFG_HALT_CORES_ON_PANIC ?= y
CFG_MMAP_REGIONS ?= 30
CFG_NUM_THREADS ?= 5
CFG_TEE_CORE_NB_CORE ?= 2
CFG_STM32MP_OPP_COUNT ?= 3

CFG_STM32_BSEC3 ?= y
CFG_STM32_EXTI ?= y
CFG_STM32_FMC ?= y
CFG_STM32_GPIO ?= y
CFG_STM32_IAC ?= y
CFG_STM32_OMM ?= y
CFG_STM32_RIF ?= y
CFG_STM32_RIFSC ?= y
CFG_STM32_RISAB ?= y
CFG_STM32_RISAF ?= y
CFG_STM32_RNG ?= y
CFG_STM32_RTC ?= y
CFG_STM32_SERC ?= y
CFG_STM32_STGEN ?= y
CFG_STM32_TAMP ?= y
CFG_STM32_UART ?= y

# Default enable some test facitilites
CFG_ENABLE_EMBEDDED_TESTS ?= y
CFG_WITH_STATS ?= y
CFG_WERROR ?= y

# Default disable ASLR
CFG_CORE_ASLR ?= n

# UART instance used for early console (0 disables early console)
CFG_STM32_EARLY_CONSOLE_UART ?= 2

# Default disable external DT support
CFG_EXTERNAL_DT ?= n

# Default enable HWRNG PTA support
CFG_HWRNG_PTA ?= y
ifeq ($(CFG_HWRNG_PTA),y)
$(call force,CFG_STM32_RNG,y,Mandated by CFG_HWRNG_PTA)
$(call force,CFG_WITH_SOFTWARE_PRNG,n,Mandated by CFG_HWRNG_PTA)
CFG_HWRNG_QUALITY ?= 1024
endif

# Enable reset control
ifeq ($(CFG_STM32MP25_RSTCTRL),y)
$(call force,CFG_DRIVERS_RSTCTRL,y)
$(call force,CFG_STM32_RSTCTRL,y)
endif

# Enable BSEC PTA for fuses access management
CFG_STM32_BSEC_PTA ?= y
ifeq ($(CFG_STM32_BSEC_PTA),y)
$(call force,CFG_STM32_BSEC3,y,Mandated by CFG_STM32_BSEC_PTA)
endif

# Enable Early TA NVMEM for provisioning management
CFG_TA_STM32MP_NVMEM ?= y
ifeq ($(CFG_TA_STM32MP_NVMEM),y)
$(call force,CFG_STM32_BSEC_PTA,y,Mandated by CFG_TA_STM32MP_NVMEM)
CFG_IN_TREE_EARLY_TAS += stm32mp_nvmem/1a8342cc-81a5-4512-99fe-9e2b3e37d626
endif

# Provisioning support for BSEC shadow OTP is dedicated to insecure development
# configuration only.
CFG_STM32MP_PROVISIONING ?= y
ifeq ($(CFG_STM32MP_PROVISIONING),y)
$(call force,CFG_WARN_INSECURE,y,Required by CFG_STM32MP_PROVISIONING)
endif

# Optional behavior upon receiving illegal access events
CFG_STM32_PANIC_ON_IAC_EVENT ?= y
ifeq ($(CFG_TEE_CORE_DEBUG),y)
CFG_STM32_PANIC_ON_SERC_EVENT ?= n
else
CFG_STM32_PANIC_ON_SERC_EVENT ?= y
endif
