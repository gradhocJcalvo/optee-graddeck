#
# Arm SCP/MCP Software
# Copyright (c) 2022, Linaro Limited and Contributors. All rights reserved.
# Copyright (c) 2024, STMicroelectronics and the Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

add_library(arch-tfm)

if(NOT SCP_TFM_PLAT_DIR)
        message(FATAL_ERROR
            "Insufficient firmware metadata provided.\n"
            "For tfm arch, you must set SCP_TFM_PLAT_DIR")
endif()

if(NOT SCP_TFM_DIR)
        message(FATAL_ERROR
            "Insufficient firmware metadata provided.\n"
            "For tfm arch, you must set SCP_TFM_DIR")
endif()


target_include_directories(arch-tfm
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(arch-tfm
    PRIVATE
        tfm_sprt
    PUBLIC
        module-tfm-mbx

)

target_sources(
    arch-tfm PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/arch_interrupt.c"
                       "${CMAKE_CURRENT_SOURCE_DIR}/src/arch_main.c")
