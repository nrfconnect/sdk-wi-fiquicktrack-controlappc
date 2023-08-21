#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

if (NOT CONFIG_WFA_QT_CONTROL_APP)
	return()
endif()

zephyr_library()

set(SOURCES_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../)
# Enable of same options as upstream points to issues with Zephyr
# headers, so, for now, we disable them.
zephyr_library_compile_options(
	-Werror
	# False positive, not going away even with null check
	-Wno-format-overflow
)

zephyr_library_compile_definitions(
	CONFIG_ZEPHYR
)

zephyr_include_directories(
	${SOURCES_BASE}
	${SOURCES_BASE}/zephyr/include
)

zephyr_library_sources(
	# Zephyr's port of the Indigo API
	${SOURCES_BASE}/zephyr/src/main.c
	${SOURCES_BASE}/zephyr/src/indigo_api_callback_dut.c
	${SOURCES_BASE}/zephyr/src/vendor_specific_dut.c
	${SOURCES_BASE}/zephyr/src/utils.c
	${SOURCES_BASE}/eloop.c
	${SOURCES_BASE}/indigo_api.c
	${SOURCES_BASE}/indigo_packet.c
	${SOURCES_BASE}/qt_client.c
)
