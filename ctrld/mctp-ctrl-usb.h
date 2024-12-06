/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MCTP_CTRL_USB_H
#define MCTP_CTRL_USB_H
#include <stdlib.h>
#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <mctp-ctrl.h>

#include "libmctp-usb.h"
#include "libmctp.h"
#include "mctp-sdbus.h"

/**
 *
 * @brief Struct to store MCTP USB control context
 *
 */
typedef struct mctp_ctrl_usb {
	mctp_ctrl_t *mctp_ctrl;
	libusb_device_handle *dev_handle;
	libusb_hotplug_callback_handle cb_handle;
	libusb_context *ctx;
	const struct libusb_pollfd **usb_poll_fds;
	nfds_t bindingfds_cnt;
	int ports_count;
	uint8_t bus_id;
	uint8_t ports[MCTP_USB_PORT_PATH_MAX_DEPTH];
	mctp_sdbus_context_t *context;
} mctp_ctrl_usb_t;

/**
 * @brief  Initialize USB hotplug handling for MCTP control
 *
 * @param[in] mctp_ctrl - main mctp_ctrl structure
 * @param[in] context - the MCTP D-Bus context
 *
 * @return mctp_ctrl_usb_t* - usb binding structure
 */
mctp_ctrl_usb_t *mctp_ctrl_usb_hotplug_init(mctp_ctrl_t *mctp_ctrl,
					    mctp_sdbus_context_t *context);

/**
 * @brief Clean up USB hotplug handling for MCTP control
 *
 * @param[in] usb - main mctp_ctrl_usb structure
 */
void mctp_ctrl_usb_hotplug_exit(mctp_ctrl_usb_t *usb);

/**
 * @brief Initialize usb poll file descriptors
 *
 * @param[in] usb - the USB binding structure
 *
 */
int mctp_ctrl_usb_init_pollfd(mctp_ctrl_usb_t *usb);

/**
 * @brief Handle the usb event from libusb 
 *
 * @param[in] usb - the USB binding structure
 * @param[in] context - the MCTP D-Bus context 
 *
 * @return int (errno may be set). failure is returned.
 */
int mctp_ctrl_usb_handle_event(mctp_ctrl_t *mctp_ctrl,
			       mctp_sdbus_context_t *context);

/**
 * @brief Parse string to uint8_t integer array
 * 
 * @param[in] path_str   Input string（format example: "1-2-3 or 22-33-44"）
 * @param[in] arr Output array
 * @param[in] max_ports  Maximum port number(suggest 7)
 * @param[in] delimiter  delimiter（ex: '-'）
 * @return Actually port path number when success, negative when an error occurs
 */
int parse_delimited_numbers(const char *path_str, uint8_t *arr, int max_ports,
			    const char delimiter);

#endif //MCTP_CTRL_USB_H
