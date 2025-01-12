/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBMCTP_USB_H
#define _LIBMCTP_USB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"
#include <poll.h>

/* Maximum possible single transfer in MCTP_USB_BATCH_FRAG and
   MCTP_USB_BATCH_ZPAD */
#define USB_BUF_MAX_XFR 5120

/* Maximum USB packet size for MCTP_USB_BATCH_REG */
#define USB_MAX_PKT 512

enum { MCTP_USB_NO_ERROR = 0, MCTP_USB_FD_CHANGE };

typedef enum {
	MCTP_USB_BATCH_NONE = 0,
	MCTP_USB_BATCH_REG = 1,
	MCTP_USB_BATCH_FRAG = 2,
	MCTP_USB_BATCH_ZPAD = 3
} MctpUsbBatchMode;

struct mctp_usb_pkt_private {
	/*
	 * We are unsure if we really need this.
	 * Let's reserve some memory in case we need to
	 * store something useful here.
	 */
	uint8_t _reserved[32];
} __attribute__((packed));

struct mctp_binding_usb;

int mctp_usb_handle_event(struct mctp_binding_usb *usb);

struct mctp_binding_usb *mctp_usb_init(uint16_t vendor_id, uint16_t product_id,
				       uint16_t class_id, MctpUsbBatchMode mode,
				       uint8_t bus_id, char *port_path);

int mctp_usb_init_pollfd(struct mctp_binding_usb *usb, struct pollfd **pollfds);

void mctp_send_tx_queue_usb(struct mctp_bus *bus);

struct mctp_binding *mctp_binding_usb_core(struct mctp_binding_usb *usb);

#ifdef __cplusplus
}
#endif
#endif /* _LIBMCTP_SMBUS_H */
