/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBMCTP_USB_H
#define _LIBMCTP_USB_H
#define USB_BUF_MAX 512

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"
#include <poll.h>

enum {
       MCTP_USB_NO_ERROR = 0,
       MCTP_USB_FD_CHANGE
};

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

struct mctp_binding_usb *mctp_usb_init(uint16_t vendor_id, uint16_t product_id, uint16_t class_id);

int mctp_usb_init_pollfd(struct mctp_binding_usb *usb,
			   struct pollfd **pollfds);
			   
void mctp_send_tx_queue_usb(struct mctp_bus *bus);

struct mctp_binding *mctp_binding_usb_core(struct mctp_binding_usb *usb);

#ifdef __cplusplus
}
#endif
#endif /* _LIBMCTP_SMBUS_H */
