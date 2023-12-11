#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

#define pr_fmt(x) "smbus: " x

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-usb.h"
#include "libmctp.h"
#include "mctp-json.h"

#define USB_POLL_FD_NUM 3 //Assume that the number of usb fd we want to poll is fixed

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif
#define binding_to_usb(b)   container_of(b, struct mctp_binding_usb, binding)


#define MCTP_USB_DMTF_ID 0x1AB4
#define USB_ENDPOINT_OUT (LIBUSB_ENDPOINT_OUT | 2) /* endpoint address */

struct mctp_usb_header_tx {
	uint16_t dmtf_id;
	uint8_t reserved;
	uint8_t length;
};

struct mctp_binding_usb {
	struct mctp_binding binding;
	libusb_context *ctx;
	libusb_device_handle *dev_handle;
	/* temporary transmit buffer */
	uint8_t txbuf[512];
	const struct libusb_pollfd **usb_poll_fds;
	uint8_t bindingfds_cnt;
	bool bindingfds_change;
};

int mctp_usb_handle_event(struct mctp_binding_usb *usb)
{
	struct timeval t;
	memset(&t, 0, sizeof(t));
	int ret = MCTP_USB_NO_ERROR;

	libusb_handle_events_timeout_completed(usb->ctx, &t, NULL);

	if(usb->bindingfds_change) {
		ret = MCTP_USB_FD_CHANGE;
		usb->bindingfds_change = false;
	}

	return ret;
}

int mctp_usb_hotplug_callback(struct libusb_context *ctx,
			      struct libusb_device *dev,
			      libusb_hotplug_event event, void *user_data)
{
	static libusb_device_handle *dev_handle = NULL;
	struct libusb_device_descriptor desc;
	int rc;
	bool bus_reg false;
	struct mctp_binding_usb *usb = user_data;
	struct mctp_binding *base_usb = usb->binding;
	(void)libusb_get_device_descriptor(dev, &desc);
	(void)ctx;

	if (base_usb->bus){
		bus_reg = true;
	}

	if (LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event) {
		rc = libusb_get_device_descriptor(dev, &desc);
		if (LIBUSB_SUCCESS == rc) {
			printf("Device attached: %04x:%04x\n", desc.idVendor,
			       desc.idProduct);			
		} else {
			printf("Device attached\n");
			fprintf(stderr, "Error getting device descriptor: %s\n",
				libusb_strerror((enum libusb_error)rc));
		}
		rc = libusb_open(dev, &dev_handle);
		if (LIBUSB_SUCCESS != rc) {
			printf("Could not open USB device\n");
		}
		usb->usb_poll_fds = libusb_get_pollfds(usb->ctx);
		usb->bindingfds_cnt = 0;
		while (usb->usb_poll_fds[usb->bindingfds_cnt]) {
			usb->bindingfds_cnt++;
		}
		usb->bindingfds_change = true;
		if (bus_reg)
			mctp_binding_set_tx_enabled(base_usb, true);

	} else if (LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event) {
		rc = libusb_get_device_descriptor(dev, &desc);
		if (bus_reg)
			mctp_binding_set_tx_enabled(base_usb, false);
		if (LIBUSB_SUCCESS == rc) {
			printf("Device de-attached: %04x:%04x\n", desc.idVendor,
			       desc.idProduct);
		} else {
			printf("Device de-attached\n");
			fprintf(stderr, "Error getting device descriptor: %s\n",
				libusb_strerror((enum libusb_error)rc));
		}
		if (dev_handle) {
			libusb_close(dev_handle);
			dev_handle = NULL;
		}
	} else {
		printf("Unhandled event %d\n", event);
		if (bus_reg)
			mctp_binding_set_tx_enabled(base_usb, false);
	}
	usb->dev_handle=dev_handle;
	return 0;
}


void callbackUSBTxTransferComplete(struct libusb_transfer *xfr)
{
	printf("callbackWriteComplete, status: %d\n", xfr->status);
	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		break;
	case LIBUSB_TRANSFER_ERROR:
        fprintf(stderr, "Transfer failed with error\n");
		//Retry?
        break;
    case LIBUSB_TRANSFER_CANCELLED:
        //Retry?
		printf("Transfer was canceled\n");
        break;
	default:
		break;
	}

}


static int mctp_usb_tx(struct mctp_binding_usb *usb, uint8_t len)
{
	struct libusb_transfer *tx_xfr = libusb_alloc_transfer(0);
	void *data_tx = &usb->txbuf;
	libusb_fill_bulk_transfer(tx_xfr, usb->dev_handle,
				  USB_ENDPOINT_OUT,
				  data_tx, len,
				  callbackUSBTxTransferComplete, NULL, 0);
	if (libusb_submit_transfer(tx_xfr) < 0) {
		// Error
		printf("Tx: Error libusb_submit_transfer\n");
		libusb_free_transfer(tx_xfr);
		return -1;
	}

	return 0;
}


//Tx for MCTP over USB
static int mctp_binding_usb_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	mctp_prdebug("%s: Prepared MCTP packet\n", __func__);

	struct mctp_binding_usb *usb = binding_to_usb(b);
	struct mctp_usb_header_tx *hdr;
	size_t pkt_length = mctp_pktbuf_size(pkt);
	int rv;

	uint8_t *buf_ptr;
	uint8_t usb_message_len;

	/* the length field in the header excludes usb framing
	 * and escape sequences */
	hdr = (struct mctp_usb_header_tx *)usb->txbuf;
	hdr->dmtf_id = MCTP_USB_DMTF_ID;
	hdr->length = (uint8_t)pkt_length + 1;
	hdr->reserved=0x0;

	// Check if endpoint support mctp, if no just drop send message
	// for (i = 0; i < smbus->static_endpoints_len; i++) {
	// 	if (smbus->static_endpoints[i].slave_address ==
	// 	    smbus->dest_slave_addr[0]) {
	// 		if (smbus->static_endpoints[i].support_mctp == 0) {
	// 			mctp_prerr(
	// 				"EID: %d, address: %d, bus: %d does not support MCTP, dropping packet\n",
	// 				smbus->static_endpoints[i].endpoint_num,
	// 				smbus->static_endpoints[i].slave_address,
	// 				smbus->static_endpoints[i].bus_num);
	// 			return 0;
	// 		}
	// 	}
	// }

	buf_ptr = (uint8_t *)usb->txbuf + sizeof(*hdr);
	memcpy(buf_ptr, &pkt->data[pkt->start], pkt_length);

	buf_ptr = buf_ptr + pkt_length;
	
	//MCTP packet length of [ header, data]
	usb_message_len = sizeof(*hdr) + pkt_length;

	rv = mctp_usb_tx(usb, usb_message_len);
	MCTP_ASSERT_RET(rv >= 0, -1, "mctp_usb_tx failed: %d", rv);

	return 0;
}

/*
 * Start function. mctp_usb_hotplug_callback opens the libusb device
 * Start function only checks the dev handle for USB
 */
static int mctp_usb_start(struct mctp_binding *b)
{
	struct mctp_binding_usb *usb = binding_to_usb(b);

	//Potential race condition - what if hotplug callback hasn't happened yet?
	if (!usb->dev_handle) {
		printf("Error starting USB device (hotplug callback not yet happened): \n");
		mctp_binding_set_tx_enabled(b, false);
	}
	else {
		mctp_binding_set_tx_enabled(b, true);
	}
	
	return 0;

}

/*
 * Returns generic binder handler from USB binding handler
 */
struct mctp_binding *mctp_binding_usb_core(struct mctp_binding_usb *usb)
{
	return &usb->binding;
}

struct mctp_binding_usb *mctp_usb_init(uint16_t vendor_id, uint16_t product_id,
				       uint16_t class_id)
{
	struct mctp_binding_usb *usb;
	libusb_hotplug_callback_handle callback_handle;
	int rc;
	usb = __mctp_alloc(sizeof(*usb));
	libusb_init(&usb->ctx);
	usb->dev_handle=NULL;

	usb->bindingfds_change = false;

	usb->binding.name = "usb";
	usb->binding.version = 1;

	usb->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	usb->binding.pkt_header = 4;
	usb->binding.pkt_trailer = 0;
	usb->binding.pkt_priv_size = sizeof(struct mctp_usb_pkt_private);

	rc = libusb_hotplug_register_callback(
		NULL,
		LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
			LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
		LIBUSB_HOTPLUG_ENUMERATE, vendor_id, product_id, class_id,
		mctp_usb_hotplug_callback, usb, &callback_handle);
	if (LIBUSB_SUCCESS != rc) {
		printf("Error creating a hotplug callback\n");
		libusb_exit(NULL);
	}
	usb->usb_poll_fds = libusb_get_pollfds(usb->ctx);
	usb->bindingfds_cnt = 0;
	while (usb->usb_poll_fds[usb->bindingfds_cnt]) {
		usb->bindingfds_cnt++;
	}
	usb->binding.start = mctp_usb_start;
	usb->binding.tx = mctp_binding_usb_tx;
	
	return usb;
}

int mctp_usb_init_pollfd(struct mctp_binding_usb *usb, struct pollfd **pollfds)
{
	*pollfds = __mctp_alloc(USB_POLL_FD_NUM * sizeof(struct pollfd));
	for (int i = 0; i < USB_POLL_FD_NUM; i++) {
		if(i < usb->bindingfds_cnt) {
			(*pollfds + i)->fd = usb->usb_poll_fds[i]->fd;
			(*pollfds + i)->events = usb->usb_poll_fds[i]->events;
		}
		else {
			(*pollfds + i)->fd = -1;
			(*pollfds + i)->events = 0;
		}
	}
	return USB_POLL_FD_NUM;
}
