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

#define pr_fmt(x) "usb: " x

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

#define MCTP_USB_DMTF_ID 0xB41A
#define MCTP_CLASS_ID	 0x14

struct mctp_usb_header_tx {
	uint16_t dmtf_id;
	uint8_t reserved;
	uint8_t length;
} __attribute__((packed));

struct mctp_usb_header_rx {
	uint16_t dmtf_id;
	uint8_t rsvd;
	uint8_t byte_count;
} __attribute__((packed));

struct mctp_binding_usb {
	struct mctp_binding binding;
	libusb_context *ctx;
	libusb_device_handle *dev_handle;
	/* temporary transmit buffer */
	uint8_t txbuf[512];
	/* receive buffer */
	uint8_t rxbuf[512];
	struct mctp_pktbuf *rx_pkt;
	const struct libusb_pollfd **usb_poll_fds;
	uint8_t bindingfds_cnt;
	bool bindingfds_change;
	uint8_t endpoint_in_addr;
	uint8_t endpoint_out_addr;
	/* stats for binding Tx */
	uint16_t tx_failed_cntr;
	uint16_t tx_cntr;
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

void mctp_usb_rx_transfer_callback(struct libusb_transfer *xfr)
{
	struct mctp_binding_usb *usb = xfr->user_data;
	struct mctp_usb_header_rx *hdr;

	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:

		mctp_trace_rx(xfr->buffer, xfr->actual_length);

		if (xfr->actual_length < (ssize_t)sizeof(*hdr)) {
			mctp_prerr(
				"Got bad length in MCTP Rx! Length is too short: %d\n",
				xfr->actual_length);
			goto out;
		}

		hdr = (void *)xfr->buffer;
		if (hdr->dmtf_id != MCTP_USB_DMTF_ID) { // The recipient of the message is 'Src_slave_addr'
			mctp_prerr("Got bad DMTF ID: %d", hdr->dmtf_id);
			goto out;
		}
		if (hdr->byte_count != xfr->actual_length) {
			// Got an incorrectly sized payload
			mctp_prerr("Expecting payload sized %d, got %d",
				   hdr->byte_count, xfr->actual_length);
			mctp_trace_rx(xfr->buffer, xfr->actual_length);
			goto out;
		}
		usb->rx_pkt = mctp_pktbuf_alloc(&usb->binding, 0);
		MCTP_ASSERT(usb->rx_pkt != NULL, -1, "Could not allocate pktbuf.");
		if (mctp_pktbuf_push(usb->rx_pkt, &usb->rxbuf[sizeof(*hdr)],
			xfr->actual_length - sizeof(*hdr)) != 0) {
			mctp_prerr("Can't push to pktbuf.");
			goto out;
		}
		mctp_bus_rx(&usb->binding, usb->rx_pkt);
		usb->rx_pkt = NULL;
		break;
	default:
		mctp_prerr("Rx transfer failed with status: %d\n", xfr->status);
		break;
	}
out:
	libusb_submit_transfer(xfr);
}

int mctp_usb_hotplug_callback(struct libusb_context *ctx,
			      struct libusb_device *dev,
			      libusb_hotplug_event event, void *user_data)
{
	static libusb_device_handle *dev_handle = NULL;
	struct libusb_device_descriptor desc;
	int rc;
	bool bus_reg = false;
	struct mctp_binding_usb *usb = user_data;
	struct mctp_binding *base_usb = &usb->binding;
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
		// Iterate through all usb configurations to get mctp info
		struct libusb_config_descriptor *config;
		for (uint8_t i = 0; i < desc.bNumConfigurations; i++) {
			libusb_get_config_descriptor(dev, i, &config);
			for (uint8_t j = 0; j < config->bNumInterfaces; ++j) {
				const struct libusb_interface *itf =
					&config->interface[j];
				for (uint8_t k = 0; k < itf->num_altsetting;
				     ++k) {
					const struct libusb_interface_descriptor
						*itf_desc = &itf->altsetting[k];
					if (itf_desc->bInterfaceClass ==
					    MCTP_CLASS_ID) {
						for (uint8_t l = 0;
						     l <
						     itf_desc->bNumEndpoints;
						     l++) {
							const struct libusb_endpoint_descriptor
								*ep_desc =
									&itf_desc->endpoint
										 [l];
							// Get endpoints address
							if ((ep_desc->bEndpointAddress &
							     0x80) ==
							    LIBUSB_ENDPOINT_OUT)
								usb->endpoint_out_addr =
									ep_desc->bEndpointAddress;
							if ((ep_desc->bEndpointAddress &
							     0x80) ==
							    LIBUSB_ENDPOINT_IN)
								usb->endpoint_in_addr =
									ep_desc->bEndpointAddress;
						}
					}
				}
			}
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
		//Submit to get Rx
		struct libusb_transfer *rx_xtr = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(rx_xtr, dev_handle,
					  usb->endpoint_in_addr, // Endpoint ID
					  usb->rxbuf, sizeof(usb->rxbuf),
					  mctp_usb_rx_transfer_callback, usb,
					  0);
		if (libusb_submit_transfer(rx_xtr) < 0) {
			mctp_prerr("Rx: Error libusb_submit_transfer\n");
			libusb_free_transfer(rx_xtr);
		}

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

void mctp_usb_tx_transfer_callback(struct libusb_transfer *xfr)
{
	struct mctp_binding_usb *usb = (struct mctp_binding_usb *) xfr->user_data;
	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		usb->tx_cntr += 1;
		break;
	case LIBUSB_TRANSFER_ERROR:
        mctp_prerr("Transfer FAILED with status %d\n", xfr->status);
		usb->tx_failed_cntr += 1;
		//Retry?
        break;
    case LIBUSB_TRANSFER_CANCELLED:
		mctp_prerr("Transfer was CANCELLED with status %d\n", xfr->status);
		usb->tx_failed_cntr += 1;
        //Retry?
        break;
	default:
		mctp_prerr("Tx transfer error: %d\n", xfr->status);
		break;
	}
	libusb_free_transfer(xfr);

}

static int mctp_usb_tx(struct mctp_binding_usb *usb, size_t len)
{
	struct libusb_transfer *tx_xfr = libusb_alloc_transfer(0);

	mctp_trace_tx(usb->txbuf, len);

	void *data_tx = (void *)usb->txbuf;

	if (!usb->dev_handle){
		return -1;
	}
	libusb_fill_bulk_transfer(tx_xfr, usb->dev_handle,
				  usb->endpoint_out_addr, data_tx, len,
				  mctp_usb_tx_transfer_callback, usb, 0);
	if (libusb_submit_transfer(tx_xfr) < 0) {
		// Error
		mctp_prerr("Tx: Error libusb_submit_transfer\n");
		libusb_free_transfer(tx_xfr);
		return -1;
	}

	return 0;
}

static size_t prepare_usb_hdr(struct mctp_pktbuf *pkt, size_t pkt_length)
{
	struct mctp_usb_header_tx *hdr;
	uint8_t mctp_pkt_length;

	hdr = (struct mctp_usb_header_tx *)pkt->data;
	hdr->dmtf_id = MCTP_USB_DMTF_ID;
	mctp_pkt_length = (uint8_t)pkt_length + (uint8_t)sizeof(hdr);
	hdr->length = mctp_pkt_length;
	hdr->reserved=0x0;

	return mctp_pkt_length;
}


/* 
 * Batch Tx on bus, called from core.c
 */
void mctp_send_tx_queue_usb(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;
	int rv;
	char *buf_ptr;
	size_t usb_buf_len = 0;
	struct mctp_binding_usb *usb = binding_to_usb(bus->binding);
	uint16_t usb_message_len;
	buf_ptr = (char *)usb->txbuf;

	if (bus->state != mctp_bus_state_tx_enabled){
		mctp_prerr("Bus is in enabled state, cannot Tx");
		return;
	}

	while ((pkt = bus->tx_queue_head)) {
		size_t pkt_length = mctp_pktbuf_size(pkt);

		/* data + binding header + mctp header */
		usb_message_len = prepare_usb_hdr(pkt, pkt_length);

		if ((usb_buf_len + usb_message_len) > USB_BUF_MAX) {
			rv = mctp_usb_tx(usb, usb_buf_len);

			MCTP_ASSERT(rv >= 0, "mctp_usb_tx failed: %d", rv);
			buf_ptr = (char  *)usb->txbuf;
			usb_buf_len = 0;
			continue;

		} else {
			usb_buf_len += usb_message_len;
			memcpy(buf_ptr, pkt->data, usb_message_len);
		}

		buf_ptr = buf_ptr + usb_message_len;

		bus->tx_queue_head = pkt->next;
		mctp_pktbuf_free(pkt);
	}
	if (!bus->tx_queue_head)
		bus->tx_queue_tail = NULL;

	rv = mctp_usb_tx(usb, usb_buf_len);
	MCTP_ASSERT(rv >= 0, "mctp_usb_tx failed: %d", rv);
}


//Tx for MCTP over USB
static int mctp_binding_usb_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	/* Payload + base mctp hdr = 68B */
	size_t pkt_length = mctp_pktbuf_size(pkt);
	struct mctp_binding_usb *usb = binding_to_usb(b);

	/* BTU + binding header + mctp hdr */
	size_t usb_message_len;
	usb_message_len = prepare_usb_hdr(pkt, pkt_length);
	
	int rv;

	unsigned char *buf_ptr;

	/* the length field in the header excludes usb framing
	 * and escape sequences */
	buf_ptr = (unsigned char *)usb->txbuf;
	memcpy(buf_ptr, &pkt->data, usb_message_len);
	
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
		mctp_prinfo("USB device could not be started (hotplug callback not yet happened!): \n");
		mctp_binding_set_tx_enabled(b, false);
	}
	else {
		mctp_prinfo("Enabling bus in start func \n");
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
	(void)class_id;
	struct mctp_binding_usb *usb;
	libusb_hotplug_callback_handle callback_handle;
	int rc;
	usb = __mctp_alloc(sizeof(*usb));
	libusb_init(&usb->ctx);
	usb->dev_handle=NULL;
	usb->bindingfds_change = false;

	usb->binding.name = "usb";
	usb->binding.version = 1;

	#ifdef MCTP_BATCH_TX
	usb->binding.mctp_send_tx_queue = mctp_send_tx_queue_usb;
	#else
	usb->binding.mctp_send_tx_queue = NULL;
	#endif


	usb->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	usb->binding.pkt_header = 4;
	usb->binding.pkt_trailer = 0;
	usb->binding.pkt_priv_size = sizeof(struct mctp_usb_pkt_private);

	rc = libusb_hotplug_register_callback(
		NULL,
		LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
			LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
		LIBUSB_HOTPLUG_ENUMERATE, vendor_id, product_id, LIBUSB_HOTPLUG_MATCH_ANY,
		mctp_usb_hotplug_callback, usb, &callback_handle);
	if (LIBUSB_SUCCESS != rc) {
		mctp_prerr("Error creating a hotplug callback\n");
		libusb_exit(NULL);
	}
	usb->usb_poll_fds = libusb_get_pollfds(usb->ctx);
	usb->bindingfds_cnt = 0;
	while (usb->usb_poll_fds[usb->bindingfds_cnt]) {
		usb->bindingfds_cnt++;
	}
	usb->binding.start = mctp_usb_start;
	usb->binding.tx = mctp_binding_usb_tx;
	usb->tx_cntr = 0;
	usb->tx_failed_cntr = 0;
	
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
