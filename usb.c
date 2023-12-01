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

struct mctp_binding_usb {
	struct mctp_binding binding;
	libusb_context *ctx;
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

	(void)libusb_get_device_descriptor(dev, &desc);
	(void)ctx;

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
		struct mctp_binding_usb *usb = user_data;
		usb->usb_poll_fds = libusb_get_pollfds(usb->ctx);
		usb->bindingfds_cnt = 0;
		while (usb->usb_poll_fds[usb->bindingfds_cnt]) {
			usb->bindingfds_cnt++;
		}
		usb->bindingfds_change = true;
	} else if (LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event) {
		rc = libusb_get_device_descriptor(dev, &desc);
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
	}
	return 0;
}

struct mctp_binding_usb *mctp_usb_init(uint16_t vendor_id, uint16_t product_id,
				       uint16_t class_id)
{
	struct mctp_binding_usb *usb;
	libusb_hotplug_callback_handle callback_handle;
	int rc;
	usb = __mctp_alloc(sizeof(*usb));
	libusb_init(&usb->ctx);
	usb->bindingfds_change = false;

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
