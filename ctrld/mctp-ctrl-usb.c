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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

#define pr_fmt(x) "mctp-ctrl-usb: " x

#include "compiler.h"
#include "dbus_log_event.h"
#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "mctp-ctrl-usb.h"
#include "mctp-discovery.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-log.h"
#include "mctp-sdbus.h"

#ifdef MCTP_IN_KERNEL
#include "mctp-netlink.h"
#define MAX_NETLINK_TRY	  5
#define MAX_NETLINK_DELAY 100000 //100 milliseconds
#endif

/* LIBUSB_CLASS_MCTP isn't defined at libusb_class_code */
#define LIBUSB_CLASS_MCTP 0x14

int parse_delimited_numbers(const char *path_str, uint8_t *arr, int max_ports,
			    const char delimiter)
{
	const char *input = path_str;
	const char *token = input;
	int port_count = 0;
	char *endptr;

	if (!path_str || !arr || max_ports <= 0)
		return -EINVAL;

	while (*token) {
		while (*token == delimiter)
			token++;
		if (*token == '\0')
			break;

		unsigned long val = strtoul(token, &endptr, 10);

		if (endptr == token || val > UINT8_MAX ||
		    (val == 0 && !isdigit(*token)))
			return -EINVAL;

		if (port_count >= max_ports)
			return -ERANGE;

		arr[port_count++] = (uint8_t)val;

		token = endptr;
		if (*token != '\0' && *token != delimiter)
			return -EINVAL;
	}

	return port_count;
}

static bool is_usb_bus_port_path_match(mctp_ctrl_usb_t *usb,
				       struct libusb_device *device)
{
	uint8_t bus_id;
	uint8_t ports_count;
	uint8_t ports[MCTP_USB_PORT_PATH_MAX_DEPTH] = { 0 };

	bus_id = libusb_get_bus_number(device);
	if (bus_id != usb->bus_id) {
		MCTP_CTRL_DEBUG("Bus ID mismatch: %u != %u\n", bus_id,
				usb->bus_id);
		return false;
	}

	ports_count = libusb_get_port_numbers(device, ports, sizeof(ports));
	if (ports_count != usb->ports_count) {
		MCTP_CTRL_DEBUG("Port count mismatch: %u != %u\n", ports_count,
				usb->ports_count);
		return false;
	}

	return !memcmp(ports, usb->ports, ports_count);
}

static bool is_mctp_usb_interface(libusb_device *device)
{
	enum libusb_error ret;
	struct libusb_config_descriptor *config;
	bool found = false;

	ret = libusb_get_active_config_descriptor(device, &config);
	if (ret != LIBUSB_SUCCESS) {
		MCTP_ERR("Failed to get config: %s\n", libusb_error_name(ret));
		return false;
	}

	for (int i = 0; i < config->bNumInterfaces; ++i) {
		const struct libusb_interface *interfaces =
			config->interface + i;
		for (int j = 0; j < interfaces->num_altsetting; ++j) {
			const struct libusb_interface_descriptor *interface =
				interfaces->altsetting + j;
			if (interface->bInterfaceClass == LIBUSB_CLASS_MCTP) {
				found = true;
				goto out;
			}
		}
	}

out:
	libusb_free_config_descriptor(config);
	return found;
}

static bool is_this_mctp_usb_device(mctp_ctrl_usb_t *usb,
				    struct libusb_device *device,
				    libusb_hotplug_event event)
{
	bool ret = false;

	ret = is_usb_bus_port_path_match(usb, device);
	MCTP_CTRL_DEBUG("Bus and port path match: %d\n", ret);
	if (!ret || event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT)
		return ret;

	return is_mctp_usb_interface(device);
}

static int handle_mctp_usb_device_left(mctp_ctrl_usb_t *usb,
				       struct libusb_device *device)
{
	extern mctp_msg_type_table_t *g_msg_type_entries;
	(void)device;

	MCTP_CTRL_DEBUG("%s\n", __func__);

	mctp_ctrl_bridge_poll_suspend(usb->mctp_ctrl->cmdline->usb.bridge_eid);

	if (usb->dev_handle) {
		libusb_close(usb->dev_handle);
		usb->dev_handle = NULL;
	}

	for (mctp_msg_type_table_t *entry = g_msg_type_entries; entry != NULL;
	     entry = entry->next) {
		entry->old_enabled = entry->enabled;
		entry->enabled = false;
	}

	MCTP_CTRL_DEBUG("Set all endpoint 'Enabled' property to false");

	return LIBUSB_SUCCESS;
}

static int handle_mctp_usb_device_arrived(mctp_ctrl_usb_t *usb,
					  struct libusb_device *device)
{
	extern mctp_msg_type_table_t *g_msg_type_entries;
	mctp_ctrl_t *mctp_ctrl = usb->mctp_ctrl;
	enum libusb_error rc;
	mctp_ret_codes_t ret;
	static bool initialised = false;

	MCTP_CTRL_DEBUG("%s\n", __func__);

	rc = libusb_open(device, &usb->dev_handle);
	if (LIBUSB_SUCCESS != rc) {
		mctp_prerr("%s: Could not open USB device:%s\n", __func__,
			   libusb_strerror(rc));
		return rc;
	}

	for (mctp_msg_type_table_t *entry = g_msg_type_entries; entry != NULL;
	     entry = entry->next) {
		entry->old_enabled = entry->enabled;
		entry->enabled = true;
	}

	MCTP_CTRL_DEBUG("Set all endpoint 'Enabled' property to true");

	/* mctp_discover_endpoints will be call later at remain initialization */
	if (unlikely(!initialised)) {
		initialised = true;
		return LIBUSB_SUCCESS;
	}

#ifdef MCTP_IN_KERNEL
	uint8_t retry = 0;
	/* Bind local EID to new ifindex, retry incase interface up is delayed */
	while (((rc = mctp_nl_socket_init()) < 0) &&
	       (retry < MAX_NETLINK_TRY)) {
		usleep(MAX_NETLINK_DELAY);
		MCTP_CTRL_ERR(
			"%s failed to setup nl_socket after device arrival, retry count[%d]",
			__func__, retry);
		retry++;
	}
	if (rc < 0) {
		MCTP_CTRL_ERR(
			"%s failed to setup nl_socket, terminating re-dicovery",
			__func__);
		return LIBUSB_ERROR_OTHER;
	}
#endif
	/* Perform a re-discovery, but start with getting routing table entries
	directly since we don't really need to repeat the whole process */
	ret = mctp_discover_endpoints(mctp_ctrl->cmdline, mctp_ctrl,
				      MCTP_SET_EP_REQUEST);

	if (ret != MCTP_RET_DISCOVERY_SUCCESS) {
		MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
		return LIBUSB_ERROR_OTHER;
	}

	mctp_ctrl_bridge_poll_resume();

	return LIBUSB_SUCCESS;
}

static int mctp_usb_hotplug_callback(libusb_context *ctx,
				     struct libusb_device *device,
				     libusb_hotplug_event event,
				     void *user_data)
{
	(void)ctx;
	mctp_ctrl_usb_t *usb = user_data;
	mctp_ctrl_t *mctp_ctrl = usb->mctp_ctrl;
	enum libusb_error rc;

	MCTP_CTRL_DEBUG("!!!!!!!!!!!Hotplug event!!!!!!!!!!!!!!!! %u\n", event);

	/* Only handle mctp usb device */
	if (!is_this_mctp_usb_device(usb, device, event)) {
		MCTP_CTRL_DEBUG("Not a MCTP USB device\n");
		return LIBUSB_SUCCESS;
	}

	switch (event) {
	case LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED:
		rc = handle_mctp_usb_device_arrived(usb, device);
		break;
	case LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT:
		rc = handle_mctp_usb_device_left(usb, device);
		break;
	default:
		MCTP_CTRL_ERR("Entered unhandled event callback, event: %d\n",
			      event);
		return LIBUSB_SUCCESS;
	};

	if (rc != LIBUSB_SUCCESS) {
		MCTP_CTRL_ERR("Failed to handle hotplug event %u: %s\n", event,
			      strerror(-rc));
		return LIBUSB_SUCCESS;
	}

	/* Arrived or left event need to refresh D-Bus states */
	rc = mctp_sdbus_refresh_endpoints(mctp_ctrl->cmdline, usb->context);
	if (rc < 0) {
		MCTP_CTRL_ERR("Failed to add/refresh D-Bus objects: %s\n",
			      strerror(-rc));
		return LIBUSB_SUCCESS;
	}

	return LIBUSB_SUCCESS;
}

static void dump_fds(mctp_ctrl_usb_t *usb, const char *prefix)
{
	struct pollfd *fds = usb->context->fds + MCTP_CTRL_TOTAL_FDS;

	MCTP_CTRL_DEBUG("%s\n", prefix);
	for (nfds_t i = 0; i < usb->bindingfds_cnt; ++i, ++fds) {
		MCTP_CTRL_DEBUG("fd = %2u, events = 0x%x, revents = 0x%x\n",
				fds->fd, fds->events, fds->revents);
	}
}

static uint8_t pollfd_update(mctp_ctrl_usb_t *usb)
{
	struct pollfd *fds;
	mctp_sdbus_context_t *context = usb->context;

	dump_fds(usb, "Old FDs:");
	if (likely(usb->usb_poll_fds))
		libusb_free_pollfds(usb->usb_poll_fds);

	usb->usb_poll_fds = libusb_get_pollfds(usb->ctx);
	if (!usb->usb_poll_fds) {
		MCTP_CTRL_ERR("%s: libusb_get_pollfds fail\n", __func__);
		return 0;
	}
	usb->bindingfds_cnt = 0;
	while (usb->usb_poll_fds[usb->bindingfds_cnt])
		usb->bindingfds_cnt++;

	assert(usb->bindingfds_cnt <= MCTP_CTRL_USB_POLL_FD_NUM);
	MCTP_CTRL_DEBUG("%s: bindindfds_cnt:%lu -> %lu\n", __func__,
			context->nfds,
			usb->bindingfds_cnt + MCTP_CTRL_TOTAL_FDS);
	context->nfds = usb->bindingfds_cnt + MCTP_CTRL_TOTAL_FDS;

	fds = context->fds + MCTP_CTRL_TOTAL_FDS;
	for (nfds_t i = 0; i < usb->bindingfds_cnt; ++i) {
		fds[i] = (struct pollfd){
			.fd = usb->usb_poll_fds[i]->fd,
			.events = usb->usb_poll_fds[i]->events,
		};
	}

	for (nfds_t i = usb->bindingfds_cnt; i < MCTP_CTRL_USB_POLL_FD_NUM;
	     ++i) {
		fds[i] = (struct pollfd){
			.fd = -1,
		};
	}
	dump_fds(usb, "New FDs:");

	return usb->bindingfds_cnt;
}

static void pollfd_added_callback(int fd, short events, void *user_data)
{
	mctp_ctrl_usb_t *usb = user_data;

	MCTP_CTRL_DEBUG("%s: fd = %d, events = %d\n", __func__, fd, events);
	if (!pollfd_update(usb))
		MCTP_CTRL_ERR("%s: Error update USB bindings \n", __func__);
}

static void pollfd_removed_callback(int fd, void *user_data)
{
	mctp_ctrl_usb_t *usb = user_data;

	MCTP_CTRL_DEBUG("%s: fd = %d\n", __func__, fd);
	if (!pollfd_update(usb))
		MCTP_CTRL_ERR("%s: Error update USB bindings \n", __func__);
}

int mctp_ctrl_usb_init_pollfd(mctp_ctrl_usb_t *usb)
{
	int ret;

	MCTP_CTRL_DEBUG("%s\n", __func__);
	ret = pollfd_update(usb);
	libusb_set_pollfd_notifiers(usb->ctx, pollfd_added_callback,
				    pollfd_removed_callback, usb);
	return ret;
}

mctp_ctrl_usb_t *mctp_ctrl_usb_hotplug_init(mctp_ctrl_t *mctp_ctrl,
					    mctp_sdbus_context_t *context)
{
	mctp_ctrl_usb_t *usb;
	struct mctp_cmdline_usb *cli = &mctp_ctrl->cmdline->usb;
	libusb_hotplug_event events = LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
				      LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT;
	int rc;

	MCTP_CTRL_DEBUG("%s\n", __func__);
	usb = __mctp_alloc(sizeof(*usb));
	if (NULL == usb) {
		MCTP_CTRL_ERR("%s: Failed to alloc memory\n", __func__);

		return NULL;
	}

	*usb = (mctp_ctrl_usb_t){
		.mctp_ctrl = mctp_ctrl,
		.bus_id = cli->bus_id,
		.context = context,
	};
	usb->ports_count = parse_delimited_numbers(cli->port_path, usb->ports,
						   sizeof(usb->ports), '-');

	if (usb->ports_count < 0) {
		MCTP_CTRL_ERR("%s:Failed to parse port path:%s\n", __func__,
			      strerror(-usb->ports_count));
		goto exit;
	}

	if (usb->ports[0] == 0) {
		MCTP_CTRL_ERR("%s:ports number should not be zero\n", __func__);
		goto exit;
	}

	libusb_init(&usb->ctx);

	rc = libusb_hotplug_register_callback(
		usb->ctx, events, LIBUSB_HOTPLUG_ENUMERATE,
		LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
		LIBUSB_HOTPLUG_MATCH_ANY, mctp_usb_hotplug_callback, usb,
		&usb->cb_handle);

	if (LIBUSB_SUCCESS != rc) {
		MCTP_CTRL_ERR("%s: Hotplug failed to register\n", __func__);
		libusb_exit(usb->ctx);
		goto exit;
	}

	return usb;
exit:
	__mctp_free(usb);
	return NULL;
}

void mctp_ctrl_usb_hotplug_exit(mctp_ctrl_usb_t *usb)
{
	if (!usb)
		return;
	usb->mctp_ctrl->pvt_binding_data = NULL;
	libusb_hotplug_deregister_callback(usb->ctx, usb->cb_handle);
	if (usb->usb_poll_fds)
		libusb_free_pollfds(usb->usb_poll_fds);
	usb->usb_poll_fds = NULL;

	if (usb->dev_handle) {
		libusb_close(usb->dev_handle);
		usb->dev_handle = NULL;
	}

	libusb_exit(usb->ctx);
	__mctp_free(usb);
}

static void handle_usb_event(mctp_ctrl_usb_t *usb)
{
	struct timeval t = { 0 };
	enum libusb_error rc;

	rc = libusb_handle_events_timeout(usb->ctx, &t);
	if (rc != LIBUSB_SUCCESS)
		mctp_prerr("%s: Libusb handle events timeout:%s", __func__,
			   libusb_strerror(rc));
}

int mctp_ctrl_usb_handle_event(mctp_ctrl_t *mctp_ctrl,
			       mctp_sdbus_context_t *context)
{
	mctp_ctrl_usb_t *usb = mctp_ctrl->pvt_binding_data;
	/* 
	 * We want to ensure only the hotplug callback handled through poll-fds
	 * is generating an mctp-ctrl re-enumeration
	 */
	struct pollfd *fds = &context->fds[MCTP_CTRL_TOTAL_FDS];
	/* Check if there was, in fact, a USB event */
	for (nfds_t i = 0; i < usb->bindingfds_cnt; i++) {
		if (!fds[i].revents)
			continue;
		handle_usb_event(usb);
	}

	return 0;
}
