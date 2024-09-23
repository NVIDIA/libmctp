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
#include <assert.h>
#include <byteswap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <systemd/sd-bus.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "libmctp-cmds.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-ctrl-log.h"
#include "mctp-sdbus.h"
#include "mctp-discovery-common.h"
#include "mctp-discovery-i2c.h"
#include "mctp-discovery.h"

extern mctp_routing_table_t *g_routing_table_entries;

extern mctp_uuid_table_t *g_uuid_entries;
extern int g_uuid_table_len;

extern mctp_msg_type_table_t *g_msg_type_entries;
extern int g_msg_type_table_len;

extern char *mctp_sock_path;
extern const char *mctp_medium_type;

extern int g_disc_timer_fd;
extern void mctp_handle_discovery_notify();
int mctp_ctrl_running = 1;

/* String map for supported bus type */
char g_mctp_ctrl_supported_buses[MCTP_CTRL_MAX_BUS_TYPES][10] = {
	"PCIe Bus ", "SPI Bus ", "SMBus Bus "
};
#if DEBUG
static int mctp_ctrl_supported_bus_types(sd_bus *bus, const char *path,
					 const char *interface,
					 const char *property,
					 sd_bus_message *reply, void *userdata,
					 sd_bus_error *error)
{
	int r, i = 0;

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	r = sd_bus_message_open_container(reply, 'a', "s");
	if (r < 0)
		return r;

	for (i = 0; i < MCTP_CTRL_MAX_BUS_TYPES; i++) {
		r = sd_bus_message_append(reply, "s",
					  g_mctp_ctrl_supported_buses[i]);
		if (r < 0) {
			MCTP_CTRL_ERR(
				"Failed to build the list of failed boot modes: %s",
				strerror(-r));
			return r;
		}
	}

	return sd_bus_message_close_container(reply);
}
#endif

static uint8_t mctp_ctrl_get_eid_from_sdbus_path(const char *path)
{
	char *output = NULL;

	output = strrchr(path, '/');
	if (output != NULL) {
		output++;
		return atoi(output);
	}

	return 0;
}

static int mctp_ctrl_sdbus_get_nw_id(sd_bus *bus, const char *path,
				     const char *interface,
				     const char *property,
				     sd_bus_message *reply, void *userdata,
				     sd_bus_error *error)
{
	uint32_t mctp_nw_id = 0;
	uint8_t eid_req = 0;
	mctp_msg_type_table_t *entry = g_msg_type_entries;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			mctp_nw_id = MCTP_CTRL_SDBUS_NETWORK_ID;
			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	/* append the message */
	return sd_bus_message_append(reply, "u", mctp_nw_id);
}

static int mctp_ctrl_sdbus_get_endpoint(sd_bus *bus, const char *path,
					const char *interface,
					const char *property,
					sd_bus_message *reply, void *userdata,
					sd_bus_error *error)
{
	uint8_t eid_req = 0;
	mctp_msg_type_table_t *entry = g_msg_type_entries;
	uint32_t get_eid = 0;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			get_eid = entry->eid;
			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	/* append the message */
	return sd_bus_message_append(reply, "u", get_eid);
}

static int mctp_ctrl_sdbus_get_msg_type(sd_bus *bus, const char *path,
					const char *interface,
					const char *property,
					sd_bus_message *reply, void *userdata,
					sd_bus_error *error)
{
	int r, i = 0;
	uint8_t eid_req = 0;
	mctp_msg_type_table_t *entry = g_msg_type_entries;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	r = sd_bus_message_open_container(reply, 'a', "y");
	if (r < 0)
		return r;

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			/* Traverse supported message type one by one */
			while (i < entry->data_len) {
				/* append the message */
				r = sd_bus_message_append(reply, "y",
							  entry->data[i]);
				if (r < 0) {
					MCTP_CTRL_ERR(
						"Failed sd-Bus message append: %s",
						strerror(-r));
					return r;
				}

				i++;
			}

			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	return sd_bus_message_close_container(reply);
}

static int mctp_ctrl_sdbus_get_sock_type(sd_bus *bus, const char *path,
					 const char *interface,
					 const char *property,
					 sd_bus_message *reply, void *userdata,
					 sd_bus_error *error)
{
	uint32_t type = SOCK_SEQPACKET;

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	/* append the message */
	return sd_bus_message_append(reply, "u", type);
}

static int mctp_ctrl_sdbus_get_sock_proto(sd_bus *bus, const char *path,
					  const char *interface,
					  const char *property,
					  sd_bus_message *reply, void *userdata,
					  sd_bus_error *error)
{
	uint32_t proto = 0;

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	/* append the message */
	return sd_bus_message_append(reply, "u", proto);
}

static int mctp_ctrl_sdbus_get_sock_name(sd_bus *bus, const char *path,
					 const char *interface,
					 const char *property,
					 sd_bus_message *reply, void *userdata,
					 sd_bus_error *error)
{
	int i;
	int r = 0, len = 0;

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	/* increase one for the fist byte NULL-teminated character */
	len = strlen(&mctp_sock_path[1]) + 1;
	r = sd_bus_message_open_container(reply, 'a', "y");
	if (r < 0) {
		MCTP_CTRL_ERR("Failed sd-bus message open: %s", strerror(-r));
		return r;
	}

	for (i = 0; i < len; i++) {
		r = sd_bus_message_append(reply, "y", mctp_sock_path[i]);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed sd-bus message append: %s",
				      strerror(-r));
			return r;
		}
	}
	return sd_bus_message_close_container(reply);
}

static int mctp_ctrl_sdbus_get_bus(sd_bus *bus, const char *path,
				   const char *interface, const char *property,
				   sd_bus_message *reply, void *userdata,
				   sd_bus_error *error)
{
	const int eid = mctp_ctrl_get_eid_from_sdbus_path(path);
	const uint32_t i2c_bus = mctp_i2c_get_i2c_bus(eid);

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	return sd_bus_message_append(reply, "u", i2c_bus);
}

static int mctp_ctrl_sdbus_get_address(sd_bus *bus, const char *path,
				       const char *interface,
				       const char *property,
				       sd_bus_message *reply, void *userdata,
				       sd_bus_error *error)
{
	const int eid = mctp_ctrl_get_eid_from_sdbus_path(path);
	const uint32_t addr = mctp_i2c_get_i2c_addr(eid);

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	return sd_bus_message_append(reply, "u", addr);
	;
}

const char *phy_transport_binding_to_string(uint8_t id)
{
	if (id == 0x0) {
		/* It is defined unspecified in DSP0239 but we used for SPI type */
		return "SPI";
	} else if (id == 0x1) {
		/* MCTP over SMbus */
		return "SMBus";
	} else if (id == 0x2) {
		/*  MCTP over PCI */
		return "PCIe";
	} else if (id == 0x3) {
		/* MCTP over USB */
		return "USB";
	} else if (id == 0x04) {
		/* MCTP over KCS */
		return "KCS";
	} else if (id == 0x05) {
		/* MCTP over Serial*/
		return "Serial";
	} else if (id == 0x06) {
		/* MCTP over I3C*/
		return "I3C";
	}
	return "Unknown";
}

static int mctp_ctrl_sdbus_get_medium_type(sd_bus *bus, const char *path,
					   const char *interface,
					   const char *property,
					   sd_bus_message *reply,
					   void *userdata, sd_bus_error *error)
{
	uint8_t eid_req = 0xff;
	uint8_t id = 0;
	char str[MCTP_CTRL_SDBUS_NMAE_SIZE] = { 0 };
	mctp_routing_table_t *entry = NULL;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);
	entry = g_routing_table_entries;

	while (entry != NULL) {
		if (entry->routing_table.starting_eid == eid_req) {
			/* 
			*SMbus 400K is running but the medium type in the spec. only
			*indicates SMbus 100K. So the medium type is I2C 400K reported by
			*FPGA from MCTP service. We used physical transport identifier to
			*populate D-Bus property
			*/
			id = entry->routing_table.phys_transport_binding_id;
			break;
		}

		entry = entry->next;
	}

	snprintf(str, sizeof(str),
		 "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.%s",
		 phy_transport_binding_to_string(id));

	/* append the message */
	return sd_bus_message_append(reply, "s", str);
}

static int mctp_ctrl_sdbus_get_uuid(sd_bus *bus, const char *path,
				    const char *interface, const char *property,
				    sd_bus_message *reply, void *userdata,
				    sd_bus_error *error)
{
	uint8_t eid_req = 0;
	mctp_uuid_table_t *entry = g_uuid_entries;
	char uuid_data[MCTP_CTRL_SDBUS_MAX_MSG_SIZE];
	mctp_sdbus_context_t *ctx = (mctp_sdbus_context_t *)userdata;

	(void)bus;
	(void)interface;
	(void)property;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	/* Reset the message buffer */
	memset(uuid_data, 0, MCTP_CTRL_SDBUS_MAX_MSG_SIZE);

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			uint8_t nil_uuid[sizeof(ctx->cmdline->uuid_str)] = { 0 };
			/* For SPI service, always report the one passed in from the command
			   line or JSON config, if any */
			if (!strncmp(mctp_medium_type, "SPI",
				     sizeof("SPI") - 1) &&
			    memcmp(ctx->cmdline->uuid_str, nil_uuid,
				   sizeof(ctx->cmdline->uuid_str))) {
				memcpy(uuid_data, ctx->cmdline->uuid_str,
				       sizeof(ctx->cmdline->uuid_str));
			} else {
				/* Frame the message */
				snprintf(
					uuid_data, MCTP_CTRL_SDBUS_MAX_MSG_SIZE,
					"%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
					__bswap_32(entry->uuid.canonical.data0),
					__bswap_16(entry->uuid.canonical.data1),
					__bswap_16(entry->uuid.canonical.data2),
					__bswap_16(entry->uuid.canonical.data3),
					entry->uuid.canonical.data4[0],
					entry->uuid.canonical.data4[1],
					entry->uuid.canonical.data4[2],
					entry->uuid.canonical.data4[3],
					entry->uuid.canonical.data4[4],
					entry->uuid.canonical.data4[5]);
			}
			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	/* append the message */
	return sd_bus_message_append(reply, "s", uuid_data);
}

static int mctp_ctrl_sdbus_get_binding_type(sd_bus *bus, const char *path,
					    const char *interface,
					    const char *property,
					    sd_bus_message *reply,
					    void *userdata, sd_bus_error *error)
{
	char str[MCTP_CTRL_SDBUS_NMAE_SIZE] = { 0 };

	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	snprintf(str, sizeof(str),
		 "xyz.openbmc_project.MCTP.Binding.BindingTypes.%s",
		 mctp_medium_type);

	/* append the message */
	return sd_bus_message_append(reply, "s", str);
}

static int mctp_ctrl_sdbus_get_enabled(sd_bus *bus, const char *path,
				       const char *interface,
				       const char *property,
				       sd_bus_message *reply, void *userdata,
				       sd_bus_error *error)
{
	uint8_t eid_req = 0;
	mctp_msg_type_table_t *entry = g_msg_type_entries;
	bool get_enabled = 0;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			get_enabled = entry->enabled;
			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	/* append the message */
	return sd_bus_message_append(reply, "b", get_enabled);
}

static int mctp_ctrl_sdbus_set_enabled(sd_bus *bus, const char *path,
				       const char *interface,
				       const char *property,
				       sd_bus_message *msg, void *userdata,
				       sd_bus_error *error)
{
	uint8_t eid_req = 0;
	int set_enabled = false;
	mctp_msg_type_table_t *entry = g_msg_type_entries;
	int r = 0;

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	r = sd_bus_message_read(msg, "b", &set_enabled);
	if (r < 0) {
		MCTP_CTRL_ERR("[%s] Error from sd_bus_message_read: %d\n",
			      __func__, r);
		return -EINVAL;
	}

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);
	while (entry != NULL) {
		if (entry->eid == eid_req) {
			printf("EID found!\n");
			break;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	if (entry && ((int)entry->enabled != set_enabled)) {
		entry->enabled = set_enabled;
		sd_bus_emit_properties_changed(bus, path, interface, property,
					       NULL);
	}

	return 1;
}

static int mctp_ctrl_sdbus_get_service_type(sd_bus *bus, const char *path,
					    const char *interface,
					    const char *property,
					    sd_bus_message *reply,
					    void *userdata, sd_bus_error *error)
{
	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;
	(void)path;

	/* append the message */
	return sd_bus_message_append(
		reply, "s",
		"xyz.openbmc_project.State.ServiceReady.ServiceTypes.MCTP");
}

static int mctp_ctrl_sdbus_get_service_state(sd_bus *bus, const char *path,
					     const char *interface,
					     const char *property,
					     sd_bus_message *reply,
					     void *userdata,
					     sd_bus_error *error)
{
	mctp_sdbus_context_t *ctx = (mctp_sdbus_context_t *)userdata;
	(void)bus;
	(void)interface;
	(void)property;
	(void)error;
	(void)path;

	if (ctx->fds[MCTP_CTRL_SD_BUS_FD].fd != 0) {
		/* append the message - We are in enabled state after we set the D-Bus
		monitoring FD */
		return sd_bus_message_append(
			reply, "s",
			"xyz.openbmc_project.State.ServiceReady.States.Enabled");
	} else {
		return sd_bus_message_append(
			reply, "s",
			"xyz.openbmc_project.State.ServiceReady.States.Starting");
	}
}

static int mctp_ctrl_sdbus_set_service_state(sd_bus *bus, const char *path,
					     const char *interface,
					     const char *property,
					     sd_bus_message *msg,
					     void *userdata,
					     sd_bus_error *error)
{
	(void)bus;
	(void)path;
	(void)interface;
	(void)property;
	(void)msg;
	(void)userdata;
	(void)error;

	return -EINVAL;
}

static int mctp_ctrl_monitor_signal_events(mctp_sdbus_context_t *context)
{
	int ret;
	struct signalfd_siginfo si;

	if (context->fds[MCTP_CTRL_SIGNAL_FD].revents) {
		ret = read(context->fds[MCTP_CTRL_SIGNAL_FD].fd, &si,
			   sizeof(si));
		if (ret < 0 || ret != sizeof(si)) {
			MCTP_CTRL_ERR("[%s] Error read signal event: %s\n",
				      __func__, strerror(-ret));
			return 0;
		}

		if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) {
			mctp_ctrl_sdbus_stop();
			return -1;
		}
	}

	return 0;
}

static int mctp_ctrl_dispatch_sd_bus(mctp_sdbus_context_t *context)
{
	int r = 0;
	if (context->fds[MCTP_CTRL_SD_BUS_FD].revents) {
		r = sd_bus_process(context->bus, NULL);
	}
	return r;
}

static int mctp_ctrl_handle_socket(mctp_ctrl_t *mctp_ctrl,
				   mctp_sdbus_context_t *context)
{
	int r = 0;
	if ((context->fds[MCTP_CTRL_SOCKET_FD].revents & POLLHUP) ||
	    (context->fds[MCTP_CTRL_SOCKET_FD].revents & POLLERR)) {
		/* Connection hang up or closed on other side */
		MCTP_CTRL_ERR(
			"%s: Rx socket hang up or closed, closing the loop\n",
			__func__);
	} else if (context->fds[MCTP_CTRL_SOCKET_FD].revents & POLLIN) {
		MCTP_CTRL_DEBUG("%s: Rx socket event [0x%x]...\n", __func__,
				context->fds[MCTP_CTRL_SOCKET_FD].revents);

		/* Read the Socket */
		r = mctp_event_monitor(mctp_ctrl);
		if (r != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Invalid data..\n", __func__);
		}
	} else if (context->fds[MCTP_CTRL_SOCKET_FD].revents == 0) {
		/*MCTP_CTRL_INFO("%s: Rx Timeout\n", __func__);*/
	} else {
		MCTP_CTRL_WARN("%s: Unsupported rx socket event: 0x%x\n",
			       __func__,
			       context->fds[MCTP_CTRL_SOCKET_FD].revents);
	}
	return r;
}

/* Properties for xyz.openbmc_project.MCTP.Endpoint */
static const sd_bus_vtable mctp_ctrl_endpoint_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("NetworkId", "u", mctp_ctrl_sdbus_get_nw_id, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("EID", "u", mctp_ctrl_sdbus_get_endpoint, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("SupportedMessageTypes", "ay",
			mctp_ctrl_sdbus_get_msg_type, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("MediumType", "s", mctp_ctrl_sdbus_get_medium_type, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

/* Properties for xyz.openbmc_project.Common.UUID */
static const sd_bus_vtable mctp_ctrl_common_uuid_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("UUID", "s", mctp_ctrl_sdbus_get_uuid, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

/* Properties for xyz.openbmc_project.Common.UnixSocket */
static const sd_bus_vtable mctp_ctrl_common_sock_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("Type", "u", mctp_ctrl_sdbus_get_sock_type, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Protocol", "u", mctp_ctrl_sdbus_get_sock_proto, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Address", "ay", mctp_ctrl_sdbus_get_sock_name, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

/* Properties for xyz.openbmc_project.MCTP.Binding */
static const sd_bus_vtable mctp_ctrl_binding_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("BindingType", "s", mctp_ctrl_sdbus_get_binding_type, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable mctp_ctrl_decorator_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("Bus", "u", mctp_ctrl_sdbus_get_bus, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Address", "u", mctp_ctrl_sdbus_get_address, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable mctp_ctrl_object_enable_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_WRITABLE_PROPERTY("Enabled", "b", mctp_ctrl_sdbus_get_enabled,
				 mctp_ctrl_sdbus_set_enabled, 0,
				 SD_BUS_VTABLE_UNPRIVILEGED |
					 SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable mctp_ctrl_service_ready_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("ServiceType", "s", mctp_ctrl_sdbus_get_service_type, 0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_WRITABLE_PROPERTY("State", "s",
				 mctp_ctrl_sdbus_get_service_state,
				 mctp_ctrl_sdbus_set_service_state, 0,
				 SD_BUS_VTABLE_UNPRIVILEGED |
					 SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};

static int mctp_mark_service_ready(mctp_sdbus_context_t *context)
{
	int r = 0;
	char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];

	memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);
	if (MCTP_BINDING_SMBUS == context->cmdline->binding_type) {
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s/%s%d", MCTP_CTRL_OBJ_NAME, mctp_medium_type,
			 context->cmdline->i2c.bus_num);
	} else if ((MCTP_BINDING_SPI == context->cmdline->binding_type) &&
		   context->cmdline->use_json == true) {
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s/%s%d", MCTP_CTRL_OBJ_NAME, mctp_medium_type,
			 context->cmdline->spi.dev_num);
	} else {
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s/%s", MCTP_CTRL_OBJ_NAME, mctp_medium_type);
	}
	r = sd_bus_add_object_manager(context->bus, NULL, mctp_ctrl_objpath);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to add object manager: %s\n",
			      strerror(-r));
		return r;
	}
	MCTP_CTRL_TRACE("Registering object '%s' for ServiceReady.\n",
			mctp_ctrl_objpath);
	r = sd_bus_add_object_vtable(context->bus, NULL, mctp_ctrl_objpath,
				     MCTP_CTRL_DBUS_SERVICE_READY_INTERFACE,
				     mctp_ctrl_service_ready_vtable, context);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to add service ready interface: %s\n",
			      strerror(-r));
		return r;
	}
	r = sd_bus_emit_object_added(context->bus, mctp_ctrl_objpath);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to emit object added: %s\n",
			      strerror(-r));
		return r;
	}
	return r;
}

static int mctp_sdbus_refresh_endpoints(const mctp_cmdline_args_t *cmdline,
					mctp_sdbus_context_t *context)
{
	int r = 0;
	char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
	mctp_msg_type_table_t *entry = g_msg_type_entries;

	while (entry != NULL) {
		/* Reset the message buffer */
		memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);

		/* Frame the message */
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s%d", MCTP_CTRL_NW_OBJ_PATH, entry->eid);

		/* Create object only if this is a new endpoint not previously seen and
		set the new property to false after creation */

		if (entry->new) {
			MCTP_CTRL_TRACE(
				"Registering object '%s' for Endpoint: %d\n",
				mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(
				context->bus, NULL, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_EP_INTERFACE,
				mctp_ctrl_endpoint_vtable, context);
			if (r < 0) {
				MCTP_CTRL_ERR(
					"Failed to add Endpoint object: %s\n",
					strerror(-r));
				return r;
			}

			MCTP_CTRL_TRACE(
				"Registering object '%s' for UUID: %d\n",
				mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(
				context->bus, NULL, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_UUID_INTERFACE,
				mctp_ctrl_common_uuid_vtable, context);
			if (r < 0) {
				MCTP_CTRL_ERR("Failed to add UUID object: %s\n",
					      strerror(-r));
				return r;
			}

			MCTP_CTRL_TRACE(
				"Registering object '%s' for UnixSocket: %d\n",
				mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(
				context->bus, NULL, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_SOCK_INTERFACE,
				mctp_ctrl_common_sock_vtable, context);
			if (r < 0) {
				MCTP_CTRL_ERR(
					"Failed to add UnixSocket object: %s\n",
					strerror(-r));
				return r;
			}

			MCTP_CTRL_TRACE(
				"Registering object '%s' for Binding: %d\n",
				mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(
				context->bus, NULL, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_BINDING_INTERFACE,
				mctp_ctrl_binding_vtable, context);
			if (r < 0) {
				MCTP_CTRL_ERR(
					"Failed to add Binding object: %s\n",
					strerror(-r));
				return r;
			}

			if (MCTP_BINDING_SMBUS == cmdline->binding_type) {
				MCTP_CTRL_TRACE(
					"Registering object '%s' for Inventory: %d\n",
					mctp_ctrl_objpath, entry->eid);
				r = sd_bus_add_object_vtable(
					context->bus, NULL, mctp_ctrl_objpath,
					MCTP_CTRL_DBUS_DECORATOR_INTERFACE,
					mctp_ctrl_decorator_vtable, context);
				if (r < 0) {
					MCTP_CTRL_ERR(
						"Failed to add Binding object: %s\n",
						strerror(-r));
					return r;
				}
			}

			MCTP_CTRL_TRACE(
				"Registering object '%s' for Enable: %d\n",
				mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(
				context->bus, NULL, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_ENABLE_INTERFACE,
				mctp_ctrl_object_enable_vtable, context);
			if (r < 0) {
				MCTP_CTRL_ERR(
					"Failed to add Binding object: %s\n",
					strerror(-r));
				return r;
			}

			r = sd_bus_emit_object_added(context->bus,
						     mctp_ctrl_objpath);
			if (r < 0) {
				MCTP_CTRL_ERR(
					"Failed to emit object added: %s\n",
					strerror(-r));
				return r;
			}
			entry->new = false;
		} else {
			/* Not a new entry, but emit properties changed signal anyway. This
			is to ensure that we don't miss state transitions when going from
			enabled->disabled->....->enabled or
			disabled->enabled->....->disabled due to the nature of the way we
			process discovery notifies and the routing table reads following the
			debounce. */
			/* Emit a properties changed signal for entry */
			sd_bus_emit_properties_changed(
				context->bus, mctp_ctrl_objpath,
				MCTP_CTRL_DBUS_ENABLE_INTERFACE, "Enabled",
				NULL);
		}

		/* Increment for next entry */
		entry = entry->next;
	}
	return r;
}

mctp_sdbus_context_t *
mctp_ctrl_sdbus_create_context(sd_bus *bus, const mctp_cmdline_args_t *cmdline)
{
	mctp_sdbus_context_t *context = NULL;
	int r;
	char mctp_ctrl_busname[MCTP_CTRL_SDBUS_NMAE_SIZE];

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		MCTP_CTRL_ERR("Failed to allocate D-Bus context\n");
		return NULL;
	}
	context->bus = bus;
	context->cmdline = cmdline;

	/* Add sd-bus object manager */
	r = sd_bus_add_object_manager(context->bus, NULL, MCTP_CTRL_OBJ_NAME);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to add object manager: %s\n",
			      strerror(-r));
		goto finish;
	}

	if (MCTP_BINDING_SMBUS == cmdline->binding_type) {
		snprintf(mctp_ctrl_busname, MCTP_CTRL_SDBUS_NMAE_SIZE,
			 "%s.%s%d", MCTP_CTRL_DBUS_NAME, mctp_medium_type,
			 cmdline->i2c.bus_num);
	} else if (MCTP_BINDING_SPI == cmdline->binding_type) {
		if (cmdline->use_json) {
			snprintf(mctp_ctrl_busname, MCTP_CTRL_SDBUS_NMAE_SIZE,
				 "%s.%s%d", MCTP_CTRL_DBUS_NAME,
				 mctp_medium_type, cmdline->spi.dev_num);
		} else {
			/* keep using original dbus name for backward compatibility */
			snprintf(mctp_ctrl_busname, MCTP_CTRL_SDBUS_NMAE_SIZE,
				 "%s.%s", MCTP_CTRL_DBUS_NAME,
				 mctp_medium_type);
		}
	} else {
		snprintf(mctp_ctrl_busname, MCTP_CTRL_SDBUS_NMAE_SIZE, "%s.%s",
			 MCTP_CTRL_DBUS_NAME, mctp_medium_type);
	}
	MCTP_CTRL_TRACE("Requesting D-Bus name: %s\n", mctp_ctrl_busname);

	r = sd_bus_request_name(context->bus, mctp_ctrl_busname,
				SD_BUS_NAME_ALLOW_REPLACEMENT |
					SD_BUS_NAME_REPLACE_EXISTING);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to acquire service name: %s\n",
			      strerror(-r));
		goto finish;
	}

	/* Mark the service as ready by hosting the ServiceReady interface */
	r = mctp_mark_service_ready(context);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to mark service ready: %s\n",
			      strerror(-r));
		goto finish;
	}
	return context;

finish:
	free(context);

	return NULL;
}

static int mctp_ctrl_sdbus_host_endpoints(const mctp_cmdline_args_t *cmdline,
					  mctp_sdbus_context_t *context)
{
	char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
	int r = 0;

	memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);
	snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE, "%s/%s",
		 MCTP_CTRL_OBJ_NAME, mctp_medium_type);
	r = mctp_sdbus_refresh_endpoints(cmdline, context);
	if (r < 0) {
		MCTP_CTRL_ERR("Failed to add/refresh D-Bus objects: %s\n",
			      strerror(-r));
		return r;
	}

	MCTP_CTRL_TRACE("Getting D-Bus file descriptors\n");
	context->fds[MCTP_CTRL_SD_BUS_FD].fd = sd_bus_get_fd(context->bus);
	if (context->fds[MCTP_CTRL_SD_BUS_FD].fd < 0) {
		r = -errno;
		MCTP_CTRL_TRACE("Couldn't get the bus file descriptor: %s\n",
				strerror(errno));
		return r;
	}

	context->fds[MCTP_CTRL_SD_BUS_FD].events = POLLIN;
	context->fds[MCTP_CTRL_SD_BUS_FD].revents = 0;

	/* Emit a properties changed signal for service ready */
	sd_bus_emit_properties_changed(context->bus, mctp_ctrl_objpath,
				       MCTP_CTRL_DBUS_SERVICE_READY_INTERFACE,
				       "State", NULL);
	return EXIT_SUCCESS;
}

static int mctp_ctrl_handle_timer(mctp_ctrl_t *mctp_ctrl,
				  mctp_sdbus_context_t *context)
{
	if (context->fds[MCTP_CTRL_TIMER_FD].revents) {
		MCTP_CTRL_INFO("%s: Timer expired for discovery notify\n",
			       __func__);
		uint64_t ign = 0;
		if (sizeof(ign) != read(context->fds[MCTP_CTRL_TIMER_FD].fd,
					&ign, sizeof(ign))) {
			MCTP_CTRL_ERR("%s: Bad read from timer FD\n", __func__);
		}

		/* Prime the endpoints by setting all their enabled to false */
		if (g_routing_table_entries) {
			mctp_routing_table_t *entry = g_routing_table_entries;
			while (entry) {
				entry->old_valid = entry->valid;
				entry->valid = false;
				entry = entry->next;
			}
		}
		if (g_msg_type_entries) {
			mctp_msg_type_table_t *entry = g_msg_type_entries;
			while (entry) {
				entry->old_enabled = entry->enabled;
				entry->enabled = false;
				entry = entry->next;
			}
		}

		/* Perform a re-discovery, but start with getting routing table entries
		directly since we don't really need to repeat the whole process */
		mctp_discover_endpoints(mctp_ctrl->cmdline, mctp_ctrl,
					MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST);

		/* Refresh D-Bus states */
		mctp_sdbus_refresh_endpoints(mctp_ctrl->cmdline, context);

		/* Re-arm the timer if we received a discovery notify during our
		handling of the discovery notify */
		if (mctp_ctrl->perform_rediscovery == true) {
			MCTP_CTRL_INFO(
				"%s: Re-arm discovery timer after handling discovery notify\n",
				__func__);
			mctp_handle_discovery_notify();
			mctp_ctrl->perform_rediscovery = false;
		}
	}
	return 0;
}

int mctp_ctrl_sdbus_dispatch(mctp_ctrl_t *mctp_ctrl,
			     mctp_sdbus_context_t *context)
{
	int polled, r;

	polled =
		poll(context->fds, MCTP_CTRL_TOTAL_FDS, MCTP_CTRL_POLL_TIMEOUT);

	/* polling timeout */
	if (polled == 0)
		return SDBUS_POLLING_TIMEOUT;
	if (polled < 0) {
		MCTP_CTRL_ERR("Error from poll(): %s\n", strerror(errno));
		return -1;
	}

	r = mctp_ctrl_monitor_signal_events(context);
	if (r < 0) {
		MCTP_CTRL_INFO("Signal event is capatured\n");
		return -1;
	}

	r = mctp_ctrl_dispatch_sd_bus(context);
	if (r < 0) {
		MCTP_CTRL_ERR("Error handling D-Bus event: %s\n", strerror(-r));
		return -1;
	}

	r = mctp_ctrl_handle_socket(mctp_ctrl, context);
	if (r < 0) {
		MCTP_CTRL_ERR("Error handling socket event: %d\n", r);
		return -1;
	}

	r = mctp_ctrl_handle_timer(mctp_ctrl, context);
	if (r < 0) {
		MCTP_CTRL_ERR("Error handling timer event: %d\n", r);
		return -1;
	}

	return SDBUS_PROCESS_EVENT;
}

void mctp_ctrl_sdbus_stop(void)
{
	mctp_ctrl_running = 0;
}
#ifdef MOCKUP_ENDPOINT
/* MCTP ctrl D-Bus initialization */
int mctp_ctrl_sdbus_init(mctp_ctrl_t *mctp_ctrl, int signal_fd,
			 const mctp_cmdline_args_t *cmdline,
			 const mctp_sdbus_fd_watch_t *monfd,
			 mctp_sdbus_context_t *context)
#else
/* MCTP ctrl D-Bus initialization */
int mctp_ctrl_sdbus_init(mctp_ctrl_t *mctp_ctrl, int signal_fd,
			 const mctp_cmdline_args_t *cmdline,
			 mctp_sdbus_context_t *context)
#endif
{
	int r = 0;

	r = mctp_ctrl_sdbus_host_endpoints(cmdline, context);
	if (r != 0) {
		MCTP_CTRL_ERR(
			"%s: mctp_ctrl_sdbus_host_endpoints did return an error\n",
			__func__);
		return -1;
	}
	context->fds[MCTP_CTRL_SIGNAL_FD].fd = signal_fd;
	context->fds[MCTP_CTRL_SIGNAL_FD].events = POLLIN;
	context->fds[MCTP_CTRL_SIGNAL_FD].revents = 0;

	context->fds[MCTP_CTRL_SOCKET_FD].fd = mctp_ctrl->sock;
	context->fds[MCTP_CTRL_SOCKET_FD].events = POLLIN;
	context->fds[MCTP_CTRL_SOCKET_FD].revents = 0;

	context->fds[MCTP_CTRL_TIMER_FD].fd = g_disc_timer_fd;
	context->fds[MCTP_CTRL_TIMER_FD].events = POLLIN;
	context->fds[MCTP_CTRL_TIMER_FD].revents = 0;

#ifdef MOCKUP_ENDPOINT
	if (monfd) {
		context->fds[MCTP_CTRL_SD_MON_FD].fd = monfd->fd_mon;
		context->fds[MCTP_CTRL_SD_MON_FD].events = POLLIN;
		context->fds[MCTP_CTRL_SD_MON_FD].revents = 0;
		context->monitor = *monfd;
	}
#endif
	MCTP_CTRL_DEBUG("%s: Entering polling loop\n", __func__);

	while (mctp_ctrl_running) {
		if ((r = mctp_ctrl_sdbus_dispatch(mctp_ctrl, context)) < 0) {
			break;
		}
	}

	free(context);
	return r;
}
