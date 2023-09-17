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

extern mctp_routing_table_t *g_routing_table_entries;

extern mctp_uuid_table_t *g_uuid_entries;
extern int g_uuid_table_len;

extern mctp_msg_type_table_t *g_msg_type_entries;
extern int g_msg_type_table_len;

extern char *mctp_sock_path;
extern const char *mctp_medium_type;

int mctp_ctrl_running = 1;

/* String map for supported bus type */
char g_mctp_ctrl_supported_buses[MCTP_CTRL_MAX_BUS_TYPES][10] = { "PCIe Bus ",
								  "SPI Bus ",
								  "SMBus Bus " };

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
				   const char *interface,
				   const char *property,
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

	MCTP_CTRL_ERR("%s: %s\n", __func__, path);

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

	MCTP_CTRL_ERR("%s: %s\n", __func__, path);

	return sd_bus_message_append(reply, "u", addr);;
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

	(void)bus;
	(void)interface;
	(void)property;
	(void)userdata;
	(void)error;

	eid_req = mctp_ctrl_get_eid_from_sdbus_path(path);

	/* Reset the message buffer */
	memset(uuid_data, 0, MCTP_CTRL_SDBUS_MAX_MSG_SIZE);

	while (entry != NULL) {
		if (entry->eid == eid_req) {
			/* Frame the message */
			snprintf(uuid_data, MCTP_CTRL_SDBUS_MAX_MSG_SIZE,
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

static int mctp_ctrl_monitor_signal_events(mctp_sdbus_context_t *context)
{
	int ret;
	struct signalfd_siginfo si;

	if (context->fds[MCTP_CTRL_SIGNAL_FD].revents) {
		ret = read(context->fds[MCTP_CTRL_SIGNAL_FD].fd, &si,
			   sizeof(si));
		if (ret < 0 || ret != sizeof(si)) {
			MCTP_CTRL_ERR("Error read signal event: %s\n",
				      strerror(-ret));
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

int mctp_ctrl_sdbus_dispatch(mctp_sdbus_context_t *context)
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
	return SDBUS_PROCESS_EVENT;
}

static mctp_sdbus_context_t *
mctp_ctrl_sdbus_create_context(sd_bus *bus, const mctp_cmdline_args_t *cmdline)
{
	mctp_sdbus_context_t *context = NULL;
	int r;
	char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
	char mctp_ctrl_busname[MCTP_CTRL_SDBUS_NMAE_SIZE];
	mctp_msg_type_table_t *entry = g_msg_type_entries;

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		MCTP_CTRL_ERR("Failed to allocate D-Bus context\n");
		return NULL;
	}
	context->bus = bus;

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

	while (entry != NULL) {
		/* Reset the message buffer */
		memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);

		/* Frame the message */
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s%d", MCTP_CTRL_NW_OBJ_PATH, entry->eid);

		MCTP_CTRL_TRACE("Registering object '%s' for Endpoint: %d\n",
				mctp_ctrl_objpath, entry->eid);
		r = sd_bus_add_object_vtable(context->bus, NULL,
					     mctp_ctrl_objpath,
					     MCTP_CTRL_DBUS_EP_INTERFACE,
					     mctp_ctrl_endpoint_vtable,
					     context);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed to add Endpoint object: %s\n",
				      strerror(-r));
			goto finish;
		}

		MCTP_CTRL_TRACE("Registering object '%s' for UUID: %d\n",
				mctp_ctrl_objpath, entry->eid);
		r = sd_bus_add_object_vtable(context->bus, NULL,
					     mctp_ctrl_objpath,
					     MCTP_CTRL_DBUS_UUID_INTERFACE,
					     mctp_ctrl_common_uuid_vtable,
					     context);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed to add UUID object: %s\n",
				      strerror(-r));
			goto finish;
		}

		MCTP_CTRL_TRACE("Registering object '%s' for UnixSocket: %d\n",
				mctp_ctrl_objpath, entry->eid);
		r = sd_bus_add_object_vtable(context->bus, NULL,
					     mctp_ctrl_objpath,
					     MCTP_CTRL_DBUS_SOCK_INTERFACE,
					     mctp_ctrl_common_sock_vtable,
					     context);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed to add UnixSocket object: %s\n",
				      strerror(-r));
			goto finish;
		}

		MCTP_CTRL_TRACE("Registering object '%s' for Binding: %d\n",
				mctp_ctrl_objpath, entry->eid);
		r = sd_bus_add_object_vtable(context->bus, NULL,
					     mctp_ctrl_objpath,
					     MCTP_CTRL_DBUS_BINDING_INTERFACE,
					     mctp_ctrl_binding_vtable, context);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed to add Binding object: %s\n",
				      strerror(-r));
			goto finish;
		}

		if (MCTP_BINDING_SMBUS == cmdline->binding_type) {
			MCTP_CTRL_TRACE("Registering object '%s' for Inventory: %d\n",
					mctp_ctrl_objpath, entry->eid);
			r = sd_bus_add_object_vtable(context->bus, NULL,
						     mctp_ctrl_objpath,
						     MCTP_CTRL_DBUS_DECORATOR_INTERFACE,
						     mctp_ctrl_decorator_vtable,
						     context);
			if (r < 0) {
				MCTP_CTRL_ERR("Failed to add Binding object: %s\n",
					      strerror(-r));
				goto finish;
			}
		}

		r = sd_bus_emit_object_added(context->bus, mctp_ctrl_objpath);
		if (r < 0) {
			MCTP_CTRL_ERR("Failed to emit object added: %s\n",
				      strerror(-r));
			goto finish;
		}

		/* Increment for next entry */
		entry = entry->next;
	}

	MCTP_CTRL_TRACE("Getting D-Bus file descriptors\n");
	context->fds[MCTP_CTRL_SD_BUS_FD].fd = sd_bus_get_fd(context->bus);
	if (context->fds[MCTP_CTRL_SD_BUS_FD].fd < 0) {
		r = -errno;
		MCTP_CTRL_TRACE("Couldn't get the bus file descriptor: %s\n",
				strerror(errno));
		goto finish;
	}

	context->fds[MCTP_CTRL_SD_BUS_FD].events = POLLIN;
	context->fds[MCTP_CTRL_SD_BUS_FD].revents = 0;
	return context;

finish:
	free(context);

	return NULL;
}

void mctp_ctrl_sdbus_stop(void)
{
	mctp_ctrl_running = 0;
}

/* MCTP ctrl D-Bus initialization */
int mctp_ctrl_sdbus_init(sd_bus *bus, int signal_fd,
			 const mctp_cmdline_args_t *cmdline)
{
	int r = 0;
	mctp_sdbus_context_t *context = NULL;

	context = mctp_ctrl_sdbus_create_context(bus, cmdline);
	if (!context) {
		return -1;
	}
	context->fds[MCTP_CTRL_SIGNAL_FD].fd = signal_fd;
	context->fds[MCTP_CTRL_SIGNAL_FD].events = POLLIN;
	context->fds[MCTP_CTRL_SIGNAL_FD].revents = 0;

	MCTP_CTRL_DEBUG("%s: Entering polling loop\n", __func__);

	while (mctp_ctrl_running) {
		if ((r = mctp_ctrl_sdbus_dispatch(context)) < 0) {
			break;
		}
	}

	free(context);
	return r;
}
