/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>

#include <json-c/json.h>

#define SD_LISTEN_FDS_START 3

#include "compiler.h"
#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-astpcie.h"
#include "libmctp-astspi.h"
#include "libmctp-externals.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp-usb.h"
#include "utils/mctp-capture.h"
#include "mctp-json.h"
#include "astpcie.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused      __attribute__((unused))

#define MCTP_BIND_INFO_OFFSET (sizeof(uint8_t))
#define MCTP_PCIE_EID_OFFSET                                                   \
	(MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_astpcie_pkt_private))
#define MCTP_PCIE_MSG_OFFSET MCTP_PCIE_EID_OFFSET + (sizeof(uint8_t))
#define MCTP_SPI_EID_OFFSET                                                    \
	(MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_astspi_pkt_private))
#define MCTP_SPI_MSG_OFFSET (MCTP_SPI_EID_OFFSET + sizeof(uint8_t))

// MCTP_SMBUS defined offsets
#define MCTP_SMBUS_EID_OFFSET                                                  \
	MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_smbus_pkt_private)
#define MCTP_SMBUS_MSG_OFFSET MCTP_SMBUS_EID_OFFSET + (sizeof(uint8_t))
#define MCTP_SMBUS_MSG_COMMAND_CODE_OFFSET                                     \
	MCTP_SMBUS_EID_OFFSET + (3 * sizeof(uint8_t))
#define MCTP_SMBUS_MSG_DATA_0_OFFSET                                           \
	MCTP_SMBUS_EID_OFFSET + (5 * sizeof(uint8_t))

#define MCTP_SMBUS_BUS_NUM                                                     \
	2 //I2C Bus: 			11(BMC), 2(HMC) [7-bit]
#define MCTP_SMBUS_DEST_SLAVE_ADDR                                             \
	0x30 //Dest_Slave_Addr:	0x52(BMC), 0x30(HMC) [7-bit]
#define MCTP_SMBUS_SRC_SLAVE_ADDR                                              \
	0x18 //Src_Slave_Addr:	0x51(BMC), 0x18(HMC) [7-bit]

// MCTP_USB defined offsets:
// Question: offsets for smbus do not correspond to diagram in spec
#define MCTP_USB_EID_OFFSET                                                  \
	MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_usb_pkt_private)
#define MCTP_USB_MSG_OFFSET MCTP_USB_EID_OFFSET + (sizeof(uint8_t))

#include <systemd/sd-daemon.h>

uint8_t i2c_bus_num = MCTP_SMBUS_BUS_NUM;
uint8_t i2c_bus_num_smq = MCTP_SMBUS_BUS_NUM;
uint8_t i2c_dest_slave_addr = MCTP_SMBUS_DEST_SLAVE_ADDR;
uint8_t i2c_src_slave_addr = MCTP_SMBUS_SRC_SLAVE_ADDR;

static const mctp_eid_t local_eid_default = 8;

struct binding {
	const char *name;
	int (*init)(struct mctp *mctp, struct binding *binding, mctp_eid_t eid,
		    int n_params, char *const *params);
	void (*destroy)(struct mctp *mctp, struct binding *binding);
	int (*init_pollfd)(struct binding *binding, struct pollfd **pollfd);
	int (*process)(struct binding *binding);
	void *data;
	char *sockname;
	uint8_t bindingfds_cnt;
	bool bindings_changed;
};

struct client {
	bool active;
	int sock;
	uint8_t type;
};

struct ctx {
	struct mctp *mctp;
	struct binding *binding;
	bool verbose;
	int local_eid;
	void *buf;
	size_t buf_size;

	int sock;
	struct pollfd *pollfds;
	int n_bindings;
	struct client *clients;
	int n_clients;
	bool clients_changed;

	struct {
		struct capture binding;
		struct capture socket;
	} pcap;
};

uint8_t chosen_eid_type;

struct mctp_static_endpoint_mapper *smbus_static_endpoints = NULL;
uint8_t smbus_static_endpoints_len;

static void mctp_print_hex(uint8_t *data, size_t length)
{
	for (size_t i = 0; i < length; ++i) {
		printf("%02X ", data[i]);
	}
	printf("\n");
}

static void tx_pvt_message(struct ctx *ctx, void *msg, size_t len)
{
	int rc = 0;
	mctp_binding_ids_t bind_id;
	union {
		struct mctp_astpcie_pkt_private pcie;
		struct mctp_astspi_pkt_private spi;
		struct mctp_smbus_pkt_private i2c;
		struct mctp_usb_pkt_private usb;
	} pvt_binding = { 0 };
	mctp_eid_t eid = 0;
	const size_t min_packet_pcie = MCTP_PCIE_MSG_OFFSET + 1;
	const size_t min_packet_spi = MCTP_SPI_MSG_OFFSET + 1;
	const size_t min_packet_smbus = MCTP_SMBUS_MSG_OFFSET + 1;
	const size_t min_packet_usb = MCTP_USB_EID_OFFSET + 1;

	/* Get the bus type (binding ID) */
	bind_id = *((uint8_t *)msg);

	/* Handle based on bind ID's */
	switch (bind_id) {
	case MCTP_BINDING_PCIE:
		if (len <= min_packet_pcie) {
			mctp_prwarn("Packet too short for PCIe, len = %zi, expected > %zi\n",
						len, min_packet_pcie);
			return;
		}

		/* Copy the binding information */
		memcpy(&pvt_binding.pcie, ((uint8_t *)msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_astpcie_pkt_private));

		/* Get target EID */
		eid = *((uint8_t *)msg + MCTP_PCIE_EID_OFFSET);

		/* Set MCTP payload size */
		len = len - min_packet_pcie;
		mctp_prdebug("Printing packet length, PCIE binding: %zi", len);
		if (ctx->verbose) {
			mctp_print_hex((uint8_t *)msg + MCTP_PCIE_MSG_OFFSET, len);
		}
		rc = mctp_message_pvt_bind_tx(ctx->mctp, eid, MCTP_MESSAGE_TO_SRC, 0,
					      (uint8_t *)msg + MCTP_PCIE_MSG_OFFSET, len,
					      (void *)&pvt_binding.pcie);

		if (ctx->verbose) {
			printf("%s: BindID: %d, Target EID: %d, msg len: %zi,\
			    Routing:%d remote_id: 0x%x\n",
			       __func__, bind_id, eid, len,
			       pvt_binding.pcie.routing,
			       pvt_binding.pcie.remote_id);
		}
		if (rc) {
			warnx("Failed to send message: %d", rc);
		}
		break;
	case MCTP_BINDING_SPI:
		if (len < min_packet_spi) {
			mctp_prwarn("Packet too short for SPI, len = %zi, expected > %zi\n",
						len, min_packet_spi);
			return;
		}

		memcpy(&pvt_binding.spi, ((uint8_t *)msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_astspi_pkt_private));

		eid = *((uint8_t *)msg + MCTP_SPI_EID_OFFSET);

		len = len - (MCTP_SPI_MSG_OFFSET)-1;
		mctp_prdebug("Printing packet length, SPI binding: %zi", len);
		if (ctx->verbose) {
			mctp_print_hex((uint8_t *)msg + MCTP_SPI_MSG_OFFSET, len);
		}
		rc = mctp_message_pvt_bind_tx(ctx->mctp, eid,
					      MCTP_MESSAGE_TO_SRC, 0,
					      (uint8_t *)msg + MCTP_SPI_MSG_OFFSET, len,
					      NULL);

		break;
	case MCTP_BINDING_SMBUS:
		if (len <= min_packet_smbus) {
			mctp_prwarn("Packet too short for SMBUS, len = %zi, expected > %zi\n",
						len, min_packet_smbus);
			return;
		}

		/* Copy the binding information */
		memcpy(&pvt_binding.i2c, ((uint8_t *)msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_smbus_pkt_private));

		/* Get target EID */
		eid = *((uint8_t *)msg + MCTP_SMBUS_EID_OFFSET);

		/* Set MCTP payload size */
		len = len - min_packet_smbus;

		mctp_prdebug("Print msg: ");
		mctp_prdebug("Printing packet length, SMBUS binding: %zi", len);
		if (ctx->verbose) {
			mctp_print_hex((uint8_t *)msg + MCTP_SMBUS_MSG_OFFSET, len);
		}
		mctp_prdebug("\n");

		pvt_binding.i2c.i2c_bus = i2c_bus_num;
		pvt_binding.i2c.dest_slave_addr = i2c_dest_slave_addr;
		pvt_binding.i2c.src_slave_addr = i2c_src_slave_addr;

		rc = mctp_message_pvt_bind_tx(ctx->mctp, eid, MCTP_MESSAGE_TO_SRC, 0,
					      (uint8_t *)msg + MCTP_SMBUS_MSG_OFFSET, len,
					      (void *)&pvt_binding.i2c);

		if (ctx->verbose) {
			printf("%s: SMBUS EID: %d, Bus: %d, src-slave-addr: 0x%x, dest-slave-addr: 0x%x, len: %zu\n",
			       __func__, eid, pvt_binding.i2c.i2c_bus,
			       pvt_binding.i2c.src_slave_addr,
			       pvt_binding.i2c.dest_slave_addr, len);
		}
		if (rc) {
			warnx("Failed to send message: %d", rc);
		}
		break;
	
	case MCTP_BINDING_USB:

		if (len < min_packet_usb) {
			mctp_prwarn("Packet too short for USB.");
			return;
		}

		/* Copy the binding information */
		memcpy(&pvt_binding.usb, ((uint8_t *)msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_usb_pkt_private));
		
		/* Get target EID */
		eid = *((uint8_t *)msg + MCTP_USB_EID_OFFSET);

		/* Set MCTP payload size */
		len = len - (MCTP_USB_MSG_OFFSET)-1;

		rc = mctp_message_pvt_bind_tx(ctx->mctp, eid, MCTP_MESSAGE_TO_SRC, 0,
					      (uint8_t *)msg + MCTP_USB_MSG_OFFSET, len,
					      (void *)&pvt_binding.usb);
		if (rc) {
			warnx("Failed to send message: %d", rc);
		}


		break;

	default:
		warnx("Invalid/Unsupported binding ID %d", bind_id);
		mctp_print_hex((uint8_t *)msg, len);
		break;
	}
}

static void tx_message(struct ctx *ctx, uint8_t tag_owner_and_tag,
		       mctp_eid_t eid, void *msg, size_t len)
{
	int rc;

	rc = mctp_message_tx(ctx->mctp, eid,
			     (tag_owner_and_tag & LIBMCTP_TAG_OWNER_MASK),
			     (tag_owner_and_tag & LIBMCTP_TAG_MASK), msg, len);
	if (rc)
		warnx("Failed to send message: %d", rc);
}

static void client_remove_inactive(struct ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->n_clients; i++) {
		struct client *client = &ctx->clients[i];

		if (client->active)
			continue;

		close(client->sock);

		ctx->n_clients--;
		memmove(&ctx->clients[i], &ctx->clients[i + 1],
			(ctx->n_clients - i) * sizeof(*ctx->clients));
		ctx->clients = realloc(ctx->clients,
				       ctx->n_clients * sizeof(*ctx->clients));
	}
}

static void clean_all_clients(struct ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->n_clients; i++) {
		struct client *client = &ctx->clients[i];
		if (client->sock) {
			close(client->sock);
		}
	}

	free(ctx->clients);
	ctx->n_clients = 0;

	ctx->clients = NULL;
}

static void rx_message(uint8_t eid, bool tag_owner, uint8_t msg_tag, void *data,
		       void *msg, size_t len)
{
	struct ctx *ctx = data;
	struct iovec iov[2];
	struct msghdr msghdr;
	uint8_t type;
	int i, rc;
	uint8_t tag_eid[2] = {
		((tag_owner << 3) | (msg_tag & LIBMCTP_TAG_MASK)), eid
	};

	if (len < 2)
		return;

	type = *(uint8_t *)msg & 0x7F;

	if (ctx->verbose)
		fprintf(stderr, "MCTP message received: len %zd, type %d\n",
			len, type);

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 2;
	iov[0].iov_base = &tag_eid;
	iov[0].iov_len = 2;
	iov[1].iov_base = msg;
	iov[1].iov_len = len;

	for (i = 0; i < ctx->n_clients; i++) {
		struct client *client = &ctx->clients[i];

		if (ctx->verbose)
			fprintf(stderr, " %i client type: %hhu type: %hhu\n", i,
				client->type, type);

		if (client->type != type)
			continue;

		if (ctx->verbose)
			fprintf(stderr, "  forwarding to client %d\n", i);

		mctp_trace_common(">SOCK RX HDR>", &tag_eid, 2);
		mctp_trace_common(">SOCK RX>", msg, len);

		rc = sendmsg(client->sock, &msghdr, 0);
		/* EAGAIN shouldn't close socket. Otherwise,spi-ctrl daemon will fail 
		 * to communicate with demux due to socket close.
		 */
		if (errno != EAGAIN && rc != (ssize_t)(len + 2)) {
			client->active = false;
			ctx->clients_changed = true;
		}
	}
}

static int binding_null_init(struct mctp *mctp __unused,
			     struct binding *binding __unused,
			     mctp_eid_t eid __unused, int n_params,
			     char *const *params __unused)
{
	if (n_params != 0) {
		warnx("null binding doesn't accept parameters");
		return -1;
	}
	return 0;
}

static int binding_serial_init(struct mctp *mctp, struct binding *binding,
			       mctp_eid_t eid, int n_params,
			       char *const *params)
{
	struct mctp_binding_serial *serial;
	const char *path;
	int rc;

	if (n_params != 1) {
		warnx("serial binding requires device param");
		return -1;
	}

	path = params[0];

	serial = mctp_serial_init();
	MCTP_ASSERT_RET(serial != NULL, -1, "serial is NULL");

	rc = mctp_serial_open_path(serial, path);
	if (rc)
		return -1;

	mctp_register_bus(mctp, mctp_binding_serial_core(serial), eid);

	binding->data = serial;
	binding->bindings_changed = false;

	return 0;
}

static int binding_serial_init_pollfd(struct binding *binding,
				      struct pollfd **pollfd)
{
	return mctp_serial_init_pollfd(binding->data, pollfd);
}

static int binding_serial_process(struct binding *binding)
{
	return mctp_serial_read(binding->data);
}

static int binding_astlpc_init(struct mctp *mctp, struct binding *binding,
			       mctp_eid_t eid, int n_params,
			       char *const *params __attribute__((unused)))
{
	struct mctp_binding_astlpc *astlpc;

	if (n_params) {
		warnx("astlpc binding does not accept parameters");
		return -1;
	}

	astlpc = mctp_astlpc_init_fileio();
	if (!astlpc) {
		warnx("could not initialise astlpc binding");
		return -1;
	}

	mctp_register_bus(mctp, mctp_binding_astlpc_core(astlpc), eid);

	binding->data = astlpc;
	binding->bindings_changed = false;
	return 0;
}

static void binding_astlpc_destroy(struct mctp *mctp, struct binding *binding)
{
	struct mctp_binding_astlpc *astlpc = binding->data;

	mctp_unregister_bus(mctp, mctp_binding_astlpc_core(astlpc));

	mctp_astlpc_destroy(astlpc);
}

static int binding_astlpc_init_pollfd(struct binding *binding,
				      struct pollfd **pollfd)
{
	return mctp_astlpc_init_pollfd(binding->data, pollfd);
}

static int binding_astlpc_process(struct binding *binding)
{
	return mctp_astlpc_poll(binding->data);
}

static int binding_astpcie_init(struct mctp *mctp, struct binding *binding,
				mctp_eid_t eid, int n_params,
				char *const *params __attribute__((unused)))
{
	struct mctp_binding_astpcie *astpcie;

	if (n_params) {
		warnx("astpcie binding does not accept parameters");
		return -1;
	}

	astpcie = mctp_astpcie_init_fileio();
	if (!astpcie) {
		warnx("could not initialise astpcie binding");
		return -1;
	}

	mctp_register_bus(mctp, mctp_binding_astpcie_core(astpcie), eid);

	binding->data = astpcie;
	binding->bindings_changed = false;
	return 0;
}

static void binding_astpcie_destroy(
	struct mctp *mctp __attribute__((unused)), 
	struct binding *binding)
{
	struct mctp_binding_astpcie *astpcie = binding->data;

	mctp_astpcie_free(astpcie);
}

static int binding_astpcie_init_pollfd(struct binding *binding,
				       struct pollfd **pollfd)
{
	return mctp_astpcie_init_pollfd(binding->data, pollfd);
}

static int binding_astpcie_process(struct binding *binding)
{
	int rc;

	rc = mctp_astpcie_poll(binding->data, MCTP_ASTPCIE_POLL_TIMEOUT);
	if (rc & POLLIN) {
		rc = mctp_astpcie_rx(binding->data);
		MCTP_ASSERT_RET(rc == 0, rc, "mctp_astpcie_rx returned %d", rc);
	}

	return rc;
}

static void binding_astspi_usage(void)
{
	fprintf(stderr,
		"Usage: astspi\n"
		"\tgpio=<line num> - GPIO line num to monitor\n"
		"\tdevice=<dev num> - SPI device to open\n"
		"\tchannel=<chan num> - SPI channel to open\n"
		"\tmode=<mode num> - SPI mode (default: 0)\n"
		"\tdisablecs=<0|1> - enable / disable CS (default: 0)\n"
		"\tsinglemode=<0|1> - enable / disable single mode (default: 0)\n");

	fprintf(stderr, "Example: astpspi gpio=11 disablecs=1\n");
}

static int binding_astspi_init(struct mctp *mctp, struct binding *binding,
			       mctp_eid_t eid, int n_params,
			       char *const *params)
{
	struct mctp_binding_spi *astspi;
	struct mctp_astspi_device_conf config = {
		.gpio = SPB_GPIO_INTR_NUM,
		.dev = AST_MCTP_SPI_DEV_NUM,
		.channel = AST_MCTP_SPI_CHANNEL_NUM,
		.mode = 0,
		.disablecs = 0,
		.singlemode = 0,
	};
	struct {
		char *prefix;
		void *target;
	} options[] = {
		{ "gpio=", &config.gpio },
		{ "device=", &config.dev },
		{ "channel=", &config.channel },
		{ "mode=", &config.mode },
		{ "disablecs=", &config.disablecs },
		{ "singlemode=", &config.singlemode },
		{ NULL, NULL },
	};
	binding->bindings_changed = false;

	for (int ii = 0; ii < n_params; ii++) {
		bool parsed = false;

		for (int jj = 0; options[jj].prefix != NULL; jj++) {
			const char *prefix = options[jj].prefix;
			const size_t len = strlen(prefix);

			if (strncmp(params[ii], prefix, len) == 0) {
				int val = 0;
				char *arg = strstr(params[ii], "=") + 1;
				val = (int)strtoimax(arg, NULL, 10);
				*(int *)options[jj].target = val;
				parsed = true;
			}
		}

		if (!parsed) {
			binding_astspi_usage();
			exit(1);
		}
	}

	astspi = mctp_spi_bind_init(&config);
	MCTP_ASSERT_RET(astspi != NULL, -1, "mctp_spi_bind_init failed.");

	mctp_register_bus(mctp, mctp_binding_astspi_core(astspi), eid);
	binding->data = astspi;

	return (0);
}

static int binding_astspi_init_pollfd(struct binding *binding,
				      struct pollfd **pollfd)
{
	struct mctp_binding_spi *astspi = binding->data;

	return (mctp_spi_init_pollfd(astspi, pollfd));
}

static int binding_astspi_process(struct binding *binding)
{
	struct mctp_binding_spi *astspi = binding->data;

	/*
	 * We got interrupt on GPIO line. There may be several
	 * reasons we got it, one of them is request to process
	 * incoming data from remote device. Let's keep all
	 * internal details within astspi implementation.
	 */
	return (mctp_spi_process(astspi));
}

static void binding_smbus_usage(void)
{
	fprintf(stderr,
		"Usage: smbus (use dec or hex value)\n"
		"\ti2c_bus=<bus num>              - i2c bus to use\n"
		"\ti2c_config_file=<config.json>  - i2c json config file\n"
		"\ti2c_dest_addr=<7-bit addr num> - i2c destination slave address to use\n"
		"\ti2c_src_addr=<7-bit addr num>  - i2c source slave address to use\n");

	fprintf(stderr, "Example: smbus i2c_bus=2 i2c_dest_addr=0x30 i2c_src_addr=0x18\n"
					"     or: smbus i2c_bus=2 i2c_dest_addr=48 i2c_src_addr=24\n");
}

static void binding_smbus_use_default_config(void)
{
	i2c_bus_num = MCTP_I2C_BUS_NUM_DEFAULT;
	i2c_dest_slave_addr = MCTP_I2C_DEST_SLAVE_ADDR_DEFAULT;
	i2c_src_slave_addr = MCTP_I2C_SRC_SLAVE_ADDR_DEFAULT;

	mctp_prinfo("Used default configuration. Discovery endpoint via FPGA (dec. val.):");
	mctp_prinfo("i2c bus num = %d, i2c dest addr = %d, i2c src addr = %d",
	        i2c_bus_num, i2c_dest_slave_addr, i2c_src_slave_addr);
}

static void fix_muxed_bus_numbers()
{
	for (uint8_t k = 0; k < smbus_static_endpoints_len; ++k) {
		mctp_prdebug("Mux addr: %d, Mux channel: %d\n",
			     smbus_static_endpoints[k].mux_addr,
			     smbus_static_endpoints[k].mux_channel);
		if (smbus_static_endpoints[k].mux_addr == 0xFF ||
		    smbus_static_endpoints[k].mux_channel == 0xFF) {
			continue;
		}

		char top_dir_name[255] = { 0 };
		snprintf(top_dir_name, sizeof(top_dir_name),
			 "%s%d/%d-00%x/channel-%d/i2c-dev",
			 "/sys/bus/i2c/devices/i2c-", i2c_bus_num, i2c_bus_num,
			 smbus_static_endpoints[k].mux_addr,
			 smbus_static_endpoints[k].mux_channel);
		mctp_prdebug("Scanning directory: %s\n", top_dir_name);
		DIR *dir = opendir(top_dir_name);

		if (!dir) {
			mctp_prerr("Failed to open dir: %s\n", top_dir_name);
			return;
		}

		struct dirent *entry = NULL;
		while ((entry = readdir(dir)) != NULL) {
			mctp_prdebug("Found entry: %s\n", entry->d_name);
			if (strncmp(entry->d_name, "i2c-",
				    sizeof("i2c-") - 1)) {
				continue;
			}
			/* Extract the bus number */
			intmax_t bus_num = strtoimax(
				(entry->d_name + sizeof("i2c-") - 1), NULL, 10);

			mctp_prdebug("Got bus number: %d\n", (int)bus_num);
			smbus_static_endpoints[k].bus_num = bus_num;
		}
		closedir(dir);
	}
}

static void parse_joson_config(
	char *config_json_file_path, 
	struct binding *binding,
	mctp_eid_t *eid)
{
	json_object *parsed_json;
	int rc;

	rc = mctp_json_get_tokener_parse(&parsed_json, 
			config_json_file_path);

	if (rc == EXIT_FAILURE) {
		mctp_prinfo(
			"Use default config, JSON parsing failed\n");
		binding_smbus_use_default_config();
		return;
	}

	// Get common parameters
	mctp_json_i2c_get_common_params_mctp_demux(parsed_json,
		&i2c_bus_num, &i2c_bus_num_smq, &i2c_src_slave_addr,
		&binding->sockname);
	if (binding->sockname == NULL) {
		mctp_prerr("Get null socket name");
		return;
	} else if (binding->sockname[0] == '\0') {
		mctp_prdebug("Chosen socket path unix: %s\n",
				&(binding->sockname[1]));
	} else {
		mctp_prdebug("Chosen socket path: %s\n",
				binding->sockname);
	}

	i2c_bus_num_smq = i2c_bus_num;

	// Get info about eid_type
	chosen_eid_type =
		mctp_json_get_eid_type(parsed_json,
						binding->name,
						&i2c_bus_num);

	mctp_prdebug("Chosen EID type: %d\n",
				chosen_eid_type);

	switch (chosen_eid_type) {
		case EID_TYPE_BRIDGE:
			mctp_prinfo("Use bridge endpoint\n");
			rc = mctp_json_i2c_get_params_bridge_static_demux(
				parsed_json, &i2c_bus_num,
				&i2c_dest_slave_addr, eid);

			if (rc == EXIT_FAILURE)
				binding_smbus_use_default_config();

			break;

		case EID_TYPE_STATIC:
			mctp_prinfo("Use static endpoint\n");
			smbus_static_endpoints = malloc(
				MCTP_I2C_MAX_BUSES *
				sizeof(struct mctp_static_endpoint_mapper));
			memset(smbus_static_endpoints, 0xFF,
					MCTP_I2C_MAX_BUSES *
						sizeof(struct mctp_static_endpoint_mapper));
			smbus_static_endpoints_len =
				MCTP_I2C_MAX_BUSES;
			rc = mctp_json_i2c_get_params_bridge_static_demux(
				parsed_json, &i2c_bus_num,
				&i2c_dest_slave_addr, eid);
			smbus_static_endpoints[0].slave_address =
				i2c_dest_slave_addr;

			if (rc == EXIT_FAILURE)
				binding_smbus_use_default_config();

			rc = mctp_json_i2c_get_params_static_demux(
				parsed_json, &i2c_bus_num,
				smbus_static_endpoints);

			break;

		case EID_TYPE_POOL:
			mctp_prinfo("Use pool endpoints\n");

			rc = mctp_json_i2c_get_params_pool_demux(
				parsed_json, &i2c_bus_num,
				&smbus_static_endpoints,
				&smbus_static_endpoints_len);

			if (rc == EXIT_FAILURE) {
				mctp_prerr(
					"Get params for pool failed!");
				binding_smbus_use_default_config();
			}

			break;

		default:
			break;
	}

	// free parsed json object
	json_object_put(parsed_json);
}

static int binding_smbus_init(struct mctp *mctp, struct binding *binding,
			      mctp_eid_t eid, int n_params,
			      char *const *params __attribute__((unused)))
{
	struct mctp_binding_smbus *smbus;

	struct {
		char *prefix;
		void *target;
	} options[] = {
		{ "i2c_bus=", &i2c_bus_num },
		{ "i2c_config_file=", NULL},
		{ "i2c_dest_addr=", &i2c_dest_slave_addr },
		{ "i2c_src_addr=", &i2c_src_slave_addr},
		{ NULL, NULL },
	};
	binding->bindings_changed = false;

	char *config_json_file_path = NULL;

	if (n_params != 0) {
		for (int ii = 0; ii < n_params; ii++) {
			bool parsed = false;

			for (int jj = 0; options[jj].prefix != NULL; jj++) {
				const char *prefix = options[jj].prefix;
				const size_t len = strlen(prefix);

				if (strncmp(params[ii], prefix, len) == 0) {
					int val = 0;
					char *arg = strstr(params[ii], "=") + 1;	// Get string after "="

					/* Check if path or values are given */
					if (strncmp(params[ii],
						    options[1].prefix,
						    strlen(options[1].prefix)) ==
						    0) {
						if (config_json_file_path == NULL) {
							config_json_file_path = malloc(strlen(arg) + 1);
							memcpy(config_json_file_path, arg, (strlen(arg) + 1));
						}
					} else {
						/* Check if a value is given in 'hex' or 'dec' */
						if (strncmp(arg, "0x", 2) == 0)
							val = strtoul(arg, NULL, 16);
						else
							val = (int)strtoimax(arg, NULL, 10);

						*(uint8_t *)options[jj].target = val;
					}

					parsed = true;
				}
			}

			/* Exit only if a passed parameter is not supported */
			if (!parsed) {
				mctp_prinfo("[%s] Unsupported param = %s\n", __func__, params[ii]);
				binding_smbus_usage();
				if (config_json_file_path != NULL) {
					free(config_json_file_path);
				}
				return -1;
			}
		}
	}
	else {
		mctp_prinfo("[%s] Using default config .. no params\n", __func__);
		binding_smbus_use_default_config();
	}

	if (config_json_file_path != NULL) {
		parse_joson_config(config_json_file_path, binding, &eid);
		free(config_json_file_path);
	} 
	
	if (smbus_static_endpoints_len == 0) {
		/* Set one default static endpoint - bridge one */
		mctp_prinfo("[%s] Using predefined static endpoint .. no proper config file\n", __func__);
		smbus_static_endpoints = malloc(sizeof(struct mctp_static_endpoint_mapper));
		memset(smbus_static_endpoints, 0xFF,
				sizeof(struct mctp_static_endpoint_mapper));
		smbus_static_endpoints[0].endpoint_num = 13;
		smbus_static_endpoints[0].bus_num = i2c_bus_num;
		smbus_static_endpoints[0].slave_address = i2c_dest_slave_addr;
		smbus_static_endpoints_len = 1;
	}

	/* Bus numbers for muxed busses can be dynamic, fix them if needed */
	fix_muxed_bus_numbers();

	mctp_prdebug("No of endpoints to handle: %d\n", smbus_static_endpoints_len);
	for (uint8_t i = 0; i < smbus_static_endpoints_len; ++i) {
		mctp_prdebug("Endpoint: bus: %d, addr: %d, eid: %d\n",
				 smbus_static_endpoints[0].endpoint_num,
			     smbus_static_endpoints[i].bus_num,
			     smbus_static_endpoints[i].slave_address);
	}

	smbus = mctp_smbus_init(i2c_bus_num, i2c_bus_num_smq,
				i2c_dest_slave_addr, i2c_src_slave_addr,
				smbus_static_endpoints_len, smbus_static_endpoints);
	MCTP_ASSERT_RET(smbus != NULL, -1,
			"could not initialise smbus binding");

	mctp_register_bus(mctp, mctp_binding_smbus_core(smbus), eid);

	binding->data = smbus;
	return 0;
}

static int binding_smbus_init_pollfd(struct binding *binding,
				  struct pollfd **pollfd)
{
	return mctp_smbus_init_pollfd(binding->data, pollfd);
}

static int binding_smbus_process(struct binding *binding)
{
	int rc;

	rc = mctp_smbus_poll(binding->data, MCTP_SMBUS_POLL_TIMEOUT);
	if (rc & POLLPRI) {
		rc = mctp_smbus_read(binding->data);
		MCTP_ASSERT_RET(rc == 0, rc, "mctp_smbus_read failed: %d", rc);
	}
	return 0;
}

#ifdef ENABLE_USB

static void binding_usb_usage(void)
{
	fprintf(stderr,
		"Usage: usb (use dec or hex value)\n"
		"\tvendor_id=<vendor id> - usb vendor id to filter\n"
		"\tproduct_id=<product id> - usb product id to filter\n"
		"\tclass_id=<class id> - usb class id to filter\n");

	fprintf(stderr, "Example: usb vendor_id=0x0483 product_id=0xffff class_id=0x00\n");
}

static int binding_usb_init(struct mctp *mctp, struct binding *binding,
			      mctp_eid_t eid, int n_params,
			      char *const *params __attribute__((unused)))
{
	struct mctp_binding_usb *usb;
	uint16_t vendor_id;
	uint16_t product_id;
	uint16_t class_id;
	struct {
		char *prefix;
		void *target;
	} options[] = {
		{ "vendor_id=", &vendor_id },
		{ "product_id=", &product_id},
		{ "class_id=", &class_id },
		{ NULL, NULL },
	};
	binding->bindings_changed = false;

	if(n_params != 0) {
		for (int ii = 0; ii < n_params; ii++) {
			bool parsed = false;

			for (int jj = 0; options[jj].prefix != NULL; jj++) {
				const char *prefix = options[jj].prefix;
				const size_t len = strlen(prefix);

				if (strncmp(params[ii], prefix, len) == 0) {
					int val = 0;
					char *arg = strstr(params[ii], "=") + 1;	// Get string after "="

					/* Check if a value is given in 'hex' or 'dec' */
					if (strncmp(arg, "0x", 2) == 0)
						val = strtoul(arg, NULL, 16);
					else
						val = (int)strtoimax(arg, NULL,
								     10);

					*(uint16_t *)options[jj].target =
						val;

					parsed = true;
				}
			}

			if (!parsed) {
				binding_usb_usage();
				exit(1);
			}
		}
	}
	else {
		mctp_prinfo("Using default config .. no params\n");
	}

	usb = mctp_usb_init(vendor_id, product_id, class_id);

	MCTP_ASSERT_RET(usb != NULL, -1,"could not initialise usb binding");
	mctp_prinfo("registering bus");

	mctp_register_bus(mctp, mctp_binding_usb_core(usb), eid);

	binding->data = usb;
	return 0;
}

static int binding_usb_init_pollfd(struct binding *binding,
				  struct pollfd **pollfds)
{
	return mctp_usb_init_pollfd(binding->data, pollfds);
}

static int binding_usb_process(struct binding *binding)
{
	int rc;

	rc = mctp_usb_handle_event(binding->data);
	if(rc == MCTP_USB_FD_CHANGE) {
		binding->bindings_changed = true;
	}
	return rc;
}

#endif

struct binding bindings[] = { {
				      .name = "null",
				      .init = binding_null_init,
			      },
			      {
				      .name = "serial",
				      .init = binding_serial_init,
				      .destroy = NULL,
				      .init_pollfd = binding_serial_init_pollfd,
				      .process = binding_serial_process,
				      .sockname = "\0mctp-serial-mux",
			      },
			      {
				      .name = "astlpc",
				      .init = binding_astlpc_init,
				      .destroy = binding_astlpc_destroy,
				      .init_pollfd = binding_astlpc_init_pollfd,
				      .process = binding_astlpc_process,
				      .sockname = "\0mctp-lpc-mux",
			      },
			      {
				      .name = "astpcie",
				      .init = binding_astpcie_init,
				      .destroy = binding_astpcie_destroy,
				      .init_pollfd =
					      binding_astpcie_init_pollfd,
				      .process = binding_astpcie_process,
				      .sockname = "\0mctp-pcie-mux",
			      },
			      {
				      .name = "astspi",
				      .init = binding_astspi_init,
				      .destroy = NULL,
				      .init_pollfd = binding_astspi_init_pollfd,
				      .process = binding_astspi_process,
				      .sockname = "\0mctp-spi-mux",
			      },
			      {
				      .name = "smbus",
				      .init = binding_smbus_init,
				      .destroy = NULL,
				      .init_pollfd = binding_smbus_init_pollfd,
				      .process = binding_smbus_process,
				      .sockname = "\0mctp-i2c-mux",
			      },

				  #ifdef ENABLE_USB
				  {
				      .name = "usb",
				      .init = binding_usb_init,
				      .destroy = NULL,
				      .init_pollfd = binding_usb_init_pollfd,
				      .process = binding_usb_process,
				      .sockname = "\0mctp-usb-mux",
			      } 
				  #endif
				  };

struct binding *binding_lookup(const char *name)
{
	struct binding *binding;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bindings); i++) {
		binding = &bindings[i];

		if (!strcmp(binding->name, name))
			return binding;
	}

	return NULL;
}

static int socket_init(struct ctx *ctx)
{
	struct sockaddr_un addr;
	int namelen, rc;

	memset(&addr, 0, sizeof(addr));

	if (ctx->binding->sockname[0] == '\0') {
		namelen = 1 + strlen(ctx->binding->sockname + 1);
	} else {
		namelen = strlen(ctx->binding->sockname);
	}

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, ctx->binding->sockname, namelen);

	ctx->sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (ctx->sock < 0) {
		warn("can't create socket");
		return -1;
	}

	rc = bind(ctx->sock, (struct sockaddr *)&addr,
		  sizeof(addr.sun_family) + namelen);
	if (rc) {
		warn("can't bind socket");
		goto err_close;
	}

	rc = listen(ctx->sock, 1);
	if (rc) {
		warn("can't listen on socket");
		goto err_close;
	}
	return 0;

err_close:
	close(ctx->sock);
	return -1;
}

static int socket_process(struct ctx *ctx)
{
	struct client *client;
	int fd;

	fd = accept4(ctx->sock, NULL, 0, SOCK_NONBLOCK);
	if (fd < 0)
		return -1;

	ctx->n_clients++;
	ctx->clients =
		realloc(ctx->clients, ctx->n_clients * sizeof(struct client));

	client = &ctx->clients[ctx->n_clients - 1];
	memset(client, 0, sizeof(*client));
	client->active = true;
	client->sock = fd;

	/* Reset client type to 0xff as type-0 is for MCTP ctrl */
	client->type = 0xff;

	return 0;
}

static int client_process_recv(struct ctx *ctx, int idx)
{
	struct client *client = &ctx->clients[idx];
	uint8_t eid;
	ssize_t len;
	int rc;

	/* are we waiting for a type message? */
	if (client->type == 0xff) {
		uint8_t type;
		rc = read(client->sock, &type, 1);
		if (rc <= 0) {
			mctp_prdebug("[%s] Error on reading one byte from socket: %d (errno = %d, %s)",
				__func__, rc, errno, strerror(errno));
			goto out_close;
		}

		if (ctx->verbose)
			fprintf(stderr, "[%s] client[%d] registered for type %u",
				__func__, idx, type);

		mctp_prdebug("[%s] Set client %d type to %u\n", __func__, idx, type);
		client->type = type;
		return 0;
	}

	len = recv(client->sock, NULL, 0, MSG_PEEK | MSG_TRUNC);
	if (len < 0) {
		if (errno != ECONNRESET)
			warn("can't receive (peek) from client");

		rc = -1;
		goto out_close;
	}

	if ((size_t)len > ctx->buf_size) {
		void *tmp;

		tmp = realloc(ctx->buf, len);
		if (!tmp) {
			warn("can't allocate for incoming message");
			rc = -1;
			goto out_close;
		}
		ctx->buf = tmp;
		ctx->buf_size = len;
	}

	rc = recv(client->sock, ctx->buf, ctx->buf_size, 0);
	if (rc < 0) {
		mctp_prerr("recv(2) failed: %d", rc);
		if (errno != ECONNRESET)
			warn("can't receive from client");
		rc = -1;
		goto out_close;
	}

	if (rc <= 0) {
		rc = -1;
		goto out_close;
	}

	/* Need a special handling for MCTP-Ctrl type
	 * as it will use different packet formatting as mentioned
	 * below:
	 * PKT-FORMAT:
	 *          [MCTP-BIND-ID]
	 *          [MCTP-PVT-BIND-INFO]
	 *          [MCTP-MSG-HDR]
	 *          [MCTP-MSG]
	 */
	if (client->type == MCTP_MESSAGE_TYPE_MCTP_CTRL) {
		tx_pvt_message(ctx, ctx->buf, rc);
		return 0;
	}

	if (ctx->pcap.socket.path)
		capture_socket(ctx->pcap.socket.dumper, ctx->buf, rc);

	mctp_trace_common("<SOCK TX<", ctx->buf, len);
	eid = *((uint8_t *)ctx->buf + 1);

	if (ctx->verbose)
		fprintf(stderr, "client[%d] sent message: dest 0x%02x len %d\n",
			idx, eid, rc - 2);

	if (eid == ctx->local_eid)
		rx_message(eid, MCTP_MESSAGE_TO_DST, 0, ctx,
			   (uint8_t *)ctx->buf + 2, rc - 2);
	else
		tx_message(ctx, *((uint8_t *)ctx->buf), eid,
			   (uint8_t *)ctx->buf + 2, rc - 2);

	return 0;

out_close:
	client->active = false;
	return rc;
}

static int binding_init(struct ctx *ctx, const char *name, int argc,
			char *const *argv)
{
	int rc;

	ctx->binding = binding_lookup(name);
	if (!ctx->binding) {
		warnx("no such binding '%s'", name);
		return -1;
	}

	rc = ctx->binding->init(ctx->mctp, ctx->binding, ctx->local_eid, argc,
				argv);
	return rc;
}

static void binding_destroy(struct ctx *ctx)
{
	if (ctx->binding->destroy)
		ctx->binding->destroy(ctx->mctp, ctx->binding);
}

enum {
	FD_SOCKET = 0,
	FD_SIGNAL,
	FD_TIMER,
	FD_NR,
	/*
		FD for binding will be dynamically allocate here.
	*/
	/*
		FD for clients unix socket application will be dynamically allocate here.
	*/
};

static int run_daemon(struct ctx *ctx)
{
	sigset_t mask;
	int rc, i;
	struct itimerspec timer;

	ctx->pollfds = malloc(FD_NR * sizeof(struct pollfd));

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);

	if ((rc = sigprocmask(SIG_BLOCK, &mask, NULL)) == -1) {
		warn("sigprocmask");
		return rc;
	}

	ctx->pollfds[FD_SIGNAL].fd = signalfd(-1, &mask, 0);
	ctx->pollfds[FD_SIGNAL].events = POLLIN;

	ctx->pollfds[FD_TIMER].fd = timerfd_create(CLOCK_MONOTONIC, 0);
	ctx->pollfds[FD_TIMER].events = POLLIN;

	timer.it_value.tv_sec = 5;
	timer.it_value.tv_nsec = 0;
	timer.it_interval.tv_sec = 5;
	timer.it_interval.tv_nsec = 0;

	if (timerfd_settime(ctx->pollfds[FD_TIMER].fd, 0, &timer, NULL) == -1) {
		warn("Failed to set time on watchdog timer FD!");
		return -1;
	}

	ctx->pollfds[FD_SOCKET].fd = ctx->sock;
	ctx->pollfds[FD_SOCKET].events = POLLIN;

	ctx->clients_changed = false;

	mctp_set_rx_all(ctx->mctp, rx_message, ctx);

	if (chosen_eid_type == EID_TYPE_STATIC) {
		check_device_supports_mctp(ctx->binding->data);
	} else if (chosen_eid_type == EID_TYPE_POOL) {
		find_and_set_pool_of_endpoints(ctx->binding->data);

		int j, k;
		for (j = 0; j < smbus_static_endpoints_len; j++) {
			if (smbus_static_endpoints[j].bus_num == 0xFF) {
				continue;
			}
			mctp_prdebug("\n%s: Static endpoint Pool", __func__);
			mctp_prdebug("Endpoint = %d", smbus_static_endpoints[j].endpoint_num);
			mctp_prdebug("Slave address = 0x%x", smbus_static_endpoints[j].slave_address);
			mctp_prdebug("Support MCTP = %d", smbus_static_endpoints[j].support_mctp);
			mctp_prdebug("UDID = ");
			for (k = 0; k < 16; k++) {
				mctp_prdebug("0x%x ", smbus_static_endpoints[j].udid[k]);
			}
		}
	}

	struct pollfd *bindingfds;
	if (ctx->binding->init_pollfd) {
		ctx->n_bindings = ctx->binding->init_pollfd(ctx->binding,
			&bindingfds);
		if(ctx->n_bindings > 0) {
			ctx->pollfds = realloc(ctx->pollfds,
							(ctx->n_bindings + FD_NR) *
								sizeof(struct pollfd));
			memcpy(&ctx->pollfds[FD_NR], bindingfds, ctx->n_bindings * sizeof(struct pollfd));
		}
	}

	for (;;) {
		if (ctx->clients_changed) {
			int i;

			ctx->pollfds = realloc(ctx->pollfds,
					       (ctx->n_bindings + ctx->n_clients + FD_NR) *
						       sizeof(struct pollfd));

			for (i = 0; i < ctx->n_clients; i++) {
				ctx->pollfds[ctx->n_bindings + FD_NR + i].fd =
					ctx->clients[i].sock;
				ctx->pollfds[ctx->n_bindings + FD_NR + i].events = POLLIN;
			}
			ctx->clients_changed = false;
		}

		if(ctx->binding->bindings_changed) {
			ctx->binding->bindings_changed = false;
			struct pollfd *bindingfds;
			if (ctx->binding->init_pollfd) {
				int fds_size = ctx->binding->init_pollfd(ctx->binding,
									&bindingfds);
				if(fds_size == ctx->n_bindings) {
					for(int i = 0; i < fds_size; i++) {
						ctx->pollfds[FD_NR + i] = bindingfds[i];
					}
				}
				else {
					/*At present, we assume that the size of the binding fds is not changed, just the content changed*/
					mctp_prerr("Number of bindings changed. Original: %d, New Initialized: %d", ctx->n_bindings, fds_size );
				}
			}
		}

		rc = poll(ctx->pollfds, ctx->n_bindings + ctx->n_clients + FD_NR, -1);
		if (rc < 0) {
			warn("poll failed");
			break;
		}

		if (!rc)
			continue;

		if (ctx->pollfds[FD_SIGNAL].revents) {
			struct signalfd_siginfo si;
			ssize_t got;

			got = read(ctx->pollfds[FD_SIGNAL].fd, &si, sizeof(si));
			if (got == sizeof(si)) {
				warnx("Received %s, quitting\n",
				      strsignal(si.ssi_signo));
				rc = 0;
				break;
			} else {
				warnx("Unexpected read result for signalfd: %d\n",
				      rc);
				warnx("Quitting on the basis that signalfd became ready\n");
				rc = -1;
				break;
			}
		}

		if (ctx->pollfds[FD_TIMER].revents) {
			uint64_t ign = 0;
			if (sizeof(ign) != read(ctx->pollfds[FD_TIMER].fd, &ign,
						sizeof(ign))) {
				warnx("Bad size read from timer FD!");
				/* No need to quit here */
			}
			sd_notify(0, "WATCHDOG=1");
		}

		for (i = 0; i < ctx->n_bindings; i++) {
			if (ctx->pollfds[FD_NR + i].revents) {
				rc = 0;
				if (ctx->binding->process)
					rc = ctx->binding->process(ctx->binding);
				if (rc)
					break;
			}
		}
		//Question: Where are we resetting revents?
		for (i = 0; i < ctx->n_clients; i++) {
			int fds_number = ctx->n_bindings + FD_NR + i;
			if (!ctx->pollfds[fds_number].revents)
				continue;

			if ((ctx->pollfds[fds_number].revents & POLLHUP) ||
				(ctx->pollfds[fds_number].revents & POLLERR)) {
				/* Manage disconnection case - this client is not active anymore */
				mctp_prinfo("\n%s: Client %d was disconnected, events = 0x%04x", 
					__func__, i, ctx->pollfds[fds_number].revents);
				ctx->clients[i].active = false;
				ctx->clients_changed = true;
			}
			else if (ctx->pollfds[fds_number].revents & POLLIN) {
				rc = client_process_recv(ctx, i);
				if (rc)
					ctx->clients_changed = true;
			}
			else {
				warnx("%s: Received unsupported event 0x%04x from client %d", 
					__func__, ctx->pollfds[fds_number].revents, i);
			}
		}

		if (ctx->pollfds[FD_SOCKET].revents) {
			rc = socket_process(ctx);
			if (rc)
				break;
			ctx->clients_changed = true;
		}

		if (ctx->clients_changed)
			client_remove_inactive(ctx);
	}

	clean_all_clients(ctx);
	
	free(ctx->pollfds);
	if (smbus_static_endpoints != NULL) {
		free(smbus_static_endpoints);
	}

	return rc;
}

static const struct option options[] = {
	{ "capture-binding", required_argument, 0, 'b' },
	{ "capture-socket", required_argument, 0, 's' },
	{ "binding-linktype", required_argument, 0, 'B' },
	{ "socket-linktype", required_argument, 0, 'S' },
	{ "verbose", no_argument, 0, 'v' },
	{ "eid", required_argument, 0, 'e' },
	{ "help", no_argument, 0, 'h' },
	{ 0 },
};

/* MCTP-DEMUX-DAEMON usage function */
static void exact_usage(void)
{
	fprintf(stderr, "Various command line options mentioned below\n");
	fprintf(stderr, "\t-v\tVerbose level\n");
	fprintf(stderr, "\t-e\tTarget Endpoint Id\n\n");

	fprintf(stderr, "SMBus commands\n");
	fprintf(stderr, "\ti2c_bus\tI2C Bus\n");
	fprintf(stderr, "\ti2c_dest_addr\tDestination Slave Address (7-bit)\n");
	fprintf(stderr, "\ti2c_src_addr\tSource Slave Address (7-bit)\n");
	fprintf(stderr, "Example of use:\n");
	fprintf(stderr, "With default parameters (i2c_bus = 2, i2c_dest_addr = 0x30, i2c_src_addr = 0x18):\n");
	fprintf(stderr, "\tmctp-demux-daemon smbus (--v)\n");
	fprintf(stderr, "With custom parameters\n");
	fprintf(stderr, "\tmctp-demux-daemon smbus i2c_bus=2 i2c_dest_addr=0x30 i2c_src_addr=0x18 (--v)\n");
}

static void usage(const char *progname)
{
	unsigned int i;

	fprintf(stderr, "usage: %s <binding> [params]\n", progname);
	fprintf(stderr, "Available bindings:\n");
	for (i = 0; i < ARRAY_SIZE(bindings); i++)
		fprintf(stderr, "  %s\n", bindings[i].name);
}

int main(int argc, char *const *argv)
{
	struct ctx *ctx = NULL, _ctx = {0};
	int rc;
	ctx = &_ctx;
	ctx->clients = NULL;
	ctx->n_clients = 0;
	ctx->n_bindings = 0;
	ctx->local_eid = local_eid_default;
	ctx->verbose = false;
	ctx->pcap.binding.path = NULL;
	ctx->pcap.binding.dumper = NULL;
	ctx->pcap.binding.linktype = -1;
	ctx->pcap.socket.path = NULL;
	ctx->pcap.socket.linktype = -1;

	mctp_prinfo("MCTP demux started.");

	for (;;) {
		rc = getopt_long(argc, argv, "b:e:s::vh", options, NULL);
		if (rc == -1)
			break;
		switch (rc) {
		case 'b':
			ctx->pcap.binding.path = optarg;
			break;
		case 's':
			ctx->pcap.socket.path = optarg;
			break;
		case 'B':
			ctx->pcap.binding.linktype = atoi(optarg);
			break;
		case 'S':
			ctx->pcap.socket.linktype = atoi(optarg);
			break;
		case 'v':
			ctx->verbose = true;
			break;
		case 'e':
			ctx->local_eid = atoi(optarg);
			break;
		case 'h':
			exact_usage();
			rc = EXIT_SUCCESS;
			goto initialize_exit;
		default:
			fprintf(stderr, "Invalid argument\n");
			rc = EXIT_FAILURE;
			goto initialize_exit;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "missing binding argument\n");
		usage(argv[0]);
		rc = EXIT_FAILURE;
		goto initialize_exit;
	}

	if (ctx->pcap.binding.linktype < 0 && ctx->pcap.binding.path) {
		fprintf(stderr, "missing binding-linktype argument\n");
		usage(argv[0]);
		rc = EXIT_FAILURE;
		goto initialize_exit;
	}

	if (ctx->pcap.socket.linktype < 0 && ctx->pcap.socket.path) {
		fprintf(stderr, "missing socket-linktype argument\n");
		usage(argv[0]);
		rc = EXIT_FAILURE;
		goto initialize_exit;
	}

	mctp_set_log_stdio(ctx->verbose ? MCTP_LOG_DEBUG : MCTP_LOG_WARNING);
	mctp_set_tracing_enabled(true);

	rc = sd_notifyf(0, "STATUS=Initializing MCTP.\nMAINPID=%d", getpid());
	if (rc < 0) {
		fprintf(stderr, "[%s] Could not notify systemd: %d\n",
			__func__, rc);
		rc = EXIT_FAILURE;
		goto initialize_exit;
	}

	ctx->mctp = mctp_init();
	if (ctx->mctp == NULL) {
		fprintf(stderr, "[%s] ctx->mctp is NULL\n", __func__);
		rc = EXIT_FAILURE;
		goto initialize_exit;
	}

	if (ctx->pcap.binding.path || ctx->pcap.socket.path) {
		if (capture_init()) {
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}
	}

	if (ctx->pcap.binding.path) {
		rc = capture_prepare(&ctx->pcap.binding);
		if (rc == -1) {
			fprintf(stderr, "Failed to initialise capture: %d\n",
				rc);
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}

		mctp_set_capture_handler(ctx->mctp, capture_binding,
					 ctx->pcap.binding.dumper);
	}

	if (ctx->pcap.socket.path) {
		rc = capture_prepare(&ctx->pcap.socket);
		if (rc == -1) {
			fprintf(stderr, "Failed to initialise capture: %d\n",
				rc);
			rc = EXIT_FAILURE;
			goto cleanup_pcap_binding;
		}
	}

	rc = sd_notify(0, "STATUS=Initializing binding.");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	rc = binding_init(ctx, argv[optind], argc - optind - 1,
			  argv + optind + 1);

	mctp_prdebug("Binding init returned: %d.", rc);
	if (rc) {
		fprintf(stderr, "Failed to initialise binding: %d\n", rc);
		rc = EXIT_FAILURE;
		goto cleanup_pcap_binding;
	}

	rc = sd_notify(0, "STATUS=Creating sockets.");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	rc = sd_listen_fds(true);
	if (rc <= 0) {
		rc = socket_init(ctx);
		if (rc) {
			fprintf(stderr, "Failed to initialse socket: %d\n", rc);
			goto cleanup_binding;
		}
	} else {
		ctx->sock = SD_LISTEN_FDS_START;
	}

	rc = sd_notify(0, "STATUS=Daemon is running.\nREADY=1");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	/* setup initial buffer */
	ctx->buf_size = 4096;
	ctx->buf = malloc(ctx->buf_size);

	rc = run_daemon(ctx);

	if (ctx->buf != NULL) {
		free(ctx->buf);
	}

cleanup_binding:
	binding_destroy(ctx);

/* KSJXXX: Unused label? cleanup_pcap_socket: */
	if (ctx->pcap.socket.path)
		capture_close(&ctx->pcap.socket);

cleanup_pcap_binding:
	if (ctx->pcap.binding.path)
		capture_close(&ctx->pcap.binding);

	rc = rc ? EXIT_FAILURE : EXIT_SUCCESS;
cleanup_mctp:
	mctp_destroy(ctx->mctp);

initialize_exit:
	return rc;
}
