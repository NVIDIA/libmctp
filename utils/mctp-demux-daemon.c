/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include "config.h"

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#define SD_LISTEN_FDS_START 3

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-astpcie.h"
#include "libmctp-astspi.h"
#include "libmctp-log.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__((unused))

#define MCTP_BIND_INFO_OFFSET (sizeof(uint8_t))
#define MCTP_PCIE_EID_OFFSET                                                   \
	MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_astpcie_pkt_private)
#define MCTP_PCIE_MSG_OFFSET MCTP_PCIE_EID_OFFSET + (sizeof(uint8_t))
#define MCTP_SPI_MSG_OFFSET                                                    \
	MCTP_BIND_INFO_OFFSET + sizeof(struct mctp_astspi_pkt_private)

#if HAVE_SYSTEMD_SD_DAEMON_H
#include <systemd/sd-daemon.h>
#else
static inline int sd_listen_fds(int i __unused)
{
	return -1;
}
#endif

static const mctp_eid_t local_eid_default = 8;

struct binding {
	const char *name;
	int (*init)(struct mctp *mctp, struct binding *binding, mctp_eid_t eid,
		    int n_params, char *const *params);
	int (*get_fd)(struct binding *binding);
	int (*process)(struct binding *binding);
	void *data;
	char *sockname;
	/*
	 * Events to monitor. Some bindings, e.g. SPI,
	 * requires to monitor POLLPRI, not POLLIN.
	 */
	short events;
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

	struct client *clients;
	int n_clients;

	bool clients_changed;
};

static void mctp_print_hex(uint8_t *data, size_t length)
{
	for (int i = 0; i < length; ++i) {
		printf("%02X ", data[i]);
	}
	printf("\n");
}

static void tx_pvt_message(struct ctx *ctx, void *msg, size_t len)
{
	int rc;
	mctp_binding_ids_t bind_id;
	union {
		struct mctp_astpcie_pkt_private pcie;
		struct mctp_astspi_pkt_private spi;
	} pvt_binding = { 0 };
	mctp_eid_t eid = 0;

	/* Get the bus type (binding ID) */
	bind_id = *((uint8_t *)msg);

	/* Handle based on bind ID's */
	switch (bind_id) {
	case MCTP_BINDING_PCIE:
		/* Copy the binding information */
		memcpy(&pvt_binding.pcie, (msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_astpcie_pkt_private));
		/* Get target EID */

		eid = *((uint8_t *)msg + MCTP_PCIE_EID_OFFSET);
		/* Set MCTP payload size */

		len = len - (MCTP_PCIE_MSG_OFFSET)-1;
		mctp_print_hex((uint8_t *)msg + MCTP_PCIE_MSG_OFFSET, len);
		rc = mctp_message_pvt_bind_tx(ctx->mctp, eid,
					      msg + MCTP_PCIE_MSG_OFFSET, len,
					      (void *)&pvt_binding.pcie);

		if (ctx->verbose) {
			printf("%s: BindID: %d, Target EID: %d, msg len: %zi,\
			    Routing:%d remote_id: 0x%x\n",
			       __func__, bind_id, eid, len,
			       pvt_binding.pcie.routing,
			       pvt_binding.pcie.remote_id);
		}
		break;
	case MCTP_BINDING_SPI:
		memcpy(&pvt_binding.spi, (msg + MCTP_BIND_INFO_OFFSET),
		       sizeof(struct mctp_astspi_pkt_private));
		break;
	default:
		warnx("Invalid/Unsupported binding ID %d", bind_id);
		break;
	}

	if (rc)
		warnx("Failed to send message: %d", rc);
}

static void tx_message(struct ctx *ctx, mctp_eid_t eid, void *msg, size_t len)
{
	int rc;

	rc = mctp_message_tx(ctx->mctp, eid, msg, len);
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

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
	struct ctx *ctx = data;
	struct iovec iov[2];
	struct msghdr msghdr;
	bool removed = false;
	uint8_t type;
	int i, rc;

	if (len < 2)
		return;

	type = *(uint8_t *)msg;

	if (ctx->verbose)
		fprintf(stderr, "MCTP message received: len %zd, type %d\n",
			len, type);

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 2;
	iov[0].iov_base = &eid;
	iov[0].iov_len = 1;
	iov[1].iov_base = msg;
	iov[1].iov_len = len;

	for (i = 0; i < ctx->n_clients; i++) {
		struct client *client = &ctx->clients[i];

		if (ctx->verbose)
			fprintf(stderr, " %i client type: %hhu type: %hhu\n",
			    i, client->type, type);

		if (client->type != type)
			continue;

		if (ctx->verbose)
			fprintf(stderr, "  forwarding to client %d\n", i);

		rc = sendmsg(client->sock, &msghdr, 0);
		if (rc != (ssize_t)(len + 1)) {
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
	MCTP_ASSERT(serial != NULL, "serial is NULL");

	rc = mctp_serial_open_path(serial, path);
	if (rc)
		return -1;

	mctp_register_bus(mctp, mctp_binding_serial_core(serial), eid);

	binding->data = serial;

	return 0;
}

static int binding_serial_get_fd(struct binding *binding)
{
	return mctp_serial_get_fd(binding->data);
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
	return 0;
}

static int binding_astlpc_get_fd(struct binding *binding)
{
	return mctp_astlpc_get_fd(binding->data);
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
	return 0;
}

static int binding_astpcie_get_fd(struct binding *binding)
{
	return mctp_astpcie_get_fd(binding->data);
}

static int binding_astpcie_process(struct binding *binding)
{
	int rc;

	rc = mctp_astpcie_poll(binding->data, MCTP_ASTPCIE_POLL_TIMEOUT);
	if (rc & POLLIN) {
		rc = mctp_astpcie_rx(binding->data);
		MCTP_ASSERT(rc == 0, "mctp_astpcie_rx returned %d", rc);
	}

	return rc;
}

static int binding_astspi_init(struct mctp *mctp, struct binding *binding,
			       mctp_eid_t eid, int n_params,
			       char *const *params)
{
	struct mctp_binding_spi *astspi;

	astspi = mctp_spi_bind_init();
	MCTP_ASSERT(astspi != NULL, "mctp_spi_bind_init failed.");

	mctp_register_bus(mctp, mctp_binding_astspi_core(astspi), eid);
	binding->data = astspi;

	return (0);
}

static int binding_astspi_get_fd(struct binding *binding)
{
	struct mctp_binding_spi *astspi = binding->data;

	return (mctp_spi_get_fd(astspi));
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

struct binding bindings[] = { {
				      .name = "null",
				      .init = binding_null_init,
			      },
			      {
				      .name = "serial",
				      .init = binding_serial_init,
				      .get_fd = binding_serial_get_fd,
				      .process = binding_serial_process,
				      .sockname = "\0mctp-serial-mux",
				      .events = POLLIN,
			      },
			      {
				      .name = "astlpc",
				      .init = binding_astlpc_init,
				      .get_fd = binding_astlpc_get_fd,
				      .process = binding_astlpc_process,
				      .sockname = "\0mctp-lpc-mux",
				      .events = POLLIN,
			      },
			      {
				      .name = "astpcie",
				      .init = binding_astpcie_init,
				      .get_fd = binding_astpcie_get_fd,
				      .process = binding_astpcie_process,
				      .sockname = "\0mctp-pcie-mux",
				      .events = POLLIN,
			      },
			      {
				      .name = "astspi",
				      .init = binding_astspi_init,
				      .get_fd = binding_astspi_get_fd,
				      .process = binding_astspi_process,
				      .sockname = "\0mctp-spi-mux",
				      .events = POLLPRI,
			      } };

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
		if (rc <= 0)
			goto out_close;

		if (ctx->verbose)
			fprintf(stderr, "client[%d] registered for type %u\n",
				idx, type);
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

	eid = *(uint8_t *)ctx->buf;

	if (ctx->verbose)
		fprintf(stderr, "client[%d] sent message: dest 0x%02x len %d\n",
			idx, eid, rc - 1);

	if (eid == ctx->local_eid)
		rx_message(eid, ctx, ctx->buf + 1, rc - 1);
	else
		tx_message(ctx, eid, ctx->buf + 1, rc - 1);

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

enum { FD_BINDING = 0,
       FD_SOCKET,
       FD_NR,
};

static int run_daemon(struct ctx *ctx)
{
	int rc, i;

	ctx->pollfds = malloc(FD_NR * sizeof(struct pollfd));

	if (ctx->binding->get_fd) {
		ctx->pollfds[FD_BINDING].fd =
			ctx->binding->get_fd(ctx->binding);
		ctx->pollfds[FD_BINDING].events = ctx->binding->events;
	} else {
		ctx->pollfds[FD_BINDING].fd = -1;
		ctx->pollfds[FD_BINDING].events = 0;
	}

	ctx->pollfds[FD_SOCKET].fd = ctx->sock;
	ctx->pollfds[FD_SOCKET].events = POLLIN;

	ctx->clients_changed = false;

	mctp_set_rx_all(ctx->mctp, rx_message, ctx);

	for (;;) {
		if (ctx->clients_changed) {
			int i;

			ctx->pollfds = realloc(ctx->pollfds,
					       (ctx->n_clients + FD_NR) *
						       sizeof(struct pollfd));

			for (i = 0; i < ctx->n_clients; i++) {
				ctx->pollfds[FD_NR + i].fd =
					ctx->clients[i].sock;
				ctx->pollfds[FD_NR + i].events = POLLIN;
			}
			ctx->clients_changed = false;
		}

		rc = poll(ctx->pollfds, ctx->n_clients + FD_NR, -1);
		if (rc < 0) {
			warn("poll failed");
			break;
		}

		if (!rc)
			continue;

		if (ctx->pollfds[FD_BINDING].revents) {
			rc = 0;
			if (ctx->binding->process)
				rc = ctx->binding->process(ctx->binding);
			if (rc)
				break;
		}

		for (i = 0; i < ctx->n_clients; i++) {
			if (!ctx->pollfds[FD_NR + i].revents)
				continue;
			MCTP_ASSERT(ctx->pollfds[FD_NR + i].fd ==
			    ctx->clients[i].sock, "Socket fd mismatch!");
			rc = client_process_recv(ctx, i);
			if (rc)
				ctx->clients_changed = true;
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

	free(ctx->pollfds);

	return rc;
}

static const struct option options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "eid", required_argument, 0, 'e' },
	{ 0 },
};

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
	struct ctx *ctx, _ctx;
	int rc;

	ctx = &_ctx;
	ctx->clients = NULL;
	ctx->n_clients = 0;
	ctx->local_eid = local_eid_default;
	ctx->verbose = false;

	mctp_prinfo("MCTP demux started.");

	for (;;) {
		rc = getopt_long(argc, argv, "e:v", options, NULL);
		if (rc == -1)
			break;
		switch (rc) {
		case 'v':
			ctx->verbose = true;
			break;
		case 'e':
			ctx->local_eid = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "missing binding argument\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* setup initial buffer */
	ctx->buf_size = 4096;
	ctx->buf = malloc(ctx->buf_size);

	mctp_set_log_stdio(ctx->verbose ? MCTP_LOG_DEBUG : MCTP_LOG_WARNING);
	mctp_set_tracing_enabled(true);

	rc = sd_notifyf(0, "STATUS=Initializing MCTP.\nMAINPID=%d", getpid());
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	ctx->mctp = mctp_init();
	MCTP_ASSERT(ctx->mctp != NULL, "ctx->mctp is NULL");

	rc = sd_notify(0, "STATUS=Initializing binding.");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	mctp_prinfo("Binding init called.");
	rc = binding_init(ctx, argv[optind], argc - optind - 1,
			  argv + optind + 1);
	mctp_prinfo("Binding init returned: %d.", rc);
	if (rc)
		return EXIT_FAILURE;

	rc = sd_notify(0, "STATUS=Creating sockets.");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	rc = sd_listen_fds(true);
	if (rc <= 0) {
		rc = socket_init(ctx);
		if (rc)
			return EXIT_FAILURE;
	} else {
		ctx->sock = SD_LISTEN_FDS_START;
	}

	rc = sd_notify(0, "STATUS=Daemon is running.\nREADY=1");
	MCTP_ASSERT_RET(rc >= 0, EXIT_FAILURE, "Could not notify systemd.");

	rc = run_daemon(ctx);
	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
