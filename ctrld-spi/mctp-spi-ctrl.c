/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-astpcie.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "ctrld/mctp-ctrl.h"
#include "ctrld/mctp-sdbus.h"
#include "ctrld/mctp-ctrl-log.h"

#include "mctp-socket.h"
#include "mctp-spi-ctrl.h"
#include "mctp-spi-ctrl-cmdline.h"
#include "mctp-spi-ctrl-cmds.h"

#define __unused __attribute__((unused))

/* Default socket path */
#define MCTP_SOCK_PATH "\0mctp-spi-mux";

/* Global definitions */
uint8_t g_verbose_level = 0;

extern const uint8_t MCTP_MSG_TYPE_HDR;
extern const uint8_t MCTP_CTRL_MSG_TYPE;

/* Variables for D-Bus serice and properity */
const char *mctp_sock_path = MCTP_SOCK_PATH;
const char *mctp_medium_type = "SPI";

/* Static variables for clean up*/
static int g_socket_fd = -1;
static int g_signal_fd = -1;
static sd_bus *g_sdbus = NULL;

static pthread_t g_keepalive_thread;

extern void *mctp_spi_keepalive_event(void *arg);
extern mctp_ret_codes_t mctp_spi_static_endpoint(void);

const char mctp_spi_help_str[] =
	"Various command line options mentioned below\n"
	"\t-v\tVerbose level\n"

	"\t-e\tTarget Endpoint Id\n"

	"\t-m\tMode: \
 0 - Commandline mode,\
 1 - daemon mode,\
 2 - Test mode\n"

	"\t-x\tMCTP base commands:\
 1 - Set Endpoint ID,\
 2 - Get Endpoint ID,\
 3 - Get Endpoint UUID,\
 4 - Get MCTP Version Support,\
 5 - Get MCTP Message Type Support\n"

	"\t-t\tBinding Type:\
 0 - Resvd,\
 6 - SPI\n"

	"\t-d\tDelay:\
 10 - Default delay value\n"

	"\t-b\tBinding data (pvt)\n"

	"\t-i\tNVIDIA IANA VDM commands:\
 1 - Set EP UUID,\
 2 - Boot complete,\
 3 - Heartbeat,\
 4 - Enable Heartbeat,\
 5 - Query boot status\n"

	"\t-s\tTx data (MCTP packet payload: [Req-dgram]-[cmd-code]--)\n"
	"\t-h\tPrints this message\n"

	"-> To send Boot complete command:\n"
	"\tmctp-spi-ctrl -i 2 -t 6 -m 2 -v 2\n"

	"-> To send Enable Heartbeat command:\n"
	"\tmctp-spi-ctrl -i 4 -t 6 -m 2 -v 2\n"

	"-> To send Heartbeat (ping) command:\n"
	"\tmctp-spi-ctrl -i 3 -t 6 -m 2 -v 2\n";

static void mctp_ctrl_clean_up(void)
{
	/* Close D-Bus */
	sd_bus_unref(g_sdbus);

	pthread_join(g_keepalive_thread, NULL);

	/* Wait for all threads to exit and close socket */
	close(g_socket_fd);

	/* Close signal fd */
	close(g_signal_fd);
}

mctp_requester_rc_t
mctp_client_with_binding_send(mctp_eid_t dest_eid, int mctp_fd,
			      const uint8_t *mctp_req_msg, size_t req_msg_len,
			      mctp_binding_ids_t *bind_id,
			      void *mctp_binding_info, size_t mctp_binding_len)
{
	uint8_t hdr[2] = { dest_eid, MCTP_MSG_TYPE_HDR };
	struct iovec iov[4];

	MCTP_ASSERT_RET(mctp_req_msg[0] == MCTP_MSG_TYPE_HDR,
			MCTP_REQUESTER_SEND_FAIL, " unsupported Msg type: %d\n",
			mctp_req_msg[0]);

	/* Binding ID and information */
	iov[0].iov_base = (uint8_t *)bind_id;
	iov[0].iov_len = sizeof(uint8_t);
	iov[1].iov_base = (uint8_t *)mctp_binding_info;
	iov[1].iov_len = mctp_binding_len;

	/* MCTP header and payload */
	iov[2].iov_base = hdr;
	iov[2].iov_len = sizeof(hdr);
	iov[3].iov_base = (uint8_t *)(mctp_req_msg + 1);
	iov[3].iov_len = req_msg_len;

	struct msghdr msg = { 0 };
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	mctp_ctrl_print_buffer("mctp_bind_id  >> ", (uint8_t *)bind_id,
			       sizeof(uint8_t));
	mctp_ctrl_print_buffer("mctp_pvt_data >> ", mctp_binding_info,
			       mctp_binding_len);
	mctp_ctrl_print_buffer("mctp_req_hdr  >> ", hdr, sizeof(hdr));
	mctp_ctrl_print_buffer("mctp_req_msg  >> ", mctp_req_msg, req_msg_len);

	ssize_t rc = sendmsg(mctp_fd, &msg, 0);
	MCTP_ASSERT_RET(rc >= 0, MCTP_REQUESTER_SEND_FAIL,
			"failed to sendmsg\n");

	return MCTP_REQUESTER_SUCCESS;
}

static const struct option g_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "eid", required_argument, 0, 'e' },
	{ "mode", required_argument, 0, 'm' },
	{ "type", required_argument, 0, 't' },
	{ "delay", required_argument, 0, 'd' },
	{ "cmd_mode", required_argument, 0, 'x' },
	{ "mctp-iana-vdm", required_argument, 0, 'i' },
	{ "tx", required_argument, 0, 's' },
	{ "rx", required_argument, 0, 'r' },
	{ "bindinfo", required_argument, 0, 'b' },
	{ "help", no_argument, 0, 'h' },
	{ 0 },
};

const char *const short_options = "v:e:m:t:d:x:i:s:b:r:h";

int mctp_spi_cmdline_exec(mctp_spi_cmdline_args_t *cmd, int sock_fd)
{
	mctp_requester_rc_t mctp_ret = 0;
	size_t resp_msg_len = 0;
	uint8_t *mctp_resp_msg = NULL;
	struct mctp_spi_pkt_private pvt_binding;

	memset(&pvt_binding, 0, sizeof(struct mctp_spi_pkt_private));

	assert(cmd);

	switch (cmd->ops) {
	case MCTP_CMDLINE_OP_WRITE_DATA:
		/* Send the request message over socket */
		MCTP_CTRL_INFO("%s: Sending EP request\n", __func__);
		mctp_ret = mctp_client_send(cmd->dest_eid, sock_fd,
					    MCTP_MSG_TYPE_HDR,
					    (const uint8_t *)cmd->tx_data,
					    cmd->tx_len);

		MCTP_ASSERT_RET(mctp_ret != MCTP_REQUESTER_SEND_FAIL,
				MCTP_CMD_FAILED, "Failed to send message..\n");

		break;

	case MCTP_CMDLINE_OP_READ_DATA:

		/* Receive the MCTP packet */
		mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd,
					    &mctp_resp_msg, &resp_msg_len);
		MCTP_ASSERT_RET(mctp_ret == MCTP_REQUESTER_SUCCESS,
				MCTP_CMD_FAILED,
				" Failed to received message %d\n", mctp_ret);

		break;

	case MCTP_CMDLINE_OP_BIND_WRITE_DATA:

		// Get binding information
		if (cmd->binding_type == MCTP_BINDING_SPI) {
			memcpy(&pvt_binding, &cmd->bind_info,
			       sizeof(struct mctp_spi_pkt_private));
		} else {
			MCTP_CTRL_ERR("%s: Invalid binding type: %d\n",
				      __func__, cmd->binding_type);
			return MCTP_CMD_FAILED;
		}

		/* Send the request message over socket */
		MCTP_CTRL_DEBUG("%s: Pvt bind data: Controller: 0x%x\n",
				__func__, pvt_binding.controller);

		mctp_ret = mctp_client_with_binding_send(
			cmd->dest_eid, sock_fd, (const uint8_t *)cmd->tx_data,
			cmd->tx_len, &cmd->binding_type, (void *)&pvt_binding,
			sizeof(pvt_binding));

		MCTP_ASSERT_RET(mctp_ret != MCTP_REQUESTER_SEND_FAIL,
				MCTP_CMD_FAILED, "Failed to send message..\n");

		break;

	case MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV:
		MCTP_CTRL_INFO("%s: Supported bindigs: PCIe\n", __func__);
		break;

	default:
		break;
	}

	/* Receive the MCTP packet */
	mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd, &mctp_resp_msg,
				    &resp_msg_len);

	MCTP_ASSERT_RET(mctp_ret == MCTP_REQUESTER_SUCCESS, MCTP_CMD_FAILED,
			" Failed to received message %d\n", mctp_ret);

	return MCTP_CMD_SUCCESS;
}

uint16_t mctp_ctrl_get_target_bdf(mctp_cmdline_args_t *cmd)
{
	/* no implementation for SPI interafce */
	return 0;
}

int mctp_cmdline_copy_tx_buff(uint8_t src[], uint8_t *dest, int len)
{
	int i = 0, buff_len = 0;

	while (i < len) {
		dest[buff_len++] = (unsigned char)strtol(&src[i], NULL, 16);
		i = i + MCTP_CMDLINE_WRBUFF_WIDTH;
	}

	return buff_len;
}

int mctp_event_monitor(mctp_ctrl_t *mctp_evt)
{
	mctp_requester_rc_t mctp_ret = 0;
	uint8_t *mctp_resp_msg = NULL;
	size_t resp_msg_len = 0;

	MCTP_CTRL_DEBUG("%s: Target eid: %d\n", __func__, mctp_evt->eid);

	/* Receive the MCTP packet */
	mctp_ret = mctp_client_recv(mctp_evt->eid, mctp_evt->sock,
				    &mctp_resp_msg, &resp_msg_len);

	MCTP_ASSERT_RET(mctp_ret == MCTP_REQUESTER_SUCCESS,
			MCTP_REQUESTER_RECV_FAIL,
			"Failed to received message %d\n", mctp_ret);

	MCTP_CTRL_DEBUG("%s: Successfully received message..\n", __func__);

	/* Free the Rx buffer */
	free(mctp_resp_msg);

	return MCTP_REQUESTER_SUCCESS;
}

static int mctp_start_daemon(mctp_ctrl_t *ctrl)
{
	int rc = 0;

	MCTP_CTRL_DEBUG("%s: Daemon starting....\n", __func__);
	ctrl->pollfds = malloc(MCTP_CTRL_FD_NR * sizeof(struct pollfd));

	ctrl->pollfds[MCTP_CTRL_FD_SOCKET].fd = ctrl->sock;
	ctrl->pollfds[MCTP_CTRL_FD_SOCKET].events = POLLIN;

	for (;;) {
		rc = poll(ctrl->pollfds, MCTP_CTRL_FD_NR, -1);

		if (rc == -1 && errno == EINTR) {
			warn("poll(2) interrupted by signal");
			continue;
		}

		if (rc < 0) {
			warn("poll failed");
			break;
		}

		if (!rc)
			continue;

		if (ctrl->pollfds[MCTP_CTRL_FD_SOCKET].revents) {
			MCTP_CTRL_DEBUG("%s: Rx socket event...\n", __func__);

			/* Read the Socket */
			rc = mctp_event_monitor(ctrl);
			if (rc != MCTP_REQUESTER_SUCCESS) {
				MCTP_CTRL_ERR("%s: Invalid data..\n", __func__);
			}

		} else {
			MCTP_CTRL_INFO("%s: Rx Timeout\n", __func__);
		}
	}

	free(ctrl->pollfds);
	return rc;
}

int main(int argc, char *const *argv)
{
	int fd = -1;
	int rc = 0;
	int ret = 0;
	sigset_t mask;
	mctp_ctrl_t *mctp_ctrl = NULL, _mctp_ctrl;
	pthread_t keepalive_thread;

	mctp_spi_cmdline_args_t cmdline = { 0 };

	/* Initialize MCTP ctrl structure */
	mctp_ctrl = &_mctp_ctrl;
	mctp_ctrl->type = MCTP_MSG_TYPE_HDR;
	mctp_ctrl->sock = -1;

	/* Initialize the cmdline structure */
	memset(&cmdline, 0, sizeof(cmdline));

	/* Update the cmdline sturcture with default values */
	const char *const mctp_ctrl_name = argv[0];
	strncpy(cmdline.name, mctp_ctrl_name, sizeof(mctp_ctrl_name) - 1);

	cmdline.device_id = -1;
	cmdline.verbose = 1;
	cmdline.binding_type = MCTP_BINDING_SPI;
	cmdline.delay = MCTP_SPI_CTRL_DELAY_DEFAULT;
	cmdline.read = 0;
	cmdline.write = 0;
	cmdline.use_socket = 0;
	cmdline.list_device_op = 0;
	cmdline.ops = MCTP_CMDLINE_OP_NONE;
	cmdline.cmd_mode = MCTP_SPI_NONE;
	cmdline.mode = -1;

	memset(&cmdline.tx_data, 0, MCTP_WRITE_DATA_BUFF_SIZE);
	memset(&cmdline.rx_data, 0, MCTP_READ_DATA_BUFF_SIZE);

	for (;;) {
		rc = getopt_long(argc, argv, short_options, g_options, NULL);
		if (rc == -1)
			break;

		switch (rc) {
		case 'v':
			cmdline.verbose = (uint8_t)atoi(optarg);
			MCTP_CTRL_DEBUG("%s: Verbose level:%d", __func__,
					cmdline.verbose);
			g_verbose_level = cmdline.verbose;
			break;
		case 'e':
			cmdline.src_eid = (uint8_t)atoi(optarg);
			mctp_ctrl->eid = cmdline.src_eid;
			break;
		case 'm':
			cmdline.mode = (uint8_t)atoi(optarg);
			MCTP_CTRL_DEBUG("%s: Mode :%s\n", __func__,
					cmdline.mode ? "Daemon mode" :
						       "Command line mode");
			break;
		case 't':
			cmdline.binding_type = (uint8_t)atoi(optarg);
			break;
		case 'd':
			cmdline.delay = (int)atoi(optarg);
			break;
		case 'x':
			cmdline.cmd_mode = (uint8_t)atoi(optarg);
			break;
		case 'i':
			cmdline.vdm_ops = atoi(optarg);
			break;
		case 'b':
			cmdline.bind_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline.bind_info, strlen(optarg));
			cmdline.ops = MCTP_CMDLINE_OP_BIND_WRITE_DATA;
			break;
		case 's':
			cmdline.tx_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline.tx_data, strlen(optarg));
			break;
		case 'h':
			MCTP_CTRL_INFO("%s\n", mctp_spi_help_str);
			return EXIT_SUCCESS;
		default:
			MCTP_CTRL_ERR("Invalid argument\n");
			return EXIT_FAILURE;
		}
	}

	/* Return if it is unknown mode */
	MCTP_ASSERT_RET(cmdline.mode >= 0, EXIT_FAILURE, " Unsupported mode");

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		MCTP_CTRL_ERR("Failed to signalmask\n");
		return EXIT_FAILURE;
	}

	/* Queue the signal and then do cleanup stuff */
	g_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (g_signal_fd < 0) {
		MCTP_CTRL_ERR("Failed to signalfd\n");
		return EXIT_FAILURE;
	}

	/* Open the user socket file-descriptor */
	rc = mctp_usr_socket_init(&fd, mctp_sock_path,
				  MCTP_MESSAGE_TYPE_VDIANA);
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("Failed to open mctp sock\n");
		close(g_signal_fd);

		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;
	/* Update global socket pointer */
	g_socket_fd = mctp_ctrl->sock;

	/* Check for test mode */
	if (cmdline.mode == MCTP_SPI_MODE_TEST) {
		mctp_spi_test_cmd(mctp_ctrl, &cmdline);
		close(g_socket_fd);
		close(g_signal_fd);

		return EXIT_SUCCESS;
	}

	ret = pthread_cond_init(&mctp_ctrl->worker_cv, NULL);
	MCTP_ASSERT_RET(ret == 0, EXIT_FAILURE, "pthread_cond_init(3) failed.");

	ret = pthread_mutex_init(&mctp_ctrl->worker_mtx, NULL);
	MCTP_ASSERT_RET(ret == 0, EXIT_FAILURE,
			"pthread_mutex_init(3) failed.");

	/* Create D-Bus for loging event and handling D-Bus request*/
	rc = sd_bus_default_system(&mctp_ctrl->bus);
	if (rc < 0) {
		MCTP_CTRL_ERR("D-Bus failed to create\n");
		close(mctp_ctrl->sock);
		return EXIT_FAILURE;
	}
	g_sdbus = mctp_ctrl->bus;

	/* Create static endpoint 0 for spi ctrl daemon */
	mctp_spi_static_endpoint();

	//create pthread for sening keepalive messages
	pthread_create(&keepalive_thread, NULL, &mctp_spi_keepalive_event,
		       (void *)mctp_ctrl);

	g_keepalive_thread = keepalive_thread;

	/* Wait until we can populate Dbus objects. */
	pthread_cond_wait(&mctp_ctrl->worker_cv, &mctp_ctrl->worker_mtx);

	/* Populate D-Bus objects */
	rc = mctp_ctrl_sdbus_init(mctp_ctrl->bus, g_signal_fd);

	/* Pass the signal to threads and notify we are going to exit */
	if (rc < 0) {
		MCTP_CTRL_INFO(
			"Deliver the termination signal to keepalive thread\n");
		pthread_kill(g_keepalive_thread, SIGUSR2);
	}

	/* Clean up the resource */
	mctp_ctrl_clean_up();

	return EXIT_SUCCESS;
}
