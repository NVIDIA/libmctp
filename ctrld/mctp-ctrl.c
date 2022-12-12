/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

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
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libmctp.h"
#include "libmctp-log.h"
#include "libmctp-astpcie.h"

#include "libmctp-cmds.h"

#include "mctp-ctrl-log.h"
#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-encode.h"
#include "mctp-sdbus.h"
#include "mctp-socket.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__((unused))

/* Default socket path */
#define MCTP_SOCK_PATH "\0mctp-pcie-mux"

/* MCTP Tx/Rx waittime in milli-seconds */
#define MCTP_CTRL_WAIT_SECONDS (1 * 1000)
#define MCTP_CTRL_WAIT_TIME (2 * MCTP_CTRL_WAIT_SECONDS)

/* MCTP control retry threshold */
#define MCTP_CTRL_CMD_RETRY_THRESHOLD 3

/* MCTP Invalid EID's */
#define MCTP_INVALID_EID_0 0
#define MCTP_INVALID_EID_FF 0xFF

/* Global definitions */
uint8_t g_verbose_level = 0;

extern const uint8_t MCTP_MSG_TYPE_HDR;
extern const uint8_t MCTP_CTRL_MSG_TYPE;

const char *mctp_sock_path = MCTP_SOCK_PATH;
const char *mctp_medium_type = "PCIe";

/* Static variables for clean up*/
static int g_socket_fd = -1;
static int g_signal_fd = -1;
static sd_bus *g_sdbus = NULL;

extern void mctp_routing_entry_delete_all(void);
extern void mctp_uuid_delete_all(void);
extern void mctp_msg_types_delete_all(void);
extern mctp_ret_codes_t mctp_discover_endpoints(mctp_cmdline_args_t *cmd,
						mctp_ctrl_t *ctrl);

static void mctp_ctrl_clean_up(void)
{
	/* Close the socket connection */
	close(g_socket_fd);

	/* Close the signalfd socket */
	close(g_signal_fd);

	/* Close D-Bus */
	sd_bus_unref(g_sdbus);

	/* Delete Routing table entries */
	mctp_routing_entry_delete_all();

	/* Delete UUID entries */
	mctp_uuid_delete_all();

	/* Delete Msg type entries */
	mctp_msg_types_delete_all();
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
	{ "tx", required_argument, 0, 's' },
	{ "rx", required_argument, 0, 'r' },
	{ "bindinfo", required_argument, 0, 'b' },

	/* EID options */
	{ "pci_own_eid", required_argument, 0, 'i' },
	{ "i2c_own_eid", required_argument, 0, 'j' },
	{ "pci_bridge_eid", required_argument, 0, 'p' },
	{ "i2c_bridge_eid", required_argument, 0, 'q' },
	{ "pci_bridge_pool_start", required_argument, 0, 'x' },
	{ "i2c_bridge_pool_start", required_argument, 0, 'y' },

	{ "help", no_argument, 0, 'h' },
	{ 0 },
};

const char *const short_options = "v:e:m:t:d:s:i:b:r:i:j:p:q:x:y:h";

static int64_t mctp_millis()
{
	struct timespec now;
	timespec_get(&now, TIME_UTC);
	return ((int64_t)now.tv_sec) * 1000 + ((int64_t)now.tv_nsec) / 1000000;
}

int mctp_cmdline_exec(mctp_cmdline_args_t *cmd, int sock_fd)
{
	mctp_requester_rc_t mctp_ret;
	size_t resp_msg_len;
	uint8_t *mctp_resp_msg;
	struct mctp_astpcie_pkt_private pvt_binding;
	int64_t t_start, t_end;
	int retry = 0;

	assert(cmd);

	/* Start time */
	t_start = mctp_millis();

	switch (cmd->ops) {
	case MCTP_CMDLINE_OP_WRITE_DATA:
		/* Send the request message over socket */
		MCTP_CTRL_INFO("%s: Sending EP request\n", __func__);
		mctp_ret =
			mctp_client_send(cmd->dest_eid, sock_fd,
					 MCTP_MSG_TYPE_HDR,
					 (uint8_t *)cmd->tx_data, cmd->tx_len);

		if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
			MCTP_CTRL_ERR("%s: Failed to send message..\n",
				      __func__);
		}

		break;

	case MCTP_CMDLINE_OP_READ_DATA:

		/* Receive the MCTP packet */
		mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd,
					    &mctp_resp_msg, &resp_msg_len);
		if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed to received message %d\n",
				      __func__, mctp_ret);
		}

		break;

	case MCTP_CMDLINE_OP_BIND_WRITE_DATA:

		// Get binding information
		if (cmd->binding_type == MCTP_BINDING_PCIE) {
			memcpy(&pvt_binding, &cmd->bind_info,
			       sizeof(struct mctp_astpcie_pkt_private));
		} else {
			MCTP_CTRL_ERR("%s: Invalid binding type: %d\n",
				      __func__, cmd->binding_type);
			return MCTP_CMD_FAILED;
		}

		/* Send the request message over socket */
		MCTP_CTRL_DEBUG(
			"%s: Pvt bind data: Routing: 0x%x, Remote ID: 0x%x\n",
			__func__, pvt_binding.routing, pvt_binding.remote_id);

		mctp_ret = mctp_client_with_binding_send(
			cmd->dest_eid, sock_fd, (const uint8_t *)cmd->tx_data,
			cmd->tx_len, &cmd->binding_type, (void *)&pvt_binding,
			sizeof(pvt_binding));

		if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
			MCTP_CTRL_ERR("%s: Failed to send message..\n",
				      __func__);
		}

		break;

	case MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV:
		MCTP_CTRL_INFO("%s: Supported bindigs: PCIe\n", __func__);
		break;

	default:
		break;
	}

	/* Receive the MCTP packet */

	while (1) {
		mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd,
					    &mctp_resp_msg, &resp_msg_len);
		if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
			/* End time */
			t_end = mctp_millis();

			/* Check if it's timedout or not */
			if ((t_end - t_start) > MCTP_CTRL_WAIT_TIME) {
				MCTP_CTRL_ERR(
					"%s: MCTP Rx Command Timed out (waited %f seconds)\n",
					__func__,
					(float)(t_end - t_start) /
						(float)MCTP_CTRL_WAIT_SECONDS);
			}

			/* Return as failed once crossed threshold */
			MCTP_ASSERT_RET(retry < MCTP_CTRL_CMD_RETRY_THRESHOLD,
					MCTP_CMD_FAILED,
					"Failed to received message %d\n",
					mctp_ret);

			MCTP_CTRL_ERR("%s: Retrying [%d] time\n", __func__,
				      ++retry);
			t_start = t_end;
		} else {
			/* End time */
			t_end = mctp_millis();

			printf("%s: Successfully received message\n", __func__);
			break;
		}
	}

	printf("Command Done in [%lld] ms\n", (t_end - t_start));

	return MCTP_CMD_SUCCESS;
}

uint16_t mctp_ctrl_get_target_bdf(mctp_cmdline_args_t *cmd)
{
	struct mctp_astpcie_pkt_private pvt_binding;

	// Get binding information
	if (cmd->binding_type == MCTP_BINDING_PCIE) {
		memcpy(&pvt_binding, &cmd->bind_info,
		       sizeof(struct mctp_astpcie_pkt_private));
	} else {
		MCTP_CTRL_INFO("%s: Invalid binding type: %d\n", __func__,
			       cmd->binding_type);
		return 0;
	}

	/* Update the target EID */
	MCTP_CTRL_INFO("%s: Target BDF: 0x%x\n", __func__,
		       pvt_binding.remote_id);
	return (pvt_binding.remote_id);
}

int mctp_cmdline_copy_tx_buff(char src[], uint8_t *dest, int len)
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
	mctp_requester_rc_t mctp_ret;
	uint8_t *mctp_resp_msg;
	size_t resp_msg_len;

	MCTP_CTRL_DEBUG("%s: Target eid: %d\n", __func__, mctp_evt->eid);

	/* Receive the MCTP packet */
	mctp_ret = mctp_client_recv(mctp_evt->eid, mctp_evt->sock,
				    &mctp_resp_msg, &resp_msg_len);
	MCTP_ASSERT_RET(mctp_ret == MCTP_REQUESTER_SUCCESS,
			MCTP_REQUESTER_RECV_FAIL,
			" Failed to received message %d\n", mctp_ret);

	MCTP_CTRL_DEBUG("%s: Successfully received message..\n", __func__);

	/* Free the Rx buffer */
	free(mctp_resp_msg);

	return MCTP_REQUESTER_SUCCESS;
}

static int mctp_start_daemon(mctp_ctrl_t *ctrl)
{
	int rc;

	MCTP_CTRL_DEBUG("%s: Daemon starting....\n", __func__);
	ctrl->pollfds = malloc(MCTP_CTRL_FD_NR * sizeof(struct pollfd));

	ctrl->pollfds[MCTP_CTRL_FD_SOCKET].fd = ctrl->sock;
	ctrl->pollfds[MCTP_CTRL_FD_SOCKET].events = POLLIN;

	for (;;) {
		rc = poll(ctrl->pollfds, MCTP_CTRL_FD_NR, -1);
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

/* Sanity check for PCIe Endpoint IDs */
static int mctp_pcie_eids_sanity_check(uint8_t pci_own_eid,
				       uint8_t pci_bridge_eid,
				       uint8_t pci_bridge_pool_start)
{
	int rc = -1;

	/* Check for PCIe own EID */
	if ((pci_own_eid == MCTP_INVALID_EID_0) ||
	    (pci_own_eid == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid pci_own_eid: 0x%x\n", __func__,
			      pci_own_eid);
		return rc;
	}

	/* Check for PCIe bridge EID */
	if ((pci_bridge_eid == MCTP_INVALID_EID_0) ||
	    (pci_bridge_eid == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid pci_bridge_eid: 0x%x\n", __func__,
			      pci_bridge_eid);
		return rc;
	}

	/* Check for PCIe bridge pool start EID */
	if ((pci_bridge_pool_start == MCTP_INVALID_EID_0) ||
	    (pci_bridge_pool_start == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid pci_bridge_pool_start: 0x%x\n",
			      __func__, pci_bridge_pool_start);
		return rc;
	}

	/* Also check for duplicate EID's if any */
	if ((pci_own_eid == pci_bridge_eid) ||
	    (pci_own_eid == pci_bridge_pool_start) ||
	    (pci_bridge_eid == pci_bridge_pool_start)) {
		MCTP_CTRL_ERR("%s: Duplicate EID's found\n", __func__);
		return rc;
	}

	return 0;
}

int main(int argc, char *const *argv)
{
	int fd;
	int rc;
	int signal_fd = -1;
	sigset_t mask;
	mctp_ctrl_t *mctp_ctrl, _mctp_ctrl;
	mctp_cmdline_args_t cmdline;

	/* Initialize MCTP ctrl structure */
	mctp_ctrl = &_mctp_ctrl;
	mctp_ctrl->type = MCTP_MSG_TYPE_HDR;

	/* Initialize the cmdline structure */
	memset(&cmdline, 0, sizeof(cmdline));

	/* Update the cmdline sturcture with default values */
	const char *const mctp_ctrl_name = argv[0];
	strncpy(cmdline.name, mctp_ctrl_name, sizeof(mctp_ctrl_name) - 1);

	cmdline.device_id = -1;
	cmdline.verbose = false;
	cmdline.binding_type = MCTP_BINDING_RESERVED;
	cmdline.delay = MCTP_CTRL_DELAY_DEFAULT;
	cmdline.read = 0;
	cmdline.write = 0;
	cmdline.use_socket = 0;
	cmdline.list_device_op = 0;
	cmdline.ops = MCTP_CMDLINE_OP_NONE;

	memset(&cmdline.tx_data, 0, MCTP_WRITE_DATA_BUFF_SIZE);
	memset(&cmdline.rx_data, 0, MCTP_READ_DATA_BUFF_SIZE);

	for (;;) {
		rc = getopt_long(argc, argv, short_options, g_options, NULL);
		if (rc == -1)
			break;

		switch (rc) {
		case 'v':
			cmdline.verbose = true;
			MCTP_CTRL_DEBUG("%s: Verbose level:%d", __func__,
					cmdline.verbose);
			g_verbose_level = cmdline.verbose;
			break;
		case 'e':
			cmdline.dest_eid = (uint8_t)atoi(optarg);
			mctp_ctrl->eid = cmdline.dest_eid;
			break;
		case 'm':
			cmdline.mode = (uint8_t)atoi(optarg);
			MCTP_CTRL_DEBUG("%s: Mode :%s", __func__,
					cmdline.mode ? "Daemon mode" :
						       "Command line mode");
			break;
		case 't':
			cmdline.binding_type = (uint8_t)atoi(optarg);
			break;
		case 'd':
			cmdline.delay = (int)atoi(optarg);
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
		case 'i':
			cmdline.pci_own_eid = (uint8_t)atoi(optarg);
			break;
		case 'j':
			cmdline.i2c_own_eid = (uint8_t)atoi(optarg);
			break;
		case 'p':
			cmdline.pci_bridge_eid = (uint8_t)atoi(optarg);
			break;
		case 'q':
			cmdline.i2c_bridge_eid = (uint8_t)atoi(optarg);
			break;
		case 'x':
			cmdline.pci_bridge_pool_start = (uint8_t)atoi(optarg);
			break;
		case 'y':
			cmdline.i2c_bridge_pool_start = (uint8_t)atoi(optarg);
			break;
		case 'h':
			MCTP_CTRL_INFO(
				"Various command line options mentioned below\n"
				"\t-v\tVerbose level\n"
				"\t-e\tTarget Endpoint Id\n"
				"\t-m\tMode: (0 - Commandline mode, 1 - daemon mode)\n"
				"\t-t\tBinding Type (0 - Resvd, 2 - PCIe)\n"
				"\t-b\tBinding data (pvt)\n"
				"\t-d\tDelay in seconds (for MCTP enumeration)\n"
				"\t-s\tTx data (MCTP packet payload: [Req-dgram]-[cmd-code]--)\n"
				"\t-i, -j\t PCIe eid, I2C eid\n"
				"\t-p, -q\t PCIe bridge eid, I2C bridge eid\n"
				"\t-x, -y\t PCIe bridge pool start eid, I2C bridge pool start eid\n"
				"\t-h\tPrints this message\n"
				"Eg: To send MCTP message of PCIe type:\n"
				"\tmctp-ctrl -s \"80 0b\" -t 2 -b \"03 00 00 00 01 12\" -e 255 -m 0");
			return EXIT_SUCCESS;
		default:
			MCTP_CTRL_ERR("Invalid argument\n");
			return EXIT_FAILURE;
		}
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		printf("Failed to signalmask\n");
		return -1;
	}

	g_signal_fd = signalfd(-1, &mask, 0);
	MCTP_ASSERT_RET(g_signal_fd >= 0, EXIT_FAILURE,
			"Failed to open signalfd\n");

	/* sleep before starting the daemon */
	sleep(cmdline.delay);

	/* Open the user socket file-descriptor */
	rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_CTRL_MSG_TYPE,
				  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("Failed to open mctp socket\n");

		close(g_signal_fd);
		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;

	/* Update global socket pointer */
	g_socket_fd = fd;

	/* Run this application only if set as daemon mode */
	if (!cmdline.mode) {
		mctp_cmdline_exec(&cmdline, mctp_ctrl->sock);
	} else {
		mctp_ret_codes_t mctp_err_ret;

		/* Create D-Bus for loging event and handling D-Bus request*/
		rc = sd_bus_default_system(&mctp_ctrl->bus);
		if (rc < 0) {
			MCTP_CTRL_ERR("D-Bus failed to create\n");
			close(mctp_ctrl->sock);
			return EXIT_FAILURE;
		}
		g_sdbus = mctp_ctrl->bus;

		/* Make sure all PCIe EID options are available from commandline */
		rc = mctp_pcie_eids_sanity_check(cmdline.pci_own_eid,
						 cmdline.pci_bridge_eid,
						 cmdline.pci_bridge_pool_start);
		if (rc < 0) {
			close(g_socket_fd);
			close(g_signal_fd);
			sd_bus_unref(mctp_ctrl->bus);
			MCTP_CTRL_ERR("MCTP-Ctrl sanity check unsuccessful\n");
			return EXIT_FAILURE;
		}

		/* Discover endpoints */
		mctp_err_ret = mctp_discover_endpoints(&cmdline, mctp_ctrl);
		if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
			MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
		}

		/* Start D-Bus initialization and monitoring */
		rc = mctp_ctrl_sdbus_init(mctp_ctrl->bus, g_signal_fd);
		if (rc < 0) {
			MCTP_CTRL_INFO("MCTP-Ctrl is going to terminate.\n");
			mctp_ctrl_clean_up();
			return EXIT_SUCCESS;
		}

		if (rc >= 0) {
			/* Start MCTP control daemon */
			MCTP_CTRL_INFO("%s: Start MCTP-CTRL daemon....",
				       __func__);
			mctp_start_daemon(mctp_ctrl);
		}
	}

	mctp_ctrl_clean_up();
	return EXIT_SUCCESS;
}
