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
#include <pthread.h>
#include <json-c/json.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-log.h"
#include "libmctp-astpcie.h"
#include "libmctp-smbus.h"

#include "libmctp-cmds.h"

#include "mctp-ctrl-log.h"
#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-ctrl-spi.h"
#include "mctp-encode.h"
#include "mctp-sdbus.h"
#include "mctp-discovery.h"
#include "mctp-discovery-i2c.h"
#include "mctp-socket.h"
#include "mctp-json.h"

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

static pthread_t g_keepalive_thread;
extern const uint8_t MCTP_MSG_TYPE_HDR;
extern const uint8_t MCTP_CTRL_MSG_TYPE;

const char *mctp_sock_path;
const char *mctp_medium_type;

/* Static variables for clean up*/
int g_socket_fd = -1;
int g_signal_fd = -1;
static sd_bus *g_sdbus = NULL;
struct mctp_static_endpoint_mapper static_endpoints[1];

static char *config_json_file_path = NULL;
bool use_config_json_file_mc = false;
extern json_object *parsed_json;
static uint8_t chosen_eid_type = 0;

extern void mctp_routing_entry_delete_all(void);
extern void mctp_uuid_delete_all(void);
extern void mctp_msg_types_delete_all(void);
extern mctp_ret_codes_t mctp_discover_endpoints(const mctp_cmdline_args_t *cmd,
						mctp_ctrl_t *ctrl);
extern mctp_ret_codes_t mctp_i2c_discover_endpoints(const mctp_cmdline_args_t *cmd,
						mctp_ctrl_t *ctrl);
extern void *mctp_spi_keepalive_event(void *arg);
extern mctp_ret_codes_t mctp_spi_discover_endpoint(mctp_ctrl_t *ctrl);

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
			      const mctp_binding_ids_t *bind_id,
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
	{ "cfg_file_path", required_argument, 0, 'f'},
	{ "bus_num", required_argument, 0, 'n'},

	/* EID options */
	{ "pci_own_eid", required_argument, 0, 'i' },
	{ "i2c_own_eid", required_argument, 0, 'j' },
	{ "pci_bridge_eid", required_argument, 0, 'p' },
	{ "i2c_bridge_eid", required_argument, 0, 'q' },
	{ "pci_bridge_pool_start", required_argument, 0, 'x' },
	{ "i2c_bridge_pool_start", required_argument, 0, 'y' },

	/* SPI specific options */
	{ "cmd_mode", required_argument, 0, 'x' },
	{ "mctp-iana-vdm", required_argument, 0, 'i' },

	{ "help", optional_argument, 0, 'h' },
	{ 0 },
};

static const char *const short_options = "ve:m:t:d:s:r:b:f:n:i:j:p:q:x:y:h::";

static void usage(void)
{
	MCTP_CTRL_INFO(
		"Usage: mctp-ctrl -h<binding>\n"
		"(or if use script: mctp-<binding>-ctrl -h<binding>)\n"
		"Available bindings:\n"
		"  pcie\n"
		"  spi\n");
}

static void usage_common(void)
{
	MCTP_CTRL_INFO(
		"Various command line options mentioned below\n"
		"\t-v\tVerbose level\n"
		"\t-e\tTarget Endpoint Id\n"
		"\t-m\tMode: (0 - Commandline mode, 1 - daemon mode, 2 - SPI test mode)\n"
		"\t-t\tBinding Type (0 - Resvd, 1 - I2C, 2 - PCIe, 6 - SPI)\n"
		"\t-b\tBinding data (pvt)\n"
		"\t-d\tDelay in seconds (for MCTP enumeration)\n"
		"\t-s\tTx data (MCTP packet payload: [Req-dgram]-[cmd-code]--)\n"
		"\t-f\tAbsolute path to configuration json file\n"
		"\t-n\tBus number for the selected interface, eg. PCIe 1, PCIe 2, I2C 3, ...");
}

static void usage_pcie(void)
{
	MCTP_CTRL_INFO(
		"\t-i\t pci own eid\n"
		"\t-p\t pci bridge eid\n"
		"\t-x\t pci bridge pool start eid\n"
		"To send MCTP message for PCIe binding type\n"
		"Eg: Prepare for Endpoint Discovery\n"
		"\t mctp-ctrl -s \"00 80 0b\" -b \"03 00 00 00 00 00\" -e 255 -i 9 -p 12 -x 13 -m 0 -t 2 -v\n"
		"\t(mctp-pcie-ctrl [params ----^])\n");
}

static void usage_spi(void)
{
	MCTP_CTRL_INFO(
		"\t-i\tNVIDIA IANA VDM commands:\n"
		"\t\t1 - Set EP UUID,\n"
		"\t\t2 - Boot complete,\n"
		"\t\t3 - Heartbeat,\n"
		"\t\t4 - Enable Heartbeat,\n"
		"\t\t5 - Query boot status\n"
		"\t-x mctp base command:\n"
		"\t\t1 - Set Endpoint ID,\n"
		"\t\t2 - Get Endpoint ID,\n"
		"\t\t3 - Get Endpoint UUID,\n"
		"\t\t4 - Get MCTP Version Support\n"
		"\t\t5 - Get MCTP Message Type Support\n"
		"To send MCTP message for SPI binding type\n"
		"\t-> To send Boot complete command:\n"
		"\t\t mctp-ctrl -i 2 -t 6 -m 2 -v\n"
		"\t-> To send Enable Heartbeat command:\n"
		"\t\t mctp-ctrl -i 4 -t 6 -m 2 -v\n"
		"\t-> To send Heartbeat (ping) command:\n"
		"\t\t mctp-ctrl -i 3 -t 6 -m 2 -v\n"
		"\t\t(mctp-spi-ctrl [params ----^])\n");
}

static void usage_i2c(void)
{
	MCTP_CTRL_INFO(
		"\t-j\t i2c own eid\n"
		"\t-q\t i2c bridge eid\n"
		"\t-y\t i2c bridge pool start eid\n"
		"To send MCTP message for I2C binding type\n"
		"Eg: Set Endpoint ID\n"
		"\t mctp-ctrl -s \"00 80 01 00 1e\" -t 1 -b \"30\" -e 0 -m 0 -v\n"
		"\t(mctp-i2c-ctrl [params ----^])\n");
}

static int64_t mctp_millis()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((int64_t)now.tv_sec) * 1000 + ((int64_t)now.tv_nsec) / 1000000;
}

static int do_mctp_cmdline(const mctp_cmdline_args_t *cmd, int sock_fd)
{
	mctp_requester_rc_t mctp_ret;
	size_t resp_msg_len;
	uint8_t *mctp_resp_msg;
	struct mctp_astpcie_pkt_private pvt_binding;
	struct mctp_smbus_pkt_private pvt_binding_smbus;
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

			/* Send the request message over socket */
			MCTP_CTRL_DEBUG(
				"%s: Pvt bind data: Routing: 0x%x, Remote ID: 0x%x\n",
				__func__, pvt_binding.routing,
				pvt_binding.remote_id);

			mctp_ret = mctp_client_with_binding_send(
				cmd->dest_eid, sock_fd,
				(const uint8_t *)cmd->tx_data, cmd->tx_len,
				&cmd->binding_type, (void *)&pvt_binding,
				sizeof(pvt_binding));

			if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
				MCTP_CTRL_ERR("%s: Failed to send message..\n",
					      __func__);
			}
		} else if (cmd->binding_type == MCTP_BINDING_SMBUS) {
			memcpy(&pvt_binding_smbus, &cmd->bind_info,
			       sizeof(struct mctp_smbus_pkt_private));

			/* Send the request message over socket */
			MCTP_CTRL_DEBUG(
				"%s: SMBUS pvt bind data: Dest slave Addr: 0x%x\n",
				__func__, pvt_binding_smbus.dest_slave_addr);

			mctp_ret = mctp_client_with_binding_send(
				cmd->dest_eid, sock_fd, (const uint8_t *)cmd->tx_data,
				cmd->tx_len, &cmd->binding_type, (void *)&pvt_binding_smbus,
				sizeof(pvt_binding_smbus));

			if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
				MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
			}
		} else {
			MCTP_CTRL_ERR("%s: Invalid binding type: %d\n",
				      __func__, cmd->binding_type);
			return MCTP_CMD_FAILED;
		}

		break;

	case MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV:
		MCTP_CTRL_INFO("%s: Supported bindigs: PCIe\n", __func__);
		MCTP_CTRL_INFO("%s: Supported bindigs: SPI\n", __func__);
		MCTP_CTRL_INFO("%s: Supported bindigs: SMBus\n", __func__);
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

uint16_t mctp_ctrl_get_target_bdf(const mctp_cmdline_args_t *cmd)
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

/* Sanity check for SMBus Endpoint IDs */
static int mctp_i2c_eids_sanity_check(uint8_t i2c_own_eid,
				      uint8_t i2c_bridge_eid,
				      uint8_t i2c_bridge_pool_start)
{
	int rc = -1;

	/* Check for SMBus own EID */
	if ((i2c_own_eid == MCTP_INVALID_EID_0) ||
		(i2c_own_eid == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid i2c_own_eid: 0x%x\n", __func__,
				i2c_own_eid);
		return rc;
	}

	/* Check for SMBus bridge EID */
	if ((i2c_bridge_eid == MCTP_INVALID_EID_0) ||
		(i2c_bridge_eid == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid i2c_bridge_eid: 0x%x\n", __func__,
				i2c_bridge_eid);
		return rc;
	}

	/* Check for SMBus bridge pool start EID */
	if ((i2c_bridge_pool_start == MCTP_INVALID_EID_0) ||
		(i2c_bridge_pool_start == MCTP_INVALID_EID_FF)) {
		MCTP_CTRL_ERR("%s: Invalid i2c_bridge_pool_start: 0x%x\n",
				__func__, i2c_bridge_pool_start);
		return rc;
	}

	/* Also check for duplicate EID's if any */
	if ((i2c_own_eid == i2c_bridge_eid) ||
		(i2c_own_eid == i2c_bridge_pool_start) ||
		(i2c_bridge_eid == i2c_bridge_pool_start)) {
		MCTP_CTRL_ERR("%s: Duplicate EID's found\n", __func__);
		return rc;
	}

	return 0;
}

// Exec command line mode
static int exec_command_line_mode(const mctp_cmdline_args_t *cmdline,
				  mctp_ctrl_t *mctp_ctrl)
{
	int rc, fd;

	MCTP_CTRL_INFO("%s: Run mode: Commandline mode\n", __func__);

	// Chosse binding type (PCIe or SMBus)
	if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		MCTP_CTRL_DEBUG("%s: Setting up PCIe socket\n", __func__);
		if(use_config_json_file_mc == false)
			mctp_sock_path = MCTP_SOCK_PATH_PCIE;
	} else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		MCTP_CTRL_DEBUG("%s: Setting up SMBus socket\n", __func__);
		if(use_config_json_file_mc == false)
			mctp_sock_path = MCTP_SOCK_PATH_I2C;
	}

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

	return do_mctp_cmdline(cmdline, mctp_ctrl->sock) == MCTP_CMD_SUCCESS ?
		       EXIT_SUCCESS :
		       EXIT_FAILURE;
}

static int exec_daemon_mode(const mctp_cmdline_args_t *cmdline,
			    mctp_ctrl_t *mctp_ctrl)
{
	int rc = -1, fd, ret;
	mctp_ret_codes_t mctp_err_ret;
	pthread_t keepalive_thread;

	if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		MCTP_CTRL_INFO("%s: Binding type: PCIe\n", __func__);
		if(use_config_json_file_mc == false)
			mctp_sock_path = MCTP_SOCK_PATH_PCIE;
		mctp_medium_type = "PCIe";

		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	}
	else if (cmdline->binding_type == MCTP_BINDING_SPI) {
		MCTP_CTRL_INFO("%s: Binding type: SPI\n", __func__);
		if(use_config_json_file_mc == false)
			mctp_sock_path = MCTP_SOCK_PATH_SPI;
		mctp_medium_type = "SPI";

		/* Open the user socket file-descriptor for CTRL MSG type */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);

		MCTP_ASSERT_RET(MCTP_REQUESTER_SUCCESS == rc, EXIT_FAILURE,
				"Failed to open mctp socket\n");

		mctp_ctrl->sock = fd;

		mctp_set_log_stdio(cmdline->verbose ? MCTP_LOG_DEBUG :
						     MCTP_LOG_WARNING);

		/* Create static endpoint 0 for spi ctrl daemon */
		mctp_spi_discover_endpoint(mctp_ctrl);
		close(fd);

		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_MESSAGE_TYPE_VDIANA,
					  MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	}
	else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		MCTP_CTRL_INFO("%s: Binding type: SMBus\n", __func__);
		if(use_config_json_file_mc == false)
			mctp_sock_path = MCTP_SOCK_PATH_I2C;
		mctp_medium_type = "SMBus";

		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path, MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	}

	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("Failed to open mctp socket\n");

		close(g_signal_fd);
		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;

	/* Update global socket pointer */
	g_socket_fd = fd;

	if (cmdline->binding_type == MCTP_BINDING_SPI) {
		ret = pthread_cond_init(&mctp_ctrl->worker_cv, NULL);
		if (ret != 0) {
			MCTP_CTRL_ERR("pthread_cond_init(3) failed.\n");
			close(g_socket_fd);
			close(g_signal_fd);
			return EXIT_FAILURE;
		}

		ret = pthread_mutex_init(&mctp_ctrl->worker_mtx, NULL);
		if (ret != 0) {
			MCTP_CTRL_ERR("pthread_mutex_init(3) failed.\n");
			close(g_socket_fd);
			close(g_signal_fd);
			return EXIT_FAILURE;
		}
	}

	/* Create D-Bus for loging event and handling D-Bus request*/
	rc = sd_bus_default_system(&mctp_ctrl->bus);
	if (rc < 0) {
		MCTP_CTRL_ERR("D-Bus failed to create\n");
		close(g_socket_fd);
		close(g_signal_fd);
		return EXIT_FAILURE;
	}
	g_sdbus = mctp_ctrl->bus;

	if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		/* Make sure all PCIe EID options are available from commandline */
		rc = mctp_pcie_eids_sanity_check(cmdline->pcie.own_eid,
						cmdline->pcie.bridge_eid,
						cmdline->pcie.bridge_pool_start);
		if (rc < 0) {
			close(g_socket_fd);
			close(g_signal_fd);
			sd_bus_unref(mctp_ctrl->bus);
			MCTP_CTRL_ERR("MCTP-Ctrl sanity check unsuccessful\n");
			return EXIT_FAILURE;
		}

		/* Discover endpoints via PCIe*/
		MCTP_CTRL_INFO("%s: Start MCTP-over-PCIe Discovery\n", __func__);
		mctp_err_ret = mctp_discover_endpoints(cmdline, mctp_ctrl);
		if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
			MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
		}
	}
	else if (cmdline->binding_type == MCTP_BINDING_SPI) {
		/* Create pthread for sening keepalive messages */
		pthread_create(&keepalive_thread, NULL, &mctp_spi_keepalive_event,
				(void *)mctp_ctrl);

		g_keepalive_thread = keepalive_thread;

		/* Wait until we can populate Dbus objects. */
		pthread_cond_wait(&mctp_ctrl->worker_cv, &mctp_ctrl->worker_mtx);
	}
	else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		switch (chosen_eid_type)
		{
		case EID_TYPE_BRIDGE:
			/* Make sure all SMBus EID options are available from commandline */
			rc = mctp_i2c_eids_sanity_check(cmdline->i2c.own_eid,
							cmdline->i2c.bridge_eid,
							cmdline->i2c.bridge_pool_start);
			if (rc < 0) {
				close(g_socket_fd);
				close(g_signal_fd);
				sd_bus_unref(mctp_ctrl->bus);
				MCTP_CTRL_ERR("MCTP-Ctrl sanity check unsuccessful\n");
				return EXIT_FAILURE;
			}

			/* Discover endpoints connected to FPGA via SMBus*/
			MCTP_CTRL_INFO("%s: Start MCTP-over-SMBus Discovery via Bridge\n", __func__);
			mctp_err_ret = mctp_i2c_discover_endpoints(cmdline, mctp_ctrl);
			if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
				MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
			}

			break;
		case EID_TYPE_STATIC:
			/* Discover static endpoint via SMBus*/
			MCTP_CTRL_INFO("%s: Start MCTP-over-SMBus Discovery as static endpoint\n", __func__);
			mctp_err_ret = mctp_i2c_discover_static_endpoint(cmdline, mctp_ctrl);
			if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
				MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
			}

			break;
		case EID_TYPE_POOL:
			mctp_prinfo("Use pool endpoints");

			break;

		default:
			break;
		}

	}

	return EXIT_SUCCESS;
}

static void parse_command_line(int argc, char *const *argv,
			       mctp_cmdline_args_t *cmdline,
			       mctp_ctrl_t *mctp_ctrl)
{
	cmdline->verbose = false;
	cmdline->binding_type = MCTP_BINDING_RESERVED;
	cmdline->delay = MCTP_CTRL_DELAY_DEFAULT;
	cmdline->ops = MCTP_CMDLINE_OP_NONE;
	cmdline->dest_eid = 8;

	memset(&cmdline->tx_data, 0, MCTP_WRITE_DATA_BUFF_SIZE);
	memset(&cmdline->rx_data, 0, MCTP_READ_DATA_BUFF_SIZE);
	uint8_t own_eid = 0, bridge_eid = 0, bridge_pool = 0;
	int vdm_ops = 0, command_mode = 0;

	/* Get the binding type parameter first,
	then assign the parameters accordingly for chosen PCIe, SPI or SMBus */
	for (;;) {
		int rc =
			getopt_long(argc, argv, short_options, g_options, NULL);
		if (rc == -1)
			break;
		if (rc == 't') {
			cmdline->binding_type = (uint8_t)atoi(optarg);
		}
	}
	optind = 1; // Reset to 1 to restart scanning

	for (;;) {
		int rc =
			getopt_long(argc, argv, short_options, g_options, NULL);
		if (rc == -1)
			break;

		switch (rc) {
		case 'v':
			cmdline->verbose = true;
			MCTP_CTRL_DEBUG("%s: Verbose level:%d\n", __func__,
					cmdline->verbose);
			g_verbose_level = cmdline->verbose;
			break;
		case 'e':
			cmdline->dest_eid = (uint8_t)atoi(optarg);
			mctp_ctrl->eid = cmdline->dest_eid;
			break;
		case 'm':
			cmdline->mode = (uint8_t)atoi(optarg);
			MCTP_CTRL_DEBUG("%s: Mode :%s\n", __func__,
					cmdline->mode ? "Daemon mode" :
							"Command line mode");
			break;
		case 't':
			break;
		case 'd':
			cmdline->delay = (int)atoi(optarg);
			break;
		case 'b':
			cmdline->bind_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline->bind_info, strlen(optarg));
			cmdline->ops = MCTP_CMDLINE_OP_BIND_WRITE_DATA;
			break;
		case 's':
			cmdline->tx_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline->tx_data, strlen(optarg));
			break;
		case 'f':
			config_json_file_path = malloc(strlen(optarg) + 1);
			memcpy(config_json_file_path, optarg, (strlen(optarg) + 1));
			use_config_json_file_mc = true;
			break;
		case 'p':
			if (cmdline->binding_type == MCTP_BINDING_PCIE) {
				bridge_eid = (uint8_t)atoi(optarg);
			}
			break;
		case 'n':
			cmdline->i2c.bus_num = (uint8_t)atoi(optarg);
			break;
		case 'j':
			if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
				own_eid = (uint8_t)atoi(optarg);
			}
			break;
		case 'q':
			if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
				bridge_eid = (uint8_t)atoi(optarg);
			}
			break;
		case 'y':
			if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
				bridge_pool = (uint8_t)atoi(optarg);
			}
			break;
		case 'i':
			if (cmdline->binding_type == MCTP_BINDING_PCIE) {
				own_eid = (uint8_t)atoi(optarg);
			}
			else if (cmdline->binding_type == MCTP_BINDING_SPI) {
				vdm_ops = atoi(optarg);
			}
			break;
		case 'x':
			if (cmdline->binding_type == MCTP_BINDING_PCIE) {
				bridge_pool = (uint8_t)atoi(optarg);
			}
			else if (cmdline->binding_type == MCTP_BINDING_SPI) {
				command_mode = atoi(optarg);
			}
			break;
		case 'h':
			if (optarg == NULL)
				usage();
			else {
				if (!strcmp(optarg, "pcie")) {
					usage_common();
					usage_pcie();
				}
				else if (!strcmp(optarg, "spi")) {
					usage_common();
					usage_spi();
				}
				else if (!strcmp(optarg, "smbus")) {
					usage_common();
					usage_i2c();
				}
				else
					printf("Wrong binding\n");
			}
			exit(EXIT_SUCCESS);
		default:
			MCTP_CTRL_ERR("Invalid argument\n");
			exit(EXIT_FAILURE);
		}
	}
	switch (cmdline->binding_type) {
	case MCTP_BINDING_PCIE:
		cmdline->pcie.bridge_eid = bridge_eid;
		cmdline->pcie.bridge_pool_start = bridge_pool;
		cmdline->pcie.own_eid = own_eid;
		break;
	case MCTP_BINDING_SPI:
		cmdline->spi.vdm_ops = vdm_ops;
		cmdline->spi.cmd_mode = command_mode;
		break;
	case MCTP_BINDING_SMBUS:
		if (use_config_json_file_mc == true) {
			int rc;

			rc = mctp_json_get_tokener_parse(config_json_file_path);

			if (rc == EXIT_FAILURE) {
				MCTP_CTRL_ERR("Json tokener parse fail\n");
				exit(EXIT_FAILURE);
			}
			else {
				// Get common parameters
				mctp_json_i2c_get_common_params_ctrl(parsed_json,
					&cmdline->i2c.bus_num, &mctp_sock_path, &cmdline->i2c.own_eid,
					&cmdline->i2c.dest_slave_addr, &cmdline->i2c.src_slave_addr);

				// Set values for SMBus private binding used in discovery
				set_g_val_for_pvt_binding(cmdline->i2c.bus_num, cmdline->i2c.dest_slave_addr,
						cmdline->i2c.src_slave_addr);

				// Get info about eid_type
				chosen_eid_type = mctp_json_get_eid_type(parsed_json, "smbus", &cmdline->i2c.bus_num);

				switch (chosen_eid_type)
				{
				case EID_TYPE_BRIDGE:
					mctp_prinfo("Use bridge endpoint");
					mctp_json_i2c_get_params_bridge_ctrl(parsed_json,
					&cmdline->i2c.bus_num, &cmdline->i2c.bridge_eid, &cmdline->i2c.bridge_pool_start);

					break;
				case EID_TYPE_STATIC:
					mctp_prinfo("Use static endpoint");
					cmdline->dest_eid_tab = NULL;
					mctp_json_i2c_get_params_static_ctrl(parsed_json,
					&cmdline->i2c.bus_num, &cmdline->dest_eid_tab,
					&cmdline->dest_eid_tab_len, &cmdline->uuid);

					break;
				case EID_TYPE_POOL:
					mctp_prinfo("Use pool endpoints");
					MCTP_CTRL_WARN("%s: EID type poll not supported\n", __func__);
					exit(EXIT_SUCCESS);

					break;

				default:
					break;
				}
			}

			// Debug info on tests

			printf("bus_num = %d, socket name = %s\n",
				cmdline->i2c.bus_num, (mctp_sock_path + 1));
			printf("src_eid = %d, bridge_eid = %d, bridge_pool_start = %d\n\n",
				cmdline->i2c.own_eid, cmdline->i2c.bridge_eid,
				cmdline->i2c.bridge_pool_start);
			// end
			free(config_json_file_path);
		}
		else {
			// Run as Bridge
			set_g_val_for_pvt_binding(MCTP_I2C_BUS_NUM_DEFAULT, MCTP_I2C_DEST_SLAVE_ADDR_DEFAULT,
					MCTP_I2C_SRC_SLAVE_ADDR_DEFAULT);
			cmdline->i2c.bridge_eid = bridge_eid;
			cmdline->i2c.bridge_pool_start = bridge_pool;
			cmdline->i2c.own_eid = own_eid;
		}
		break;
	default:
		break;
	}
}

int main(int argc, char *const *argv)
{
	int rc;
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

	parse_command_line(argc, argv, &cmdline, mctp_ctrl);

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

	/* Run this application only if set as daemon mode */
	if (cmdline.mode == MCTP_MODE_CMDLINE) { // Run mode: c. mode
		exec_command_line_mode(&cmdline, mctp_ctrl);
	} else if (cmdline.mode == MCTP_SPI_MODE_TEST) {
		if (exec_spi_test(&cmdline, mctp_ctrl) != EXIT_SUCCESS) {
			close(g_socket_fd);
			close(g_signal_fd);
			return EXIT_FAILURE;
		}
	} else { // Run mode: d. mode

		MCTP_CTRL_INFO("%s: Run mode: Daemon mode\n", __func__);

		if (exec_daemon_mode(&cmdline, mctp_ctrl) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		/* Start D-Bus initialization and monitoring */
		rc = mctp_ctrl_sdbus_init(mctp_ctrl->bus, g_signal_fd);

		if (rc < 0) {
			/* Pass the signal to threads and notify we are going to exit */
			if (cmdline.binding_type == MCTP_BINDING_SPI) {
				MCTP_CTRL_INFO(
					"Deliver the termination signal to keepalive thread\n");
				pthread_kill(g_keepalive_thread, SIGUSR2);
			}
			
			MCTP_CTRL_INFO("MCTP-Ctrl is going to terminate.\n");
			mctp_ctrl_clean_up();
			return EXIT_SUCCESS;
		}

		if (rc >= 0) {
			/* Start MCTP control daemon */
			MCTP_CTRL_INFO("%s: Start MCTP-CTRL daemon....\n",
				       __func__);
			mctp_start_daemon(mctp_ctrl);
		}
	}

	if (cmdline.binding_type == MCTP_BINDING_SPI &&
	    cmdline.mode != MCTP_SPI_MODE_TEST)
		cleanup_daemon_spi();

	mctp_ctrl_clean_up();

	return EXIT_SUCCESS;
}
