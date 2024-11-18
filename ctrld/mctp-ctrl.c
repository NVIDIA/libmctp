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
/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <bits/time.h>
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
#include <sys/timerfd.h>
#include <sys/un.h>

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-log.h"
#include "libmctp-astpcie.h"
#include "libmctp-smbus.h"
#include "libmctp-usb.h"

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
#ifdef MOCKUP_ENDPOINT
#include "fsdyn-endpoint.h"
#endif

/* MCTP Tx/Rx waittime in milli-seconds */
#define MCTP_CTRL_WAIT_SECONDS (1 * 1000)
#define MCTP_CTRL_WAIT_TIME    (2 * MCTP_CTRL_WAIT_SECONDS)

/* MCTP control retry threshold */
#define MCTP_CTRL_CMD_RETRY_THRESHOLD 3

/* MCTP Invalid EID's */
#define MCTP_INVALID_EID_0  0
#define MCTP_INVALID_EID_FF 0xFF

/* Global definitions */
uint8_t g_verbose_level = 0;

static pthread_t g_keepalive_thread = 0;
extern const uint8_t MCTP_MSG_TYPE_HDR;
extern const uint8_t MCTP_CTRL_MSG_TYPE;

char *mctp_sock_path = NULL;

/* 21 character for portpath + 14 for prefix sock name + 
end padding to avoid overflow*/
char usb_sock_path[2 * MCTP_USB_PORT_PATH_MAX_LEN] = MCTP_SOCK_PATH_USB;
const char *mctp_medium_type;

// Table with destination EIDs
static uint8_t g_dest_eid_tab[MCTP_DEST_EID_TABLE_MAX];

/* Static variables for clean up*/
int g_socket_fd = -1;
int g_signal_fd = -1;
#ifdef MOCKUP_ENDPOINT
int g_mon_fd = -1;
#endif
int g_disc_timer_fd = -1;
static sd_bus *g_sdbus = NULL;

static uint8_t chosen_eid_type = EID_TYPE_BRIDGE;
extern int command_line_mode;

extern void mctp_routing_entry_delete_all(void);
extern void mctp_uuid_delete_all(void);
extern void mctp_msg_types_delete_all(void);
extern mctp_ret_codes_t mctp_discover_endpoints(const mctp_cmdline_args_t *cmd,
						mctp_ctrl_t *ctrl,
						mctp_discovery_mode start_mode);
extern mctp_ret_codes_t
mctp_i2c_discover_endpoints(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);
extern void *mctp_spi_keepalive_event(void *arg);
extern mctp_ret_codes_t
mctp_spi_discover_endpoint(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);

#ifdef MOCKUP_ENDPOINT
// Create selected endpoint
static void mctp_emu_dyn_ep_create(const fsdyn_ep_config_t *cfg)
{
	int ret;
	MCTP_CTRL_DEBUG("Adding new emu eid %i\n", cfg->eid);
	if (cfg->has_uuid) {
		mctp_uuid_table_t uuid = { .eid = cfg->eid, .uuid = cfg->uuid };
		ret = mctp_uuid_entry_add(&uuid);
		if (ret < 0) {
			MCTP_CTRL_ERR(
				"Failed to update global UUID table err (%i)\n",
				ret);
		}
	}
	mctp_msg_type_table_t type = { .eid = cfg->eid,
				       .data_len = cfg->data_size,
				       .new = true,
				       .old_enabled = false,
				       .enabled = true };
	memcpy(type.data, cfg->data, cfg->data_size);
	ret = mctp_msg_type_entry_add(&type);
	if (ret < 0) {
		MCTP_CTRL_ERR(
			"Failed to update global routing table for option err (%i)\n",
			ret);
	}
}

static void mctp_emu_dyn_ep_remove(const fsdyn_ep_config_t *cfg)
{
	int ret;
	MCTP_CTRL_DEBUG("Removing new emu eid %i\n", cfg->eid);
	if (cfg->has_uuid) {
		ret = mctp_uuid_entry_remove(cfg->eid);
		if (ret < 0) {
			MCTP_CTRL_ERR("Failed to remove UUID by EID (%i)\n",
				      ret);
		}
	}
	ret = mctp_msg_type_entry_remove(cfg->eid);
	if (ret < 0) {
		MCTP_CTRL_ERR("Failed to remove TYPE by EID (%i)\n", ret);
	}
}

static const fsdyn_ep_ops_t fmon_emulation_fops = {
	.add = mctp_emu_dyn_ep_create,
	.remove = mctp_emu_dyn_ep_remove
};
#endif

static void mctp_ctrl_clean_up(void)
{
	/* Make sure opened threads are closed */
	if (g_keepalive_thread != 0) {
		pthread_kill(g_keepalive_thread, SIGUSR2);
		pthread_join(g_keepalive_thread, NULL);
	}

	/* Close the socket connection */
	if (g_socket_fd != -1) {
		close(g_socket_fd);
	}

	/* Close the signalfd socket */
	if (g_signal_fd != -1) {
		close(g_signal_fd);
	}

	/* Close D-Bus */
	if (g_sdbus != NULL) {
		sd_bus_unref(g_sdbus);
	}

	/* Delete Routing table entries */
	mctp_routing_entry_delete_all();

	/* Delete UUID entries */
	mctp_uuid_delete_all();

	/* Delete Msg type entries */
	mctp_msg_types_delete_all();

	/* Terminating the thread*/
	mctp_ctrl_sdbus_stop();
}

static const struct option g_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "remove_duplicates", no_argument, 0, 'c' },
	{ "eid", required_argument, 0, 'e' },
	{ "mode", required_argument, 0, 'm' },
	{ "type", required_argument, 0, 't' },
	{ "delay", required_argument, 0, 'd' },
	{ "tx", required_argument, 0, 's' },
	{ "rx", required_argument, 0, 'r' },
	{ "bindinfo", required_argument, 0, 'b' },
	{ "cfg_file_path", required_argument, 0, 'f' },
	{ "bus_num", required_argument, 0, 'n' },
	{ "uuid", required_argument, 0, 'u' },

	/* EID options */
	{ "pci_own_eid", required_argument, 0, 'i' },
	{ "i2c_own_eid", required_argument, 0, 'j' },
	{ "pci_bridge_eid", required_argument, 0, 'p' },
	{ "i2c_bridge_eid", required_argument, 0, 'q' },
	{ "pci_bridge_pool_start", required_argument, 0, 'x' },
	{ "i2c_bridge_pool_start", required_argument, 0, 'y' },
	{ "ignore_eids", required_argument, 0, 'z' },

	/* SPI specific options */
	{ "cmd_mode", required_argument, 0, 'x' },
	{ "mctp-iana-vdm", required_argument, 0, 'i' },

	/* USB specific options */
	{ "port_path", required_argument, 0, 'w' },

	{ "help", optional_argument, 0, 'h' },
	{ 0 },
};

static const char *const short_options =
	"v:c:e:m:t:d:s:r:b:f:n:u:i:j:p:q:x:y:z:w:h::";

static void usage(void)
{
	MCTP_CTRL_INFO("Usage: mctp-ctrl -h<binding>\n"
		       "(or if use script: mctp-<binding>-ctrl -h<binding>)\n"
		       "Available bindings:\n"
		       "  pcie\n"
		       "  spi\n"
		       "  smbus\n"
		       "  usb\n");
}

static void usage_common(void)
{
	MCTP_CTRL_INFO(
		"Various command line options mentioned below\n"
		"\t-v\tVerbose level\n"
		"\t-e\tTarget Endpoint Id\n"
		"\t-m\tMode: (0 - Commandline mode, 1 - daemon mode, 2 - SPI test mode)\n"
		"\t-t\tBinding Type (0 - Resvd, 1 - I2C, 2 - PCIe, 3 - USB, 6 - SPI)\n"
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
		"\t-c\t option to remove duplicate EID entries from the routing table\n"
		"\t-z\t option to ignore certain EID entries from the routing table"
		" supplied as a space separated list in decimal\n"
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
		"\t-u\tUUID:\n"
		"\t\tUUID to be set on SPI endpoint 0's D-Bus object in string format\n"
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
		"\t-z\t option to ignore certain EID entries from the routing table"
		" supplied as a space separated list in decimal\n"
		"To send MCTP message for I2C binding type\n"
		"Eg: Set Endpoint ID\n"
		"\t mctp-ctrl -s \"00 80 01 00 1e\" -t 1 -b \"30\" -e 0 -m 0 -v\n"
		"\t(mctp-i2c-ctrl [params ----^])\n");
}

// ToDo: Usage example
static void usage_usb(void)
{
	MCTP_CTRL_INFO(
		"\t-i\t usb own eid\n"
		"\t-p\t usb bridge eid\n"
		"\t-x\t usb bridge pool start eid\n"
		"\t-w\t port path of device <busid>-<port1>.<port2> eg 1-2.3 \n"
		"\t-c\t option to remove duplicate EID entries from the routing table\n"
		"\t-z\t option to ignore certain EID entries from the routing table"
		" supplied as a space separated list in decimal\n"
		"To send MCTP message for USB binding type\n"
		"Eg: Prepare for Endpoint Discovery\n");
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
		mctp_ret = MCTP_REQUESTER_SEND_FAIL;
		if (cmd->tx_len > 0) {
			mctp_ret = mctp_client_send(
				cmd->dest_eid, sock_fd, cmd->tx_data[0],
				((uint8_t *)cmd->tx_data) + 1, cmd->tx_len - 1);
		}
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
				cmd->dest_eid, sock_fd,
				(const uint8_t *)cmd->tx_data, cmd->tx_len,
				&cmd->binding_type, (void *)&pvt_binding_smbus,
				sizeof(pvt_binding_smbus));

			if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
				MCTP_CTRL_ERR("%s: Failed to send message..\n",
					      __func__);
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

			MCTP_CTRL_INFO("%s: Successfully received message\n",
				       __func__);
			break;
		}
	}

	MCTP_CTRL_INFO("Command Done in [%zu] ms\n", (size_t)(t_end - t_start));

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

int mctp_cmdline_copy_tx_buff(char src[], uint8_t *dest, int len, int base,
			      int max_buf)
{
	int i = 0, buff_len = 0;
	char *str_end = NULL;

	while ((i < len) && (buff_len < max_buf - 1)) {
		uint8_t num = (unsigned char)strtol(&src[i], &str_end, base);
		if (str_end == &src[i]) {
			break;
		}
		dest[buff_len++] = num;
		if (16 == base) {
			i = i + MCTP_CMDLINE_WRBUFF_WIDTH;
		} else {
			i = i + (str_end - &src[i]);
		}
	}

	return buff_len;
}

void mctp_handle_discovery_notify()
{
	/* Broad logic: This function bumps up discovery notify handler timer for
    another 5s. This is done to ensure that a flood of discovery notifies do
    not cause us to repeatedly perform rediscovery. Upon a timer expiry, the
    event loop will initiate a re-query of the routing table from the bridge
    and update the D-Bus objects. */

	struct itimerspec timer;

	timer.it_value.tv_sec = 5;
	timer.it_value.tv_nsec = 0;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_nsec = 0;

	if (timerfd_settime(g_disc_timer_fd, 0, &timer, NULL) == -1) {
		MCTP_CTRL_ERR(
			"%s: Failed to set discovery notify timer! errno: %d\n",
			__func__, errno);
		return;
	}
	MCTP_CTRL_INFO("%s: Bump discovery timer\n", __func__);
}

static void mctp_handle_event(mctp_ctrl_t *mctp_ctrl, uint8_t *message,
			      size_t length)
{
	/* Only certain bindings support events */
	if ((mctp_ctrl->cmdline->binding_type != MCTP_BINDING_USB) &&
	    (mctp_ctrl->cmdline->binding_type != MCTP_BINDING_PCIE)) {
		MCTP_CTRL_ERR("%s: Events unsupported for binding type: %d\n",
			      __func__, mctp_ctrl->cmdline->binding_type);
	}
	/* Need at least 3 bytes -- message type, req/datagram/seq. number byte and
	command code */
	if (length < 3) {
		MCTP_CTRL_ERR("%s: Got MCTP event with invalid length: %zu\n",
			      __func__, length);
		return;
	}
	/* Only support datagram requests/events */
	if (((message[1] & 0x80) != 0x80) || ((message[1] & 0x40) != 0x40)) {
		MCTP_CTRL_ERR(
			"%s: MCTP message has the wrong req bit or datagram bit. Req bit: %d, Datagram bit: %d\n",
			__func__, (message[1] & 0x80) >> 7,
			(message[1] & 0x40) >> 6);
		return;
	}
	switch (message[2]) {
	case 0x0D:
		mctp_handle_discovery_notify();
		break;
	default:
		MCTP_CTRL_ERR(
			"%s: Unrecognized MCTP control message type: %d\n",
			__func__, message[2]);
		break;
	}
}

int mctp_event_monitor(mctp_ctrl_t *mctp_evt)
{
	mctp_requester_rc_t mctp_ret;
	uint8_t *mctp_resp_msg;
	size_t resp_msg_len;

	/* Receive the MCTP packet */
	mctp_ret = mctp_client_recv(mctp_evt->eid, mctp_evt->sock,
				    &mctp_resp_msg, &resp_msg_len);
	MCTP_ASSERT_RET(mctp_ret == MCTP_REQUESTER_SUCCESS,
			MCTP_REQUESTER_RECV_FAIL,
			" Failed to received message %d\n", mctp_ret);

	MCTP_CTRL_DEBUG("%s: Successfully received message..\n", __func__);

	/* Handle Event */
	mctp_handle_event(mctp_evt, mctp_resp_msg, resp_msg_len);

	/* Free the Rx buffer */
	free(mctp_resp_msg);

	return MCTP_REQUESTER_SUCCESS;
}

/* Sanity check for PCIe Endpoint IDs */
static int mctp_eids_sanity_check(uint8_t pci_own_eid, uint8_t pci_bridge_eid,
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
	command_line_mode = 1;

	MCTP_CTRL_INFO("%s: Run mode: Commandline mode\n", __func__);
	mctp_set_log_stdio(cmdline->verbose ? MCTP_LOG_DEBUG :
					      MCTP_LOG_WARNING);
	// Chosse binding type (PCIe or SMBus or USB)
	if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		MCTP_CTRL_DEBUG("%s: Setting up PCIe socket\n", __func__);
		mctp_sock_path = MCTP_SOCK_PATH_PCIE;
	} else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		MCTP_CTRL_DEBUG("%s: Setting up SMBus socket\n", __func__);
		if (mctp_sock_path == NULL) {
			mctp_sock_path = MCTP_SOCK_PATH_I2C;
		}
	} else if (cmdline->binding_type == MCTP_BINDING_USB) {
		MCTP_CTRL_DEBUG("%s: Setting up USB socket\n", __func__);
		int len = strlen(&usb_sock_path[1]);
		snprintf(usb_sock_path + len + 1, sizeof(usb_sock_path) - len,
			 "-%d-%s", cmdline->usb.bus_id, cmdline->usb.port_path);
		mctp_sock_path = usb_sock_path;
	} else if (cmdline->binding_type == MCTP_BINDING_SPI) {
		MCTP_CTRL_DEBUG("%s: Setting up SPI socket\n", __func__);
		mctp_sock_path = MCTP_SOCK_PATH_SPI;
	}

	/* Open the user socket file-descriptor */
	if (cmdline->ops == MCTP_CMDLINE_OP_WRITE_DATA) {
		MCTP_CTRL_DEBUG("%s: socket init for Message Type:0x%x\n",
				__func__, cmdline->tx_data[0]);
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  cmdline->tx_data[0],
					  MCTP_CTRL_TXRX_TIMEOUT_16SECS);
	} else {
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	}
	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("[%s] Failed to open mctp socket %s\n", __func__,
			      &mctp_sock_path[1]);

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

static int open_mctp_sock(const mctp_cmdline_args_t *cmdline,
			  mctp_ctrl_t *mctp_ctrl)
{
	int rc = -1, fd;

	if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		MCTP_CTRL_INFO("%s: Binding type: PCIe\n", __func__);
		mctp_sock_path = MCTP_SOCK_PATH_PCIE;
		mctp_medium_type = "PCIe";

		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	} else if (cmdline->binding_type == MCTP_BINDING_SPI) {
		MCTP_CTRL_INFO("%s: Binding type: SPI\n", __func__);
		if (!mctp_sock_path) {
			mctp_sock_path = MCTP_SOCK_PATH_SPI;
			MCTP_CTRL_INFO(
				"%s: no specified socket path, use the default socket path: %s\n",
				__func__, mctp_sock_path);
		}
		mctp_medium_type = "SPI";

		/* Open the user socket file-descriptor for CTRL MSG type */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);

		MCTP_ASSERT_RET(MCTP_REQUESTER_SUCCESS == rc, EXIT_FAILURE,
				"[%s] Failed to open mctp socket\n", __func__);

		mctp_set_log_stdio(cmdline->verbose ? MCTP_LOG_DEBUG :
						      MCTP_LOG_WARNING);
	} else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		MCTP_CTRL_INFO("%s: Binding type: SMBus\n", __func__);
		if (mctp_sock_path == NULL) {
			mctp_sock_path = MCTP_SOCK_PATH_I2C;
		}
		mctp_medium_type = "SMBus";

		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	} else if (cmdline->binding_type == MCTP_BINDING_USB) {
		MCTP_CTRL_INFO("%s: Binding type: USB\n", __func__);
		snprintf(usb_sock_path + strlen(&usb_sock_path[1]) + 1,
			 sizeof(usb_sock_path) - strlen(&usb_sock_path[1]),
			 "-%d-%s", cmdline->usb.bus_id, cmdline->usb.port_path);
		mctp_sock_path = usb_sock_path;
		mctp_medium_type = "USB";
		/* Open the user socket file-descriptor */
		rc = mctp_usr_socket_init(&fd, mctp_sock_path,
					  MCTP_CTRL_MSG_TYPE,
					  MCTP_CTRL_TXRX_TIMEOUT_5SECS);
	} else {
		MCTP_CTRL_ERR("Unknown binding type: %d\n",
			      cmdline->binding_type);
		return EXIT_FAILURE;
	}

	if (rc != MCTP_REQUESTER_SUCCESS) {
		MCTP_CTRL_ERR("[%s] Failed to open mctp socket\n", __func__);
		return EXIT_FAILURE;
	}

	/* Update the MCTP socket descriptor */
	mctp_ctrl->sock = fd;

	/* Update global socket pointer */
	g_socket_fd = fd;
	return EXIT_SUCCESS;
}

static int exec_daemon_mode(const mctp_cmdline_args_t *cmdline,
			    mctp_ctrl_t *mctp_ctrl)
{
	mctp_ret_codes_t mctp_err_ret;
	int rc = -1;

	if (cmdline->binding_type == MCTP_BINDING_SPI) {
		/* Discover endpoints via PCIe*/
		MCTP_CTRL_INFO("%s: Start MCTP-over-SPI Discovery\n", __func__);

		/* Create static endpoint for spi ctrl daemon */
		int rc = mctp_spi_discover_endpoint(cmdline, mctp_ctrl);
		if (rc != MCTP_RET_DISCOVERY_SUCCESS) {
			MCTP_CTRL_ERR(
				"%s: MCTP spi discover endpoint failed.\n",
				__func__);
			return EXIT_FAILURE;
		}

		mctp_ctrl->worker_is_ready = false;

		int ret = pthread_cond_init(&mctp_ctrl->worker_cv, NULL);
		if (ret != 0) {
			MCTP_CTRL_ERR("pthread_cond_init(3) failed.\n");
			return EXIT_FAILURE;
		}

		ret = pthread_mutex_init(&mctp_ctrl->worker_mtx, NULL);
		if (ret != 0) {
			MCTP_CTRL_ERR("pthread_mutex_init(3) failed.\n");
			return EXIT_FAILURE;
		}

		/* Create pthread for sending keepalive messages */
		pthread_create(&g_keepalive_thread, NULL,
			       &mctp_spi_keepalive_event, (void *)mctp_ctrl);

		/* Wait until we can populate Dbus objects. */
		pthread_mutex_lock(&mctp_ctrl->worker_mtx);
		while (!mctp_ctrl->worker_is_ready) {
			pthread_cond_wait(&mctp_ctrl->worker_cv,
					  &mctp_ctrl->worker_mtx);
		}
		pthread_mutex_unlock(&mctp_ctrl->worker_mtx);
	} else if (cmdline->binding_type == MCTP_BINDING_PCIE) {
		/* Make sure all PCIe EID options are available from commandline */
		rc = mctp_eids_sanity_check(cmdline->pcie.own_eid,
					    cmdline->pcie.bridge_eid,
					    cmdline->pcie.bridge_pool_start);
		if (rc < 0) {
			MCTP_CTRL_ERR("MCTP-Ctrl sanity check unsuccessful\n");
			return EXIT_FAILURE;
		}

		/* Discover endpoints via PCIe*/
		MCTP_CTRL_INFO("%s: Start MCTP-over-PCIe Discovery\n",
			       __func__);
		mctp_err_ret = mctp_discover_endpoints(
			cmdline, mctp_ctrl,
			MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST);
		if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
			MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
#ifdef MOCKUP_ENDPOINT
			if (cmdline->mode == MCTP_MODE_MOCKUP_EID) {
				// discovery failure is allowed when mocking up EID
				return EXIT_SUCCESS;
			}
			mctp_ctrl_clean_up();
#endif
			return EXIT_FAILURE;
		}
	} else if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
		switch (chosen_eid_type) {
		case EID_TYPE_BRIDGE:
			/* Make sure all SMBus EID options are available from commandline */
			rc = mctp_i2c_eids_sanity_check(
				cmdline->i2c.own_eid, cmdline->i2c.bridge_eid,
				cmdline->i2c.bridge_pool_start);
			if (rc < 0) {
				MCTP_CTRL_ERR(
					"MCTP-Ctrl sanity check unsuccessful\n");
				return EXIT_FAILURE;
			}

			/* Discover endpoints connected to FPGA via SMBus*/
			MCTP_CTRL_INFO(
				"%s: Start MCTP-over-SMBus Discovery via Bridge\n",
				__func__);
			mctp_err_ret =
				mctp_i2c_discover_endpoints(cmdline, mctp_ctrl);
			if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
				MCTP_CTRL_ERR(
					"MCTP-Ctrl discovery unsuccessful\n");
			}

			break;
		case EID_TYPE_STATIC:
		case EID_TYPE_POOL:
			/* Discover static/pool endpoint via SMBus*/
			if (cmdline->dest_eid_tab_len == 1) {
				MCTP_CTRL_INFO(
					"%s: Start MCTP-over-SMBus Discovery as static endpoint\n",
					__func__);
			} else {
				MCTP_CTRL_INFO(
					"%s: Start MCTP-over-SMBus Discovery as pool endpoint\n",
					__func__);
			}
			mctp_err_ret = mctp_i2c_discover_static_pool_endpoint(
				cmdline, mctp_ctrl);
			if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
				MCTP_CTRL_ERR(
					"MCTP-Ctrl discovery unsuccessful\n");
			}

			break;

		default:
			break;
		}
	} else if (cmdline->binding_type == MCTP_BINDING_USB) {
		/* Make sure all USB EID options are available from commandline */
		rc = mctp_eids_sanity_check(cmdline->usb.own_eid,
					    cmdline->usb.bridge_eid,
					    cmdline->usb.bridge_pool_start);
		if (rc < 0) {
			close(g_socket_fd);
			close(g_signal_fd);
			sd_bus_unref(mctp_ctrl->bus);
			MCTP_CTRL_ERR("MCTP-Ctrl sanity check unsuccessful\n");
			return EXIT_FAILURE;
		}

		/* Discover endpoints via USB*/
		MCTP_CTRL_INFO("%s: Start MCTP-over-USB Discovery\n", __func__);
		mctp_err_ret = mctp_discover_endpoints(
			cmdline, mctp_ctrl,
			MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST);
		if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
			MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
			mctp_ctrl_clean_up();
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

void set_uuid_str(char *uuid_str, char *from, int length)
{
	int from_len = strlen(from);
	if (from_len < length) {
		MCTP_CTRL_ERR("MCTP-Ctrl input param uuid is too short");
		return;
	}

	// NOTE: afl+ gcc compiler has a compilation issue with strncpy
	for (int i = 0; i <= length; i++) {
		uuid_str[i] = from[i];
	}
}

static void parse_smbus_json_config(char *config_json_file_path,
				    mctp_cmdline_args_t *cmdline)
{
	json_object *parsed_json;
	int rc;
	rc = mctp_json_get_tokener_parse(&parsed_json, config_json_file_path);

	if (rc == EXIT_FAILURE) {
		MCTP_CTRL_ERR("[%s] Json tokener parse fail\n", __func__);
		exit(EXIT_FAILURE);
	}

	// Get common parameters
	mctp_json_i2c_get_common_params_ctrl(
		parsed_json, &cmdline->i2c.bus_num, &mctp_sock_path,
		&cmdline->i2c.own_eid, cmdline->i2c.dest_slave_addr,
		cmdline->i2c.logical_busses, &cmdline->i2c.src_slave_addr);

	// Set values for SMBus private binding used in discovery
	set_g_val_for_pvt_binding(cmdline->i2c.bus_num,
				  cmdline->i2c.dest_slave_addr[0],
				  cmdline->i2c.src_slave_addr);

	// Get info about eid_type
	chosen_eid_type = mctp_json_get_eid_type(parsed_json, "smbus",
						 &cmdline->i2c.bus_num);

	switch (chosen_eid_type) {
	case EID_TYPE_BRIDGE:
		MCTP_CTRL_INFO("[%s] Use bridge endpoint", __func__);
		mctp_json_i2c_get_params_bridge_ctrl(
			parsed_json, &cmdline->i2c.bus_num,
			&cmdline->i2c.bridge_eid,
			&cmdline->i2c.bridge_pool_start);

		break;
	case EID_TYPE_STATIC:
		MCTP_CTRL_INFO("[%s] Use static endpoint", __func__);
		cmdline->dest_eid_tab = g_dest_eid_tab;
		mctp_json_i2c_get_params_static_ctrl(
			parsed_json, &cmdline->i2c.bus_num, g_dest_eid_tab,
			&cmdline->dest_eid_tab_len, &cmdline->uuid);

		break;
	case EID_TYPE_POOL:
		MCTP_CTRL_INFO("[%s] Use pool endpoints", __func__);
		cmdline->dest_eid_tab = g_dest_eid_tab;
		mctp_json_i2c_get_params_pool_ctrl(parsed_json,
						   &cmdline->i2c.bus_num,
						   g_dest_eid_tab,
						   &cmdline->dest_eid_tab_len);

		break;

	default:
		break;
	}

	// free parsed json object
	json_object_put(parsed_json);
}

static void parse_spi_json_config(char *config_json_file_path,
				  mctp_cmdline_args_t *cmdline)
{
	json_object *parsed_json;
	int rc;
	rc = mctp_json_get_tokener_parse(&parsed_json, config_json_file_path);

	if (rc == EXIT_FAILURE) {
		MCTP_CTRL_ERR("[%s] Json tokener parse fail\n", __func__);
		exit(EXIT_FAILURE);
	}

	// Get common parameters
	mctp_json_spi_get_params_ctrl(parsed_json, &mctp_sock_path, cmdline);

	// free json object
	json_object_put(parsed_json);
}

static void parse_command_line(int argc, char *const *argv,
			       mctp_cmdline_args_t *cmdline,
			       mctp_ctrl_t *mctp_ctrl)
{
	char *config_json_file_path = NULL;

	cmdline->verbose = false;
	cmdline->use_json = false;
	cmdline->binding_type = MCTP_BINDING_RESERVED;
	cmdline->delay = MCTP_CTRL_DELAY_DEFAULT;
	cmdline->ops = MCTP_CMDLINE_OP_WRITE_DATA;
	cmdline->dest_eid = 8;

	memset(&cmdline->tx_data, 0, MCTP_WRITE_DATA_BUFF_SIZE);
	memset(&cmdline->rx_data, 0, MCTP_READ_DATA_BUFF_SIZE);
	memset(&cmdline->uuid_str, 0, sizeof(cmdline->uuid_str));
	uint8_t own_eid = 0, bridge_eid = 0, bridge_pool = 0;
	int vdm_ops = 0, command_mode = 0;
	bool remove_duplicates = false;

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
			g_verbose_level = cmdline->verbose;
			mctp_set_tracing_enabled(cmdline->verbose);
			MCTP_CTRL_INFO("%s: Verbose level:%d\n", __func__,
				       cmdline->verbose);
			break;
		case 'c':
			remove_duplicates = true;
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
				optarg, cmdline->bind_info, strlen(optarg), 16,
				sizeof(cmdline->bind_info) /
					sizeof(cmdline->bind_info[0]));
			cmdline->ops = MCTP_CMDLINE_OP_BIND_WRITE_DATA;
			break;
		case 's':
			cmdline->tx_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline->tx_data, strlen(optarg), 16,
				sizeof(cmdline->tx_data) /
					sizeof(cmdline->tx_data[0]));
			break;
		case 'z':
			cmdline->ignore_eids_len = mctp_cmdline_copy_tx_buff(
				optarg, cmdline->ignore_eids, strlen(optarg),
				10,
				sizeof(cmdline->ignore_eids) /
					sizeof(cmdline->ignore_eids[0]));
			MCTP_CTRL_INFO("%s: No. of EIDs to ignore: %d\n",
				       __func__, cmdline->ignore_eids_len);
			for (int i = 0; i < cmdline->ignore_eids_len; ++i) {
				MCTP_CTRL_INFO("%s: EID to ignore: %d\n",
					       __func__,
					       cmdline->ignore_eids[i]);
			}
			break;
		case 'u':
			set_uuid_str(cmdline->uuid_str, optarg, UUID_STR_LEN);
			break;
		case 'f':
			if (config_json_file_path == NULL) {
				config_json_file_path =
					malloc(strlen(optarg) + 1);
				memcpy(config_json_file_path, optarg,
				       (strlen(optarg) + 1));
				cmdline->use_json = true;
			}
			break;
		case 'p':
			if (cmdline->binding_type == MCTP_BINDING_PCIE ||
			    cmdline->binding_type == MCTP_BINDING_USB) {
				bridge_eid = (uint8_t)atoi(optarg);
			}
			break;
		case 'n':
			if (cmdline->binding_type == MCTP_BINDING_SMBUS) {
				cmdline->i2c.bus_num = (uint8_t)atoi(optarg);
			}
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
			if (cmdline->binding_type == MCTP_BINDING_PCIE ||
			    cmdline->binding_type == MCTP_BINDING_USB) {
				own_eid = (uint8_t)atoi(optarg);
			} else if (cmdline->binding_type == MCTP_BINDING_SPI) {
				vdm_ops = atoi(optarg);
			}
			break;
		case 'x':
			if (cmdline->binding_type == MCTP_BINDING_PCIE ||
			    cmdline->binding_type == MCTP_BINDING_USB) {
				bridge_pool = (uint8_t)atoi(optarg);
			} else if (cmdline->binding_type == MCTP_BINDING_SPI) {
				command_mode = atoi(optarg);
			}
			break;
		case 'w':
			if (cmdline->binding_type == MCTP_BINDING_USB) {
				//get busid from port path which is separated via -
				char recv_usb_path[2 *
						   MCTP_USB_PORT_PATH_MAX_LEN];
				strncpy(recv_usb_path, optarg,
					2 * MCTP_USB_PORT_PATH_MAX_LEN);
				char *hyphen_pos = strchr(recv_usb_path, '-');
				if (hyphen_pos) {
					char *start = recv_usb_path;
					*hyphen_pos = '\0';
					cmdline->usb.bus_id = atoi(start);
				} else {
					MCTP_CTRL_INFO(
						"%s: No Bus id in port path: %s\n",
						__func__, optarg);
					exit(EXIT_FAILURE);
				}
				strncpy(cmdline->usb.port_path, hyphen_pos + 1,
					sizeof(cmdline->usb.port_path));

				// Convert port_path .  to -
				if (strlen(cmdline->usb.port_path) == 0) {
					MCTP_CTRL_INFO(
						"%s: No port hierarchy in port path: %s\n",
						__func__,
						cmdline->usb.port_path);
					exit(EXIT_FAILURE);
				}
				for (size_t i = 0;
				     i < strlen(cmdline->usb.port_path); i++) {
					if (cmdline->usb.port_path[i] == '.') {
						cmdline->usb.port_path[i] = '-';
					}
				}
			}
			break;
		case 'h':
			if (optarg == NULL)
				usage();
			else {
				if (!strcmp(optarg, "pcie")) {
					usage_common();
					usage_pcie();
				} else if (!strcmp(optarg, "spi")) {
					usage_common();
					usage_spi();
				} else if (!strcmp(optarg, "smbus")) {
					usage_common();
					usage_i2c();
				} else if (!strcmp(optarg, "usb")) {
					usage_common();
					usage_usb();
				} else
					MCTP_CTRL_ERR("Wrong binding\n");
			}
			free(config_json_file_path);
			exit(EXIT_SUCCESS);
		default:
			MCTP_CTRL_ERR("Invalid argument: 0x%02x\n", rc);
			free(config_json_file_path);
			exit(EXIT_FAILURE);
		}
	}

	switch (cmdline->binding_type) {
	case MCTP_BINDING_PCIE:
		cmdline->pcie.bridge_eid = bridge_eid;
		cmdline->pcie.bridge_pool_start = bridge_pool;
		cmdline->pcie.own_eid = own_eid;
		cmdline->pcie.remove_duplicates = remove_duplicates;
		break;
	case MCTP_BINDING_SPI:
		cmdline->spi.vdm_ops = vdm_ops;
		cmdline->spi.cmd_mode = command_mode;
		cmdline->spi.hb_enable = true;
		if (config_json_file_path != NULL) {
			parse_spi_json_config(config_json_file_path, cmdline);
			mctp_ctrl->eid = cmdline->dest_eid;
		}
		break;
	case MCTP_BINDING_SMBUS:
		if (config_json_file_path != NULL) {
			parse_smbus_json_config(config_json_file_path, cmdline);
		} else {
			// Run as Bridge
			set_g_val_for_pvt_binding(
				MCTP_I2C_BUS_NUM_DEFAULT,
				MCTP_I2C_DEST_SLAVE_ADDR_DEFAULT,
				MCTP_I2C_SRC_SLAVE_ADDR_DEFAULT);
			cmdline->i2c.bridge_eid = bridge_eid;
			cmdline->i2c.bridge_pool_start = bridge_pool;
			cmdline->i2c.own_eid = own_eid;
		}
		break;
	case MCTP_BINDING_USB:
		cmdline->usb.bridge_eid = bridge_eid;
		cmdline->usb.bridge_pool_start = bridge_pool;
		cmdline->usb.own_eid = own_eid;
		cmdline->usb.remove_duplicates = remove_duplicates;
		break;
	default:
		break;
	}
	free(config_json_file_path);
}

#ifdef MOCKUP_ENDPOINT
// Custom event handler
static int mctp_ctrl_sdbus_custom_event(void *ctx)
{
	return fsdyn_ep_poll_handler((fsdyn_ep_context_ptr)ctx);
}
#endif

int main_ctrl(int argc, char *const *argv)
{
	int rc;
	sigset_t mask;
	mctp_ctrl_t *mctp_ctrl, _mctp_ctrl;
	mctp_cmdline_args_t cmdline;
	int ret_val = EXIT_SUCCESS;
#ifdef MOCKUP_ENDPOINT
	fsdyn_ep_context_ptr filemon;
#endif

	/* Initialize MCTP ctrl structure */
	mctp_ctrl = &_mctp_ctrl;
	mctp_ctrl->type = MCTP_MSG_TYPE_HDR;
	mctp_ctrl->perform_rediscovery = false;

	/* Initialize the cmdline structure */
	memset(&cmdline, 0, sizeof(cmdline));
	mctp_ctrl->cmdline = &cmdline;

	/* Update the cmdline sturcture with default values */
	const char *const mctp_ctrl_name = argv[0];
	strncpy(cmdline.name, mctp_ctrl_name, sizeof(mctp_ctrl_name) - 1);

	parse_command_line(argc, argv, &cmdline, mctp_ctrl);

#if USE_FUZZ_CTRL
	MCTP_CTRL_INFO("Running in Fuzz mode\n");
#endif

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		MCTP_CTRL_ERR("Failed to signalmask\n");
		return -1;
	}

	g_signal_fd = signalfd(-1, &mask, 0);
	MCTP_ASSERT_RET(g_signal_fd >= 0, EXIT_FAILURE,
			"Failed to open signalfd\n");

	/* sleep before starting the daemon */
	sleep(cmdline.delay);

#ifdef MOCKUP_ENDPOINT
	filemon = fsdyn_ep_mon_start(MCTP_CTRL_EMU_CFG_DIR,
				     MCTP_CTRL_EMU_CFG_FILE,
				     MCTP_CTRL_EMU_CFG_JSON_ROOT,
				     &fmon_emulation_fops);

	/* Populate Dbus objects */
	mctp_sdbus_fd_watch_t extra_mon = {
		.ctx = filemon,
		.fd_mon = fsdyn_ep_get_fd(filemon),
		.fd_event = mctp_ctrl_sdbus_custom_event
	};
#endif
	/* Run this application only if set as daemon mode */
	if (cmdline.mode == MCTP_MODE_CMDLINE) {
		// Run mode: command line mode
		exec_command_line_mode(&cmdline, mctp_ctrl);
	} else if (cmdline.mode == MCTP_SPI_MODE_TEST) {
		// Run mode: SPI test mode
		if (exec_spi_test(&cmdline, mctp_ctrl) != EXIT_SUCCESS) {
			MCTP_CTRL_ERR("Sending SPI test command failure\n");
			ret_val = EXIT_FAILURE;
		}
	} else {
		// Run mode: daemon mode
		MCTP_CTRL_INFO("%s: Run mode: Daemon mode\n", __func__);
#if !USE_FUZZ_CTRL
		/* Create D-Bus for loging event and handling D-Bus request*/
		rc = sd_bus_default_system(&mctp_ctrl->bus);
#else
		/* For Fuzz tests create user D-Bus */
		rc = sd_bus_open_user(&mctp_ctrl->bus);
#endif
		if (rc < 0) {
			MCTP_CTRL_ERR("D-Bus failed to create\n");
			return EXIT_FAILURE;
		}
		g_sdbus = mctp_ctrl->bus;

		if (open_mctp_sock(&cmdline, mctp_ctrl) != EXIT_SUCCESS) {
			MCTP_CTRL_ERR("MCTP socket open failure\n");
			ret_val = EXIT_FAILURE;
		}

		mctp_sdbus_context_t *context = mctp_ctrl_sdbus_create_context(
			mctp_ctrl->bus, &cmdline);
		if (context == NULL) {
			MCTP_CTRL_ERR("%s: Context is null\n", __func__);
			ret_val = EXIT_FAILURE;
		}

		if (exec_daemon_mode(&cmdline, mctp_ctrl) != EXIT_SUCCESS) {
			MCTP_CTRL_ERR("Running demon mode failure\n");
			ret_val = EXIT_FAILURE;
		} else {
			if (-1 == g_disc_timer_fd) {
				MCTP_CTRL_INFO(
					"%s: Creating discovery timer for the first time\n",
					__func__);
				g_disc_timer_fd = timerfd_create(
					CLOCK_MONOTONIC, TFD_NONBLOCK);
			}

			/* Arm the rediscovery timer in case we got any discovery notifies
			during the discovery process */
			if (mctp_ctrl->perform_rediscovery == true) {
				MCTP_CTRL_INFO(
					"%s: Re-arm discovery timer after handling discovery notify\n",
					__func__);
				mctp_handle_discovery_notify();
				mctp_ctrl->perform_rediscovery = false;
			}
			MCTP_CTRL_INFO("%s: Initiate dbus\n", __func__);
#ifdef MOCKUP_ENDPOINT
			/* Start D-Bus initialization and monitoring */
			rc = mctp_ctrl_sdbus_init(mctp_ctrl, g_signal_fd,
						  &cmdline, &extra_mon,
						  context);
#else
			/* Start D-Bus initialization and monitoring */
			rc = mctp_ctrl_sdbus_init(mctp_ctrl, g_signal_fd,
						  &cmdline, context);
#endif

			MCTP_CTRL_INFO("%s: Event Loop Exit: result = %d\n",
				       __func__, rc);

			MCTP_CTRL_INFO("MCTP-Ctrl is going to terminate.\n");
			ret_val = (rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
		}
	}

	mctp_ctrl_clean_up();

#ifdef MOCKUP_ENDPOINT
	/* Disable monitoring service */
	fsdyn_ep_mon_stop(filemon);
#endif
	return ret_val;
}

#if !USE_FUZZ_CTRL
int main(int argc, char *const *argv)
{
	return main_ctrl(argc, argv);
}
#endif
