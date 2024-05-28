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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <threads.h>
#include <time.h>
#include <getopt.h>
#include <sys/auxv.h> // required for getauxval

#include "../mctp-ctrl.h"
#include "../../libmctp-cmds.h"
#include "../mctp-ctrl-cmds.h"
#include "../mctp-encode.h"
#include "../mctp-discovery-common.h"

#include "../../libmctp-externals.h"
#include "vdm/nvidia/libmctp-vdm-cmds.h"
#include "vdm/nvidia/mctp-vdm-commands.h"

/* Verbose level:
    0 - only crucial information;
    1 - more crucial logs for fuzzer;
    2 - debugs and info for fuzzer;
    3 - plus trace for fuzzer;
    4 - turn on verbose level for the UUT
*/
int g_fuzz_verbose_level = 0;

/* Use random input (true) or standard input (false) */
bool g_random_input = false;

/* Demux socket path for test purposes */
char *g_socket_path = MCTP_SOCK_PATH_PCIE;

/* By default choose random interface, or set:
    1, for SMBUS;
    2, for PCIE;
    3, for USB;
    6, for SPI.
*/
int g_tested_interface_type = 1000;

/* Number of used random values in one test run */
static uint32_t g_random_values = 0;

/* threads management */
pthread_mutex_t mctp_ctrl_mock_sync_mutex;
pthread_mutexattr_t mctp_ctrl_mock_sync_mutex_attr;
pthread_cond_t mctp_ctrl_mock_sync_cond = PTHREAD_COND_INITIALIZER;
bool mctp_ctrl_fuzz_thread_is_ready = false;

/* Warning: those values MUST much config json settings */
#define MCTP_SOCKET_NAME_NIC_CFG_JSON "\0/tmp/mctp-i2c2-mux"
#define MCTP_SOCKET_NAME_CONFIG_JSON  "\0mctp-i2c1-mux"

#define nullptr 0

#define LOG(format, ...)                                                       \
	do {                                                                   \
		if (g_fuzz_verbose_level >= 2) {                               \
			fprintf(stdout, format, ##__VA_ARGS__);                \
			fprintf(stdout, "\n");                                 \
		}                                                              \
	} while (0)

#define LOG_FR(format, ...)                                                    \
	do {                                                                   \
		if (g_fuzz_verbose_level >= 2) {                               \
			fprintf(stdout, "[FR at %s:%d]: ", __func__,           \
				__LINE__);                                     \
			LOG(format, ##__VA_ARGS__);                            \
		}                                                              \
	} while (0)

#define LOG_ML(format, ...)                                                    \
	do {                                                                   \
		if (g_fuzz_verbose_level >= 2) {                               \
			fprintf(stdout, "[ML at %s:%d]: ", __func__,           \
				__LINE__);                                     \
			LOG(format, ##__VA_ARGS__);                            \
		}                                                              \
	} while (0)

#define LOG_ERR(format, ...)                                                   \
	do {                                                                   \
		if (g_fuzz_verbose_level >= 1) {                               \
			fprintf(stdout, "[FR][ERR at %s:%d]: ", __func__,      \
				__LINE__);                                     \
			fprintf(stderr, format, ##__VA_ARGS__);                \
			fprintf(stderr, "\n");                                 \
		}                                                              \
	} while (0)

#define LOG_HEX(data, size, label)                                             \
	do {                                                                   \
		if (g_fuzz_verbose_level >= 4) {                               \
			printf("\n");                                          \
			fprintf(stdout, "[FR][HEX][%s]: { ", (label));         \
			for (unsigned int i = 0; i < (unsigned int)(size);     \
			     i++) {                                            \
				printf("%02X ", (data)[i]);                    \
			}                                                      \
			printf("}\n");                                         \
		}                                                              \
	} while (0)

struct thread_args {
	int argc;
	char **argv;
};

uint8_t getUint8tFromInput()
{
	return (uint8_t)getchar();
}

uint8_t getUint8tUrand()
{
	return (uint8_t)(rand() % 256);
}

uint8_t getUint8t()
{
	g_random_values++;
	return g_random_input ? getUint8tUrand() : getUint8tFromInput();
}

/* For MCTP CTRL daemon the packets sizes are up to 68 bytes,
    so we can safely make bitflip only on one position */
void flipRandomBits(uint8_t *data, size_t size)
{
	/* Randomize byte number and make one bitflip on the randomized position */
	int byte_number = getUint8t() % size;
	int seed = getUint8t() % 2;
	int bit_number = getUint8t() % 8;
	if (seed > 0) {
		data[byte_number] ^= (1 << bit_number);
	}
}

static uint8_t createInstanceId()
{
	static uint8_t instanceId = 0x00;

	instanceId = (instanceId)&MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	return instanceId;
}

static uint8_t getRqDgramInst()
{
	uint8_t instanceID = createInstanceId();
	uint8_t rqDgramInst = instanceID | MCTP_CTRL_HDR_FLAG_REQUEST;
	return rqDgramInst;
}

static void encode_ctrl_cmd_header(struct mctp_ctrl_cmd_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

/* Buffer for messages received and sent to UUT: MCTP client */
#define MCTP_MAX_CTRL_MESSAGE_SIZE 1024
uint8_t mctp_resp_buf[MCTP_MAX_CTRL_MESSAGE_SIZE];
uint8_t mctp_req_buf[MCTP_MAX_CTRL_MESSAGE_SIZE];

static int manage_rx_packets(int client_fd, int bytes_received)
{
	size_t resp_len = 0;
	struct mctp_ctrl_cmd_msg_hdr hdr;
	size_t mctp_prefix_len = 1 /* HEADER TAG byte */ + sizeof(mctp_eid_t);
	uint8_t mctp_tag = getUint8t();
	uint8_t mctp_prefix = getUint8t();
	size_t buffer_size = mctp_prefix_len + sizeof(struct mctp_ctrl_resp);
	int rec_msg_length = 8;

	if (g_tested_interface_type == MCTP_BINDING_SMBUS) {
		rec_msg_length = 37;
	} else if (g_tested_interface_type == MCTP_BINDING_PCIE) {
		rec_msg_length = 8;
	} else if (g_tested_interface_type == MCTP_BINDING_USB) {
		rec_msg_length = 34;
	} else if (g_tested_interface_type == MCTP_BINDING_SPI) {
		rec_msg_length = 34;
	} else {
		LOG_FR("Interface type is not supported, using defaults as for PCIE");
	}

	if (bytes_received < (rec_msg_length + 4)) {
		/* The minimum number of received bytes is expected as:
            8 bytes for PCIe, or
            34 bytes for SPI and USB, or
            37 bytes for SMBUS
            + 4 bytes of MCTP ctrl messag 
        */
		LOG_FR("Expect messages of at least %d bytes, ignoring",
		       rec_msg_length + 4);
		return 0;
	}

	memset(&mctp_resp_buf, 0, buffer_size);
	struct mctp_ctrl_resp *response =
		(struct mctp_ctrl_resp *)&(mctp_resp_buf[mctp_prefix_len]);

	mctp_resp_buf[0] = mctp_tag;
	mctp_resp_buf[1] = mctp_prefix;

	/* MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST */
	if ((mctp_req_buf[rec_msg_length] == 0) &&
	    (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
	    (mctp_req_buf[rec_msg_length + 2] ==
	     MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY)) {
		struct mctp_ctrl_resp_prepare_discovery prep_discovery_resp;
		encode_ctrl_cmd_header(
			&hdr, getRqDgramInst(),
			MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY);
		prep_discovery_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
		prep_discovery_resp.ctrl_hdr = hdr;

		resp_len = sizeof(prep_discovery_resp);
		memcpy(response, &prep_discovery_resp,
		       sizeof(prep_discovery_resp));
	}
	/* MCTP_CTRL_CMD_ENDPOINT_DISCOVERY */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_ENDPOINT_DISCOVERY)) {
		struct mctp_ctrl_resp_endpoint_discovery resp_ep_discovery;
		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_ENDPOINT_DISCOVERY);
		resp_ep_discovery.completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_ep_discovery.ctrl_hdr = hdr;

		resp_len = sizeof(resp_ep_discovery);
		memcpy(response, &resp_ep_discovery, sizeof(resp_ep_discovery));
		/**/
	}
	/* MCTP_SET_EP_REQUEST */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_SET_ENDPOINT_ID)) {
		struct mctp_ctrl_resp_set_eid resp_set_eid;
		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
		resp_set_eid.ctrl_hdr = hdr;
		resp_set_eid.completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_set_eid.status = getUint8t();
		resp_set_eid.eid_set = getUint8t();
		resp_set_eid.eid_pool_size = getUint8t();

		resp_len = sizeof(struct mctp_ctrl_resp_set_eid);
		memcpy(response, &resp_set_eid, resp_len);
	}
	/* MCTP_ALLOCATE_EP_ID_REQUEST */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS)) {
		struct mctp_ctrl_resp_alloc_eid resp_alloc_eid;
		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
		resp_alloc_eid.completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_alloc_eid.ctrl_hdr = hdr;
		resp_alloc_eid.alloc_status = getUint8t();
		resp_alloc_eid.eid_start = getUint8t();
		resp_alloc_eid.eid_pool_size = getUint8t();

		resp_len = sizeof(resp_alloc_eid);
		memcpy(response, &resp_alloc_eid, sizeof(resp_alloc_eid));
	}
	/* MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES)) {
		struct mctp_ctrl_resp_get_routing_table get_routing_table;
		struct get_routing_table_entry routing_table_entry;
		int entries_cnt = 0;

		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
		get_routing_table.completion_code = MCTP_CTRL_CC_SUCCESS;
		get_routing_table.next_entry_handle = getUint8t();
		get_routing_table.number_of_entries = entries_cnt = getUint8t();

		//resp_len = sizeof(struct mctp_ctrl_resp_get_routing_table);
		resp_len = sizeof(get_routing_table);
		memcpy(response, &get_routing_table, sizeof(get_routing_table));

		for (int i = 0; i < entries_cnt; ++i) {
			routing_table_entry.eid_range_size = getUint8t();
			routing_table_entry.starting_eid = getUint8t();
			routing_table_entry.entry_type = getUint8t();
			routing_table_entry.phys_transport_binding_id =
				getUint8t();
			routing_table_entry.phys_media_type_id = getUint8t();
			routing_table_entry.phys_address_size = getUint8t();

			memcpy(((uint8_t *)response) + resp_len,
			       &routing_table_entry,
			       sizeof(struct get_routing_table_entry));

			resp_len += sizeof(struct get_routing_table_entry);

			if (resp_len > (sizeof(struct mctp_ctrl_resp) -
					sizeof(struct get_routing_table_entry)))
				break;
		}
	}
	/* MCTP_CTRL_CMD_GET_ENDPOINT_UUID */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_GET_ENDPOINT_UUID)) {
		struct mctp_ctrl_resp_get_uuid resp_get_uuid;
		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
		resp_get_uuid.completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_get_uuid.uuid.raw[0] = getUint8t();
		resp_get_uuid.uuid.raw[1] = getUint8t();
		resp_get_uuid.uuid.raw[2] = getUint8t();
		resp_get_uuid.uuid.raw[3] = getUint8t();
		resp_get_uuid.uuid.raw[4] = getUint8t();
		resp_get_uuid.uuid.raw[5] = getUint8t();
		resp_get_uuid.uuid.raw[6] = getUint8t();
		resp_get_uuid.uuid.raw[7] = getUint8t();
		resp_get_uuid.uuid.raw[8] = getUint8t();
		resp_get_uuid.uuid.raw[9] = getUint8t();
		resp_get_uuid.uuid.raw[10] = getUint8t();
		resp_get_uuid.uuid.raw[11] = getUint8t();
		resp_get_uuid.uuid.raw[12] = getUint8t();
		resp_get_uuid.uuid.raw[13] = getUint8t();
		resp_get_uuid.uuid.raw[14] = getUint8t();
		resp_get_uuid.uuid.raw[15] = getUint8t();

		resp_len = sizeof(resp_get_uuid);
		memcpy(response, &resp_get_uuid, sizeof(resp_get_uuid));
	}
	/* MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)) {
		struct mctp_ctrl_resp_get_msg_type_support
			resp_get_msg_type_support;
		int entries_cnt = 0;

		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
		resp_get_msg_type_support.completion_code =
			MCTP_CTRL_CC_SUCCESS;
		resp_get_msg_type_support.msg_type_count = entries_cnt =
			getUint8t();

		resp_len = sizeof(resp_get_msg_type_support);
		memcpy(response, &resp_get_msg_type_support,
		       sizeof(resp_get_msg_type_support));

		for (int i = 0; i < entries_cnt; ++i) {
			((uint8_t *)response)[resp_len++] = getUint8t();
			if (resp_len >
			    (sizeof(struct mctp_ctrl_resp) -
			     sizeof(struct mctp_ctrl_resp_get_msg_type_support)))
				break;
		}
	}
	/* MCTP_CTRL_CMD_GET_ENDPOINT_ID */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_GET_ENDPOINT_ID)) {
		struct mctp_ctrl_resp_get_eid resp_get_eid;

		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
		resp_get_eid.completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_get_eid.eid = getUint8t();
		resp_get_eid.eid_type = getUint8t();
		resp_get_eid.medium_data = getUint8t();

		resp_len = sizeof(resp_get_eid);
		memcpy(response, &resp_get_eid, sizeof(resp_get_eid));
	}
	/* MCTP_CTRL_CMD_GET_VERSION_SUPPORT */
	else if ((mctp_req_buf[rec_msg_length] == 0) &&
		 (mctp_req_buf[rec_msg_length + 1] == 0x80) &&
		 (mctp_req_buf[rec_msg_length + 2] ==
		  MCTP_CTRL_CMD_GET_VERSION_SUPPORT)) {
		struct mctp_ctrl_resp_get_mctp_ver_support
			resp_get_mctp_ver_support;
		int entries_cnt = 0;

		encode_ctrl_cmd_header(&hdr, getRqDgramInst(),
				       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
		resp_get_mctp_ver_support.completion_code =
			MCTP_CTRL_CC_SUCCESS;
		resp_get_mctp_ver_support.number_of_entries = entries_cnt =
			getUint8t();

		resp_len = sizeof(resp_get_mctp_ver_support);
		memcpy(response, &resp_get_mctp_ver_support,
		       sizeof(resp_get_mctp_ver_support));

		for (int i = 0; i < entries_cnt; ++i) {
			struct version_entry resp_version_entry;
			resp_version_entry.major = getUint8t();
			resp_version_entry.minor = getUint8t();
			resp_version_entry.update = getUint8t();
			resp_version_entry.alpha = getUint8t();

			memcpy(((uint8_t *)response) + resp_len,
			       &resp_version_entry,
			       sizeof(struct version_entry));

			resp_len += sizeof(struct version_entry);

			if (resp_len >
			    (sizeof(struct mctp_ctrl_resp) -
			     sizeof(struct mctp_ctrl_resp_get_mctp_ver_support)))
				break;
		}
	}

	if (resp_len > 0) {
		resp_len += mctp_prefix_len;
		LOG_FR("Response length = %zi, prefix length = %zi", resp_len,
		       mctp_prefix_len);

		flipRandomBits(((uint8_t *)mctp_resp_buf), resp_len);
		LOG_HEX((uint8_t *)mctp_resp_buf, resp_len, "write");

		int send_return_code;
		if ((send_return_code =
			     write(client_fd, mctp_resp_buf, resp_len)) == -1) {
			LOG_ERR("Write error %d, response is not sent, errno = %d",
				send_return_code, errno);
			//               err(EXIT_FAILURE, "Write error %d", send_return_code);
			if (errno == EPIPE) {
				/* Client closed the connection */
				return -1;
			}
		} else {
			LOG_FR("Response sent");
		}
	} else {
		LOG_FR("Warning: received unsupported message type - no fuzzing");
		LOG_FR("  0x%02x, 0x%02x, 0x%02x", mctp_req_buf[rec_msg_length],
		       mctp_req_buf[rec_msg_length + 1],
		       mctp_req_buf[rec_msg_length + 2]);
	}

	return 0;
}

static int manage_rx_vendor_packets(int client_fd, int bytes_received)
{
	size_t resp_len = 0;
	size_t mctp_prefix_len = 1 /* HEADER TAG byte */ + sizeof(mctp_eid_t);

	if (bytes_received < 11) {
		/* The minimum number of received bytes VDM message is 11
        */
		LOG_FR("Expect messages of at least %d bytes, ignoring", 11);
		return 0;
	}

	if (mctp_req_buf[0] != 0x0A) {
		LOG_ERR("Expected tag header byte of VDM: 0x0A, but received 0x%02x",
			mctp_req_buf[0]);
		return 0;
	}
	if (mctp_req_buf[2] != MCTP_MESSAGE_TYPE_VDIANA) {
		LOG_ERR("Expected message type VDIANA 0x7F, but received 0x%02x",
			mctp_req_buf[2]);
		return 0;
	}
	if (mctp_req_buf[3] != 0) {
		LOG_ERR("Expected iana value 0x00, but received 0x%02x",
			mctp_req_buf[3]);
		return 0;
	}
	if (mctp_req_buf[4] != 0) {
		LOG_ERR("Expected iana value 0x00, but received 0x%02x",
			mctp_req_buf[4]);
		return 0;
	}
	if (mctp_req_buf[5] != 0x16) {
		LOG_ERR("Expected iana value 0x16, but received 0x%02x",
			mctp_req_buf[5]);
		return 0;
	}
	if (mctp_req_buf[6] != 0x47) {
		LOG_ERR("Expected iana value 0x47, but received 0x%02x",
			mctp_req_buf[6]);
		return 0;
	}

	memset(&mctp_resp_buf, 0, MCTP_MAX_CTRL_MESSAGE_SIZE);

	mctp_resp_buf[0] = MCTP_TAG_VDM;
	mctp_resp_buf[1] = mctp_req_buf[1]; /* requester EID */

	/* MCTP_VENDOR_CMD_BOOTCOMPLETE */
	if ((mctp_req_buf[8] == 0x01) &&
	    (mctp_req_buf[9] == MCTP_VENDOR_CMD_BOOTCOMPLETE) &&
	    (mctp_req_buf[10] == 0x02)) {
		mctp_resp_buf[2] = MCTP_VENDOR_MSG_TYPE;
		/* struct mctp_vendor_msg_hdr */
		mctp_resp_buf[3] = 0;		      /* iana */
		mctp_resp_buf[4] = 0;		      /* iana */
		mctp_resp_buf[5] = 0x16;	      /* iana */
		mctp_resp_buf[6] = 0x47;	      /* iana */
		mctp_resp_buf[7] = 0x80;	      /* rq_dgram_inst */
		mctp_resp_buf[8] = 0x01;	      /* vendor_msg_type */
		mctp_resp_buf[9] =
			MCTP_VENDOR_CMD_BOOTCOMPLETE; /* command_code */
		mctp_resp_buf[10] = 0x02;	      /* msg_version */
		resp_len = 11;
	}
	/* MCTP_VENDOR_CMD_ENABLE_HEARTBEAT */
	else if ((mctp_req_buf[8] == 0x01) &&
		 (mctp_req_buf[9] == MCTP_VENDOR_CMD_ENABLE_HEARTBEAT) &&
		 (mctp_req_buf[10] == 0x01)) {
		mctp_resp_buf[2] = MCTP_VENDOR_MSG_TYPE;
		/* struct mctp_vendor_msg_hdr */
		mctp_resp_buf[3] = 0;			  /* iana */
		mctp_resp_buf[4] = 0;			  /* iana */
		mctp_resp_buf[5] = 0x16;		  /* iana */
		mctp_resp_buf[6] = 0x47;		  /* iana */
		mctp_resp_buf[7] = 0x80;		  /* rq_dgram_inst */
		mctp_resp_buf[8] = 0x01;		  /* vendor_msg_type */
		mctp_resp_buf[9] =
			MCTP_VENDOR_CMD_ENABLE_HEARTBEAT; /* command_code */
		mctp_resp_buf[10] = 0x01;		  /* msg_version */
		resp_len = 11;
	}
	/* MCTP_VENDOR_CMD_HEARTBEAT */
	else if ((mctp_req_buf[8] == 0x01) &&
		 (mctp_req_buf[9] == MCTP_VENDOR_CMD_HEARTBEAT) &&
		 (mctp_req_buf[10] == 0x01)) {
		mctp_resp_buf[2] = MCTP_VENDOR_MSG_TYPE;
		/* struct mctp_vendor_msg_hdr */
		mctp_resp_buf[3] = 0;	 /* iana */
		mctp_resp_buf[4] = 0;	 /* iana */
		mctp_resp_buf[5] = 0x16; /* iana */
		mctp_resp_buf[6] = 0x47; /* iana */
		mctp_resp_buf[7] = 0x80; /* rq_dgram_inst */
		mctp_resp_buf[8] = 0x01; /* vendor_msg_type */
		mctp_resp_buf[9] = MCTP_VENDOR_CMD_HEARTBEAT; /* command_code */
		mctp_resp_buf[10] = 0x01;		      /* msg_version */
		resp_len = 11;
	}

	if (resp_len > 0) {
		LOG_FR("Response length = %zi, prefix length = %zi", resp_len,
		       mctp_prefix_len);

		flipRandomBits(((uint8_t *)mctp_resp_buf), resp_len);
		LOG_HEX((uint8_t *)mctp_resp_buf, resp_len, "write");

		int send_return_code;
		if ((send_return_code =
			     write(client_fd, mctp_resp_buf, resp_len)) == -1) {
			LOG_ERR("Write error %d, response is not sent, errno = %d",
				send_return_code, errno);
			//               err(EXIT_FAILURE, "Write error %d", send_return_code);
			if (errno == EPIPE) {
				/* Client closed the connection */
				return -1;
			}
		} else {
			LOG_FR("Response sent");
		}
	} else {
		LOG_FR("Warning: received unsupported vendor message type - no fuzzing");
		LOG_FR("  0x%02x, 0x%02x, 0x%02x", mctp_req_buf[8],
		       mctp_req_buf[9], mctp_req_buf[10]);
	}

	return 0;
}

/* Send any message to MCTP CTRL - no purpose, just a spam test */
static void manage_tx_vendor_packet(int client_fd)
{
	size_t resp_len = 0;
	size_t mctp_prefix_len = 1 /* HEADER TAG byte */ + sizeof(mctp_eid_t);

	memset(&mctp_resp_buf, 0, MCTP_MAX_CTRL_MESSAGE_SIZE);

	mctp_resp_buf[0] = MCTP_TAG_VDM;
	mctp_resp_buf[1] = getUint8t(); /* requester EID */

	/* MCTP_VENDOR_CMD_BOOTCOMPLETE */
	mctp_resp_buf[2] = MCTP_VENDOR_MSG_TYPE;
	/* struct mctp_vendor_msg_hdr */
	mctp_resp_buf[3] = 0;				 /* iana */
	mctp_resp_buf[4] = 0;				 /* iana */
	mctp_resp_buf[5] = 0x16;			 /* iana */
	mctp_resp_buf[6] = 0x47;			 /* iana */
	mctp_resp_buf[7] = 0x80;			 /* rq_dgram_inst */
	mctp_resp_buf[8] = 0x01;			 /* vendor_msg_type */
	mctp_resp_buf[9] = MCTP_VENDOR_CMD_BOOTCOMPLETE; /* command_code */
	mctp_resp_buf[10] = 0x02;			 /* msg_version */
	resp_len = 11;

	LOG_FR("Response length = %zi, prefix length = %zi", resp_len,
	       mctp_prefix_len);

	flipRandomBits(((uint8_t *)mctp_resp_buf), resp_len);
	LOG_HEX((uint8_t *)mctp_resp_buf, resp_len, "write");

	int send_return_code;
	if ((send_return_code = write(client_fd, mctp_resp_buf, resp_len)) ==
	    -1) {
		LOG_ERR("Write error %d, response is not sent, errno = %d",
			send_return_code, errno);
		if (errno == EPIPE) {
			/* Client closed the connection */
		}
	} else {
		LOG_FR("Response sent");
	}
}

/* Main MCTP CTRL fuzzing test routine:
    1. Open demux socket and listen on incoming connections from clients.
    2. Accept incomming connection and wait on MCTP messages.
    3. Prepare responses with small bit flips 
*/
void *runFuzzerReceiver(void *arg)
{
	(void)arg;
	int server_fd;
	int client_fd = -1;
	int client_hb_fd = -1;
	struct sockaddr_un server_addr, client_addr;
	socklen_t client_len;
	int namelen;
	int client_connect_timeout = 0;

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;

	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);

	if ((sigprocmask(SIG_BLOCK, &mask, NULL)) == -1) {
		warn("sigprocmask");
		return NULL;
	}

	if (signalfd(-1, &mask, 0) == -1) {
		LOG_ERR("signalfd returned an error, errno = %d: %s -> exiting\n",
			errno, strerror(errno));
		exit(-1);
	}

	if ((server_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1) {
		LOG_ERR("Error creating socket.");
		err(EXIT_FAILURE, "socket");
	}

	// Set socket to non-blocking mode
	int flags = fcntl(server_fd, F_GETFL, 0);
	fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	if (g_socket_path[0] == '\0') {
		namelen = 1 + strlen(g_socket_path + 1);
		LOG_FR("Open socket with name: \\0%s, len = %d",
		       &((g_socket_path)[1]), namelen);
	} else {
		namelen = strlen(g_socket_path);
		LOG_FR("Open socket with name: %s, len = %d", g_socket_path,
		       namelen);
	}

	memcpy(server_addr.sun_path, g_socket_path, namelen);

	// bind the server socket to the address
	if (bind(server_fd, (struct sockaddr *)&server_addr,
		 sizeof(server_addr.sun_family) + namelen) == -1) {
		LOG_ERR("Error binding socket.");
		close(server_fd);
		err(EXIT_FAILURE, "bind");
	}

	// listen for connections
	if (listen(server_fd, 5) == -1) {
		LOG_ERR("Error listening on socket.");
		close(server_fd);
		err(EXIT_FAILURE, "listen");
	}

	LOG_FR("Fuzz server is listening...");

	// unlock mctp ctrl demon
	LOG_FR("Locking mutex in test");
	pthread_mutex_lock(&mctp_ctrl_mock_sync_mutex);
	mctp_ctrl_fuzz_thread_is_ready = true;
	pthread_mutex_unlock(&mctp_ctrl_mock_sync_mutex);
	LOG_FR("Unlocking mutex in test");
	pthread_cond_signal(&mctp_ctrl_mock_sync_cond);

	struct pollfd fds[3];
	fds[0].fd = server_fd;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;
	fds[2].events = POLLIN;
	int active_sockets = 1;

	client_len = sizeof(client_addr);

	int msg_cnt = 0;
	int msg_end = 15; // limit number of fuzzed responses

	int zero_length_response_cnt = 0;
	int client_type = -1;
	int client_hb_type = -1;

	while (msg_cnt < msg_end) {
		// Wait for incoming connections with a timeout
		LOG_FR("Just before poll");
		int activity = poll(fds, active_sockets, 1);
		if (activity < 0) {
			LOG_ERR("poll error");
			exit(EXIT_FAILURE);
		}

		/* timeout */
		if (activity == 0) {
			if (client_connect_timeout++ > 4) {
				LOG_FR("Timeout waiting for new messages -> ending the loop");
				break;
			} else {
				continue;
			}
		}

		/* Check for server socket activity to accept incomming connections */
		if (fds[0].revents & POLLIN) {
			if (client_fd < 0) {
				// Accept the connection for the main MCTP CTRL thread
				if ((client_fd = accept(
					     server_fd,
					     (struct sockaddr *)&client_addr,
					     &client_len)) < 0) {
					if (errno != EWOULDBLOCK &&
					    errno != EAGAIN) {
						LOG_ERR("accept failed");
						close(server_fd);
						return NULL;
					} else {
						LOG_FR("Accept for the UUT finished with errno = %d",
						       errno);
					}
				} else {
					// Connection accepted, handle it
					LOG_FR("Incoming connection from the UUT accepted, socket = %d",
					       client_fd);
					setsockopt(client_fd, SOL_SOCKET,
						   SO_RCVTIMEO, &timeout,
						   sizeof(timeout));
					fds[1].fd = client_fd;
					active_sockets = 2;
				}
			} else if (client_hb_fd < 0) {
				// Accept the connection for the MCTP CTRL SPI heart beat thread
				if ((client_hb_fd = accept(
					     server_fd,
					     (struct sockaddr *)&client_addr,
					     &client_len)) < 0) {
					if (errno != EWOULDBLOCK &&
					    errno != EAGAIN) {
						LOG_ERR("accept failed");
						close(server_fd);
						return NULL;
					} else {
						LOG_FR("Accept for the UUT finished with errno = %d",
						       errno);
					}
				} else {
					// Connection accepted, handle it
					LOG_FR("Incoming connection from the UUT accepted, socket = %d",
					       client_hb_fd);
					setsockopt(client_hb_fd, SOL_SOCKET,
						   SO_RCVTIMEO, &timeout,
						   sizeof(timeout));
					fds[2].fd = client_hb_fd;
					active_sockets = 3;
				}
			}
		} else if (fds[0].revents) {
			LOG_FR("Unsupported rx socket event [0]: 0x%x\n",
			       fds[0].revents);
		}

		/* Check for messages from the main client socket */
		if (fds[1].revents & POLLIN) {
			int bytes_received = recv(client_fd, mctp_req_buf,
						  MCTP_MAX_CTRL_MESSAGE_SIZE,
						  0);
			if (bytes_received < 0) {
				if (errno != EAGAIN) {
					LOG_FR("error receiving data, errno=%d",
					       errno);
					err(EXIT_FAILURE,
					    "error receiving data");
				} else {
					LOG_FR("recv timeout");
					// No more messages are expected from tested daemon,
					//   stopping this loop
					break;
				}
			} else if (bytes_received > 0) {
				LOG_FR("recv ok [1], msg length: %d",
				       bytes_received);
				LOG_HEX(mctp_req_buf, bytes_received, "read");

				if ((bytes_received == 1) &&
				    (client_type < 0)) {
					if (mctp_req_buf[0] ==
					    MCTP_MESSAGE_TYPE_MCTP_CTRL) {
						LOG_FR("Client type MCTP CTRL");
						client_type =
							MCTP_MESSAGE_TYPE_MCTP_CTRL;
					} else if (mctp_req_buf[0] ==
						   MCTP_MESSAGE_TYPE_VDIANA) {
						LOG_FR("Client type VDIANA");
						client_type =
							MCTP_MESSAGE_TYPE_VDIANA;
					}
				} else if (client_type ==
					   MCTP_MESSAGE_TYPE_MCTP_CTRL) {
					if (manage_rx_packets(client_fd,
							      bytes_received) <
					    0) {
						break;
					}

					msg_cnt++;
					LOG_FR("msg_cnt = %d", msg_cnt);
				} else {
					LOG_FR("Received an unexpected message [1]");
				}
			} else {
				// Left intentionally - ignore 0 length response
				LOG_FR("recv - 0 length response, errno=%d",
				       errno);
				zero_length_response_cnt++;
				if ((msg_cnt > 1) ||
				    (zero_length_response_cnt > 3)) {
					break;
				} else {
					continue;
				}
			}
		} else if (fds[1].revents) {
			LOG_FR("Unsupported rx socket event [1]: 0x%x\n",
			       fds[1].revents);
		}

		/* Check for messages from the SPI heart beat socket */
		if (fds[2].revents & POLLIN) {
			int bytes_received = recv(client_hb_fd, mctp_req_buf,
						  MCTP_MAX_CTRL_MESSAGE_SIZE,
						  0);
			if (bytes_received < 0) {
				if (errno != EAGAIN) {
					LOG_FR("error receiving data, errno=%d",
					       errno);
					err(EXIT_FAILURE,
					    "error receiving data");
				} else {
					LOG_FR("recv timeout, errno");
					// No more messages are expected from tested daemon,
					//   stopping this loop
					break;
				}
			} else if (bytes_received > 0) {
				LOG_FR("recv ok [2], msg length: %d",
				       bytes_received);
				LOG_HEX(mctp_req_buf, bytes_received, "read");

				if ((bytes_received == 1) &&
				    (client_hb_type < 0)) {
					if (mctp_req_buf[0] ==
					    MCTP_MESSAGE_TYPE_MCTP_CTRL) {
						LOG_FR("SPI heart beat thread is a client type MCTP CTRL");
						client_hb_type =
							MCTP_MESSAGE_TYPE_MCTP_CTRL;
					} else if (mctp_req_buf[0] ==
						   MCTP_MESSAGE_TYPE_VDIANA) {
						LOG_FR("SPI heart beat thread is a client type VDIANA");
						client_hb_type =
							MCTP_MESSAGE_TYPE_VDIANA;
					}
				} else if (client_hb_type ==
					   MCTP_MESSAGE_TYPE_VDIANA) {
					LOG_FR("Get a message from SPI heart beat thread");
					if (manage_rx_vendor_packets(
						    client_hb_fd,
						    bytes_received) < 0)
						break;
				} else {
					LOG_FR("Received an unexpected message [2]");
				}
			} else {
				// Left intentionally - ignore 0 length response
				LOG_FR("recv - 0 length response, errno=%d",
				       errno);
				zero_length_response_cnt++;
				if ((msg_cnt > 1) ||
				    (zero_length_response_cnt > 3)) {
					break;
				} else {
					continue;
				}
			}
		} else if (fds[2].revents) {
			LOG_FR("Unsupported rx socket event [2]: 0x%x\n",
			       fds[2].revents);
		}
	}

	/* make some spam with a random request */
	manage_tx_vendor_packet(client_fd);

	/* give some time to receive */
	usleep(100);

	if (client_fd > 0)
		close(client_fd);
	close(server_fd);

	return NULL;
}

void *mctpLogic(void *arg)
{
	int i;

	LOG_ML("MCTP CTRL UUT starting");
	struct thread_args *args = (struct thread_args *)arg;

	int argc = args->argc; // Cast and dereference to get argc
	char **argv = args->argv;

	for (i = 0; i < argc; i++) {
		LOG_ML("  arg[%d] = %s", i, argv[i]);
	}

	int ret = main_ctrl(argc, argv);

	LOG_ML("MCTP CTRL UUT finished with ret = %d", ret);

	return NULL;
}

void printHelp(const struct option long_options[])
{
	printf("Usage: program [options]\n");
	printf("Options:\n");

	for (int i = 0; long_options[i].name != NULL; i++) {
		printf("  ");
		if (long_options[i].val > 0 && long_options[i].val < 128) {
			printf("-%c,", long_options[i].val);
		} else {
			printf("    ");
		}

		printf(" --%-20s", long_options[i].name);

		if (long_options[i].has_arg == required_argument) {
			printf(" <argument>");
		} else if (long_options[i].has_arg == optional_argument) {
			printf(" [argument]");
		}

		printf("\n");
	}
}

void pushArg(struct thread_args *args, const char *newString)
{
	args->argv[args->argc] = strdup(newString);
	args->argc++;
}

/* Json config file name should be provided with proper path.
    Normally, the file will be placed in the same folder as the mctp_ctrl executable.
    However, if mctp_ctrl executable is run from a relative path then
    we may not know where this config is.
    The below function is to find out a proper relative path from the executable. */
char fileJsonConfigName[256];

void setJsonConfigName(char *const *argv, char *fileName)
{
	int parentLen = 0;

	char *path = (char *)getauxval(AT_EXECFN);
	if (path != NULL) {
		sprintf((char *)(&fileJsonConfigName[parentLen]), "%s", path);
	} else {
		sprintf((char *)(&fileJsonConfigName[parentLen]), "%s",
			argv[0]);
	}

	char *last = strrchr(fileJsonConfigName, '/');
	if (last != NULL) {
		parentLen = strlen(fileJsonConfigName) - strlen(last) + 1;
	}

	strncpy((char *)(&fileJsonConfigName[parentLen]), fileName,
		strlen(fileName) + 1);

	LOG("Json config file name param: %s", fileJsonConfigName);
}

int main(int argc, char *const *argv)
{
	uint8_t input_param_type = 255;

	struct thread_args args;
	args.argc = 0;
	args.argv = malloc(256 * sizeof(char *));

	struct timeval start, end;
	long secs_used, micros_used;
	gettimeofday(&start, NULL);

	pthread_mutexattr_init(&mctp_ctrl_mock_sync_mutex_attr);
	pthread_mutex_init(&mctp_ctrl_mock_sync_mutex,
			   &mctp_ctrl_mock_sync_mutex_attr);
	pthread_t mctpLogicThread;
	pthread_t fuzzerReceiverThread;

	pthread_attr_t attr;

	srand(time(NULL));

	/* Remove any possible socket names used during fuzz tests
       remember to add them here when adding new test cases 
       for jason files with different socket names */
	remove(MCTP_SOCK_PATH_PCIE);
	remove(MCTP_SOCK_PATH_SPI);
	remove(MCTP_SOCK_PATH_I2C);
	remove(MCTP_SOCK_PATH_USB);
	remove(MCTP_SOCKET_NAME_NIC_CFG_JSON);
	remove(MCTP_SOCKET_NAME_CONFIG_JSON);

	int opt;
	struct option long_options[] = {
		{ "help", no_argument, 0, 1001 },
		{ "verbose", required_argument, 0, 1002 },
		{ "random-input", no_argument, 0, 1003 },
		{ "parameter-type", required_argument, 0, 1004 },
		{ "type", required_argument, 0, 't' },
		{ 0, 0, 0, 0 }
	};

	pushArg(&args, argv[0]);

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "t:", long_options, NULL)) !=
	       -1) {
		switch (opt) {
		case 1001: //help
			printHelp(long_options);
			return 0;
		case 1002: //verbose
			g_fuzz_verbose_level = (int)strtol(optarg, NULL, 10);
			if (g_fuzz_verbose_level >= 1) {
				printf("[main] Fuzzing verbose level: %d\n",
				       g_fuzz_verbose_level);
			}
			break;
		case 1003: //random-input
			g_random_input = true;
			printf("[main] random input enabled\n");
			break;
		case 1004: //parameter-type
			input_param_type = (uint8_t)strtol(optarg, NULL, 10);
			if (g_fuzz_verbose_level >= 1) {
				printf("[main] Input param type = %d\n",
				       input_param_type);
			}
			break;
		case 't':
			g_tested_interface_type = atoi(optarg);
			printf("[main] type value provided = %d\n",
			       g_tested_interface_type);
			break;
		case '?':
			printf("[main] option ?\n");
			/* Ignore unknown options 
                    - use only the ones generated in the source code below */
			break;
		}
	}

	opterr = 1;

	if (g_tested_interface_type == 1000) {
		int i = getUint8t() % 4;
		if (i == 0) {
			g_tested_interface_type = MCTP_BINDING_PCIE;
		} else if (i == 1) {
			g_tested_interface_type = MCTP_BINDING_SPI;
		} else if (i == 2) {
			g_tested_interface_type = MCTP_BINDING_SMBUS;
		} else if (i == 3) {
			g_tested_interface_type = MCTP_BINDING_USB;
		}
	}

	if (input_param_type >= 255) {
		input_param_type = (int)(getUint8t());
	}

	if (input_param_type == 0) {
		/* Wrong help message */
		pushArg(&args, "-hunknown");
	} else if (input_param_type == 1) {
		/* General help message */
		pushArg(&args, "-h");
	} else if (input_param_type == 2) {
		/* Unknown argument */
		pushArg(&args, "-z");
	} else if (input_param_type == 3) {
		/* Interface help message */
		//pushArg(&args, "-h");
		switch (g_tested_interface_type) {
		case MCTP_BINDING_PCIE:
			pushArg(&args, "-hpcie");
			break;
		case MCTP_BINDING_SPI:
			pushArg(&args, "-hspi");
			break;
		case MCTP_BINDING_SMBUS:
			pushArg(&args, "-hsmbus");
			break;
		case MCTP_BINDING_USB:
			pushArg(&args, "-husb");
			break;
		default:
			pushArg(&args, "-hunknown");
			break;
		}
	} else if ((input_param_type >= 4) && (input_param_type <= 5)) {
		/* Json file parameters - for now only for SMBUS */
		LOG("Using fixed json configuration file for SMBUS tests.");

		// Delay to start demon, in fuzz mode it should be always 0
		pushArg(&args, "-d");
		pushArg(&args, "0");

		if ((g_fuzz_verbose_level >= 3) || (input_param_type == 5)) {
			pushArg(&args, "-v");
			pushArg(&args, "1");
		}

		// Start as a daemon
		pushArg(&args, "-m");
		pushArg(&args, "1");

		g_tested_interface_type = MCTP_BINDING_SMBUS;
		g_socket_path = MCTP_SOCKET_NAME_CONFIG_JSON;
		pushArg(&args, "-t");
		pushArg(&args, "1");

		setJsonConfigName(argv, "mctp_test_cfg.json");
		pushArg(&args, "-f");
		pushArg(&args, fileJsonConfigName);

		pushArg(&args, "-u");
		pushArg(&args, "\"abcdef0123456789abcdef0123456789abcd\"");

		pushArg(&args, "-c");
		pushArg(&args, "1");
	} else if ((input_param_type >= 6) && (input_param_type <= 7)) {
		/* Command line test with json config file - only SMBUS
        mctp-ctrl -m 0 -t 1 -f ./nic_cfg.json -n 5 -s "00 80 01 00 64" -t 1 -e 100 -b "32" -d 0 -v 1
        */
		LOG("Using json config file with a command line option.");

		// Start from command line
		pushArg(&args, "-m");
		pushArg(&args, "0");

		// Delay to start demon, in fuzz mode it should be always 0
		pushArg(&args, "-d");
		pushArg(&args, "0");

		pushArg(&args, "-v");
		pushArg(&args, "1");

		g_tested_interface_type = MCTP_BINDING_SMBUS;
		/* use socket name defined in json file */
		g_socket_path = MCTP_SOCKET_NAME_NIC_CFG_JSON;
		pushArg(&args, "-t");
		pushArg(&args, "1");

		setJsonConfigName(argv, "nic_cfg.json");
		pushArg(&args, "-f");
		pushArg(&args, fileJsonConfigName);

		pushArg(&args, "-n");
		pushArg(&args, "5");

		pushArg(&args, "-e");
		pushArg(&args, "100");

		pushArg(&args, "-b");
		pushArg(&args, "\"32\"");

		if (input_param_type == 6) {
			pushArg(&args, "-s");
			pushArg(&args, "\"00 80 01 00 64\"");
		} else {
			pushArg(&args, "-s");
			pushArg(&args, "\"00 80 02\"");
		}
	} else if ((input_param_type >= 8) && (input_param_type <= 9)) {
		/* SPI test commands - only for SPI */

		g_socket_path = MCTP_SOCK_PATH_SPI;
		g_tested_interface_type = MCTP_BINDING_SPI;
		pushArg(&args, "-t");
		pushArg(&args, "6");

		// Start as SPI test command
		pushArg(&args, "-m");
		pushArg(&args, "2");

		// Delay to start demon, in fuzz mode it should be always 0
		pushArg(&args, "-d");
		pushArg(&args, "0");

		pushArg(&args, "-v");
		pushArg(&args, "1");

		// Required argumend: command mode
		pushArg(&args, "-x");
		int cmd_mode = getUint8t() % 6;
		char vdm_ops_param[8];
		sprintf(vdm_ops_param, "%d", cmd_mode);
		pushArg(&args, vdm_ops_param);

		// Required argumend: mctp-iana-vdm
		pushArg(&args, "-i");
		int vdm_ops = getUint8t() % 6;
		sprintf(vdm_ops_param, "%d", vdm_ops);
		pushArg(&args, vdm_ops_param);
	} else if ((input_param_type >= 10) && (input_param_type <= 11)) {
		char ops_param[8];
		int value;

		/* Random input parameters */
		LOG("Using random input parameters for daemon or cmd line modes.");

		// Start as a daemon or command line
		pushArg(&args, "-m");
		if (g_tested_interface_type != MCTP_BINDING_SPI) {
			value = getUint8t() % 2;
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);
		} else {
			/* Workaround for SPI as it in this test SPI run from 
                command line mode causes seg fault */
			pushArg(&args, "1");
		}

		// Delay to start demon, in fuzz mode it should be always 0
		pushArg(&args, "-d");
		pushArg(&args, "0");

		switch (g_tested_interface_type) {
		case MCTP_BINDING_PCIE:
			g_socket_path = MCTP_SOCK_PATH_PCIE;
			pushArg(&args, "-t");
			pushArg(&args, "2");
			break;
		case MCTP_BINDING_SPI:
			g_socket_path = MCTP_SOCK_PATH_SPI;
			pushArg(&args, "-t");
			pushArg(&args, "6");
			break;
		case MCTP_BINDING_SMBUS:
			g_socket_path = MCTP_SOCK_PATH_I2C;
			pushArg(&args, "-t");
			pushArg(&args, "1");
			break;
		case MCTP_BINDING_USB:
			g_socket_path = MCTP_SOCK_PATH_USB;
			pushArg(&args, "-t");
			pushArg(&args, "3");
			break;
		}

		if (g_tested_interface_type != MCTP_BINDING_SPI) {
			pushArg(&args, "--bindinfo");
			pushArg(&args, "\"00 00 00 00 00 01\"");

			pushArg(&args, "--pci_own_eid");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);

			pushArg(&args, "--i2c_own_eid");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);

			pushArg(&args, "--pci_bridge_eid");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);

			pushArg(&args, "--i2c_bridge_eid");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);

			pushArg(&args, "--pci_bridge_pool_start");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);

			pushArg(&args, "--i2c_bridge_pool_start");
			value = getUint8t();
			sprintf(ops_param, "%d", value);
			pushArg(&args, ops_param);
		} else {
			// Required argumend: command mode
			pushArg(&args, "-x");
			int cmd_mode = getUint8t() % 6;
			char vdm_ops_param[8];
			sprintf(vdm_ops_param, "%d", cmd_mode);
			pushArg(&args, vdm_ops_param);

			// Required argumend: mctp-iana-vdm
			pushArg(&args, "-i");
			int vdm_ops = getUint8t() % 6;
			sprintf(vdm_ops_param, "%d", vdm_ops);
			pushArg(&args, vdm_ops_param);
		}

		if ((g_fuzz_verbose_level >= 3) || (input_param_type == 10)) {
			pushArg(&args, "-v");
			pushArg(&args, "1");
		}
	} else if (input_param_type >= 12) {
		/* Default parameters - keep it always as the last input param type */
		LOG("Using fixed command line args.");

		// Delay to start demon, in fuzz mode it should be always 0
		pushArg(&args, "-d");
		pushArg(&args, "0");

		if ((g_fuzz_verbose_level >= 3) || (input_param_type == 12)) {
			pushArg(&args, "-v");
			pushArg(&args, "1");
		}

		// Start as a daemon
		pushArg(&args, "-m");
		pushArg(&args, "1");

		switch (g_tested_interface_type) {
		case MCTP_BINDING_PCIE:
			g_socket_path = MCTP_SOCK_PATH_PCIE;
			pushArg(&args, "-t");
			pushArg(&args, "2");
			break;
		case MCTP_BINDING_SPI:
			g_socket_path = MCTP_SOCK_PATH_SPI;
			pushArg(&args, "-t");
			pushArg(&args, "6");
			break;
		case MCTP_BINDING_SMBUS:
			g_socket_path = MCTP_SOCK_PATH_I2C;
			pushArg(&args, "-t");
			pushArg(&args, "1");
			break;
		case MCTP_BINDING_USB:
			g_socket_path = MCTP_SOCK_PATH_USB;
			pushArg(&args, "-t");
			pushArg(&args, "3");
			break;
		}

		pushArg(&args, "--bindinfo");
		pushArg(&args, "\"00 00 00 00 00 01\"");
		pushArg(&args, "--pci_own_eid");
		pushArg(&args, "9");
		pushArg(&args, "--i2c_own_eid");
		pushArg(&args, "11");
		pushArg(&args, "--pci_bridge_eid");
		pushArg(&args, "12");
		pushArg(&args, "--i2c_bridge_eid");
		pushArg(&args, "30");
		pushArg(&args, "--pci_bridge_pool_start");
		pushArg(&args, "13");
		pushArg(&args, "--i2c_bridge_pool_start");
		pushArg(&args, "32");
	}

	//restart optid mechanism
	optind = 1;

	LOG("Initiating MCTP mock Fuzz tests\n");
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(&fuzzerReceiverThread, nullptr, &runFuzzerReceiver,
		       nullptr);

	// Run main mctp ctrl thread only if the fuzzer receiver is ready
	LOG("[main] Locking mutex in main");
	pthread_mutex_lock(&mctp_ctrl_mock_sync_mutex);
	if (!mctp_ctrl_fuzz_thread_is_ready) {
		pthread_cond_wait(&mctp_ctrl_mock_sync_cond,
				  &mctp_ctrl_mock_sync_mutex);
	}
	pthread_mutex_unlock(&mctp_ctrl_mock_sync_mutex);
	LOG("[main] Unlocking mutex in main");

	pthread_create(&mctpLogicThread, &attr, &mctpLogic, &args);

	// wait until the test thread has finished
	pthread_join(fuzzerReceiverThread, NULL);

	// make sure ctrl demon thread is terminated
	pthread_kill(mctpLogicThread, SIGTERM);
	pthread_join(mctpLogicThread, NULL);

	// free all allocated buffers
	for (int i = 0; i < args.argc; i++) {
		free(args.argv[i]);
	}
	free(args.argv);

	// destroy mutex
	pthread_mutex_destroy(&mctp_ctrl_mock_sync_mutex);

	if (g_fuzz_verbose_level >= 1) {
		gettimeofday(&end, NULL);
		secs_used = (end.tv_sec - start.tv_sec);
		micros_used =
			((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
		printf("[main] ... End after %ld us\n", micros_used);
	}

	LOG("[main] Used %u random values", g_random_values);

	return 0;
}
