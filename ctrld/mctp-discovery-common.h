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
#pragma once

#include <stdint.h>
#include "libmctp.h"
#include "mctp-ctrl-cmds.h"

#define MCTP_DEVICE_READY_DELAY		2
#define MCTP_DEVICE_GET_ROUTING_DELAY	4
#define MCTP_DEVICE_SET_EID_TIMEOUT	300
#define MCTP_DEVICE_GET_ROUTING_TIMEOUT 60
#define MCTP_I2C_MSG_TYPE_MAX_SIZE 0xff
#define MCTP_ROUTING_TABLE_MAX_SIZE	0x200
#define MCTP_MSG_TYPE_MAX_SIZE		0xff
#define MCTP_MSG_TYPE_DATA_LEN_OFFSET 0
#define MCTP_MSG_TYPE_DATA_OFFSET 1

/* Various discovery modes */
typedef enum {
	MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST,
	MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE,

	MCTP_EP_DISCOVERY_REQUEST,
	MCTP_EP_DISCOVERY_RESPONSE,

	MCTP_SET_EP_REQUEST,
	MCTP_SET_EP_RESPONSE,

	MCTP_ALLOCATE_EP_ID_REQUEST,
	MCTP_ALLOCATE_EP_ID_RESPONSE,

	MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST,
	MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE,

	MCTP_GET_EP_UUID_REQUEST,
	MCTP_GET_EP_UUID_RESPONSE,

	MCTP_GET_MSG_TYPE_REQUEST,
	MCTP_GET_MSG_TYPE_RESPONSE,

	MCTP_GET_VER_SUPPORT_REQUEST,
	MCTP_GET_VER_SUPPORT_RESPONSE,

	MCTP_FINISH_DISCOVERY
} mctp_discovery_mode;

/* List for Routing table entries */
typedef struct mctp_routing_table {
	int id;
	struct get_routing_table_entry routing_table;
	struct mctp_routing_table *next;
} mctp_routing_table_t;

/* List for MCTP Message types */
typedef struct mctp_msg_type_table {
	uint8_t eid;
	uint16_t data_len;
	uint8_t data[MCTP_MSG_TYPE_MAX_SIZE];
	struct mctp_msg_type_table *next;
} mctp_msg_type_table_t;

/* List for UUIDs */
typedef struct mctp_uuid_table {
	uint8_t eid;
	guid_t uuid;
	struct mctp_uuid_table *next;
} mctp_uuid_table_t;

/* Structure for Sending MCTP request */
struct mctp_ctrl_req {
	struct mctp_ctrl_cmd_msg_hdr hdr;
	uint8_t data[MCTP_BTU];
};

/* Structure for Getting MCTP response */
struct mctp_ctrl_resp {
	struct mctp_ctrl_cmd_msg_hdr hdr;
	uint8_t completion_code;
	uint8_t data[MCTP_BTU];
} __attribute__((__packed__));

/* Discovery message table for logging */
typedef struct {
	mctp_discovery_mode mode;
	const char *message;
} mctp_discovery_message_table_t;

/* Function prototypes */
void mctp_routing_entry_display(void);
int mctp_routing_entry_add(struct get_routing_table_entry *routing_table_entry);
void mctp_routing_entry_delete_all(void);

void mctp_uuid_delete_all(void);
int mctp_uuid_entry_add(mctp_uuid_table_t *uuid_tbl);
int mctp_uuid_entry_remove(uint8_t eid);
void mctp_uuid_display(void);

void mctp_msg_types_display(void);
int mctp_msg_type_entry_add(mctp_msg_type_table_t *msg_type_tbl);
int mctp_msg_type_entry_remove(uint8_t eid);
void mctp_msg_types_delete_all(void);

void mctp_print_resp_msg(struct mctp_ctrl_resp *ep_discovery_resp,
				const char *msg, int msg_len);
void mctp_print_req_msg(struct mctp_ctrl_req *ep_discovery_req,
			       const char *msg, size_t msg_len);

void mctp_print_routing_table_entry(int routing_id,
			       struct get_routing_table_entry *routing_table);
