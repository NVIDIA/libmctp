#pragma once

#include <stdint.h>
#include "mctp-ctrl-cmds.h"

#define MCTP_DEVICE_READY_DELAY		2
#define MCTP_DEVICE_GET_ROUTING_DELAY	4
#define MCTP_DEVICE_SET_EID_TIMEOUT	300
#define MCTP_DEVICE_GET_ROUTING_TIMEOUT 60
#define MCTP_ROUTING_TABLE_MAX_SIZE	0x200
#define MCTP_MSG_TYPE_MAX_SIZE		0xff

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
	int data_len;
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
