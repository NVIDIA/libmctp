/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_DISCOVERY_H__
#define __MCTP_DISCOVERY_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCTP_DEVICE_DELAY_IN_SECS       1

#define MCTP_ROUTING_TABLE_MAX_SIZE     0x200
#define MCTP_MSG_TYPE_MAX_SIZE          0xff

#define MCTP_MSG_TYPE_DATA_LEN_OFFSET   0
#define MCTP_MSG_TYPE_DATA_OFFSET       1

//struct get_routing_table_entry g_routing_table[MCTP_ROUTING_TABLE_MAX_SIZE];

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
    struct  get_routing_table_entry routing_table;
    struct  mctp_routing_table *next;
} mctp_routing_table_t;


/* List for MCTP Message types */
typedef struct mctp_msg_type_table {
    uint8_t eid;
    int     data_len;
    uint8_t data[MCTP_MSG_TYPE_MAX_SIZE];
    struct  mctp_msg_type_table *next;
} mctp_msg_type_table_t;

/* List for UUIDs */
typedef struct mctp_uuid_table {
    uint8_t eid;
    guid_t  uuid;
    struct  mctp_uuid_table *next;
} mctp_uuid_table_t;


/* Structure for Sending MCTP request */
struct mctp_ctrl_req {
        struct mctp_ctrl_cmd_msg_hdr hdr;
        uint8_t data[MCTP_BTU];
};

#if 0
/* Structure for Getting MCTP response */
struct mctp_ctrl_resp {
        struct mctp_ctrl_cmd_msg_hdr hdr;
        uint8_t completion_code;
        uint8_t data[MCTP_BTU];
} resp;
#endif

/* Discovery message table for logging */
typedef struct {
    mctp_discovery_mode mode;
    const char      *message;
} mctp_discovery_message_table_t;


/* Function prototypes */
void mctp_routing_entry_display(void);
int mctp_routing_entry_add(struct get_routing_table_entry *routing_table_entry);
int mctp_routing_entry_delete_all(void);


int mctp_uuid_delete_all(void);
int mctp_uuid_entry_add(mctp_uuid_table_t *uuid_tbl);
void mctp_uuid_display(void);

void mctp_msg_types_display(void);
int mctp_msg_type_entry_add(mctp_msg_type_table_t *msg_type_tbl);
int mctp_msg_types_delete_all(void);

mctp_ret_codes_t mctp_prepare_ep_discovery_send_request(int sock_fd);
mctp_ret_codes_t mctp_prepare_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_ep_discovery_send_request(int sock_fd);
int mctp_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_set_eid_send_request(int sock_fd, mctp_ctrl_cmd_set_eid_op op, uint8_t eid);
int mctp_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
                                                uint8_t eid, uint8_t *eid_count);

mctp_ret_codes_t mctp_alloc_eid_send_request(int sock_fd, mctp_eid_t eid,
                                    mctp_ctrl_cmd_set_eid_op op,
                                    uint8_t eid_count, uint8_t eid_start);
int mctp_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_get_routing_table_send_request(int sock_fd, mctp_eid_t eid, uint8_t entry_handle);
int mctp_get_routing_table_get_response(int sock_fd, mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_get_endpoint_uuid_send_request(int sock_fd, mctp_eid_t eid);
int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_get_msg_type_request(int sock_fd, mctp_eid_t eid);
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_discover_endpoints(mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);


#ifdef __cplusplus
}
#endif

#endif /* __MCTP_DISCOVERY_H__ */
