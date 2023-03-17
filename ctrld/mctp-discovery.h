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
#include "mctp-discovery-common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCTP_MSG_TYPE_DATA_LEN_OFFSET 0
#define MCTP_MSG_TYPE_DATA_OFFSET 1

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
void mctp_uuid_display(void);

void mctp_msg_types_display(void);
int mctp_msg_type_entry_add(mctp_msg_type_table_t *msg_type_tbl);
void mctp_msg_types_delete_all(void);

mctp_ret_codes_t mctp_prepare_ep_discovery_send_request(int sock_fd);
mctp_ret_codes_t mctp_prepare_ep_discovery_get_response(uint8_t *mctp_resp_msg,
							size_t resp_msg_len);

mctp_ret_codes_t mctp_ep_discovery_send_request(int sock_fd);
int mctp_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_set_eid_send_request(int sock_fd,
					   mctp_ctrl_cmd_set_eid_op op,
					   uint8_t eid);
int mctp_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
			      uint8_t eid, uint8_t *eid_count);

mctp_ret_codes_t mctp_alloc_eid_send_request(int sock_fd, mctp_eid_t eid,
					     mctp_ctrl_cmd_set_eid_op op,
					     uint8_t eid_count,
					     uint8_t eid_start);
int mctp_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_get_routing_table_send_request(int sock_fd,
						     mctp_eid_t eid,
						     uint8_t entry_handle);
int mctp_get_routing_table_get_response(mctp_ctrl_t *ctrl, mctp_eid_t eid,
					uint8_t *mctp_resp_msg,
					size_t resp_msg_len);

mctp_ret_codes_t mctp_get_endpoint_uuid_send_request(int sock_fd,
						     mctp_eid_t eid);
int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
				    size_t resp_msg_len);

mctp_ret_codes_t mctp_get_msg_type_request(int sock_fd, mctp_eid_t eid);
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
			       size_t resp_msg_len);

mctp_ret_codes_t mctp_discover_endpoints(const mctp_cmdline_args_t *cmd,
					 mctp_ctrl_t *ctrl);

mctp_ret_codes_t mctp_spi_static_endpoint();

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_DISCOVERY_H__ */
