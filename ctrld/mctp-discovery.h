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

/* Function prototypes */
mctp_ret_codes_t
mctp_prepare_ep_discovery_send_request(int sock_fd, mctp_binding_ids_t bind_id);
mctp_ret_codes_t mctp_prepare_ep_discovery_get_response(uint8_t *mctp_resp_msg,
							size_t resp_msg_len);

mctp_ret_codes_t mctp_ep_discovery_send_request(int sock_fd,
						mctp_binding_ids_t bind_id);
int mctp_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_set_eid_send_request(int sock_fd,
					   mctp_binding_ids_t bind_id,
					   mctp_ctrl_cmd_set_eid_op op,
					   uint8_t eid);
int mctp_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
			      uint8_t eid, uint8_t *eid_count);

mctp_ret_codes_t
mctp_alloc_eid_send_request(int sock_fd, mctp_binding_ids_t bind_id,
			    mctp_eid_t eid, mctp_ctrl_cmd_set_eid_op op,
			    uint8_t eid_count, uint8_t eid_start);
int mctp_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_get_routing_table_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t eid,
						     uint8_t entry_handle);
int mctp_get_routing_table_get_response(mctp_ctrl_t *ctrl, mctp_eid_t eid,
					uint8_t *mctp_resp_msg,
					size_t resp_msg_len,
					bool remove_duplicates);

mctp_ret_codes_t mctp_get_endpoint_uuid_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t eid);
int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
				    size_t resp_msg_len);

mctp_ret_codes_t mctp_get_msg_type_request(int sock_fd,
					   mctp_binding_ids_t bind_id,
					   mctp_eid_t eid);
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
			       size_t resp_msg_len);

mctp_ret_codes_t mctp_discover_endpoints(const mctp_cmdline_args_t *cmd,
					 mctp_ctrl_t *ctrl,
					 mctp_discovery_mode start_mode);

mctp_ret_codes_t mctp_spi_static_endpoint();

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_DISCOVERY_H__ */
