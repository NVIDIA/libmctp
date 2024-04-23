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
// /* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_I2C_DISCOVERY_H__
#define __MCTP_I2C_DISCOVERY_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-discovery-common.h"

// /* Function prototypes */
void set_g_val_for_pvt_binding(uint8_t bus_num, uint8_t dest_slave_addr,
			       uint8_t src_slave_addr);

uint8_t mctp_i2c_get_i2c_bus(int eid);
uint8_t mctp_i2c_get_i2c_addr(int eid);

mctp_ret_codes_t mctp_i2c_get_mctp_ver_support_request(int sock_fd, uint8_t eid);

mctp_ret_codes_t mctp_i2c_set_eid_send_request(int sock_fd, mctp_ctrl_cmd_set_eid_op op, uint8_t eid);
int mctp_i2c_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len, uint8_t eid, uint8_t *eid_count);

mctp_ret_codes_t mctp_i2c_alloc_eid_send_request(int sock_fd, mctp_eid_t assigned_eid, mctp_ctrl_cmd_set_eid_op op, uint8_t eid_count, uint8_t eid_start);
int mctp_i2c_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_i2c_get_routing_table_send_request(int sock_fd, mctp_eid_t eid, uint8_t entry_handle);
int mctp_i2c_get_routing_table_get_response(int sock_fd, mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_i2c_get_endpoint_uuid_send_request(int sock_fd, mctp_eid_t eid);
int mctp_i2c_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_i2c_get_msg_type_request(int sock_fd, mctp_eid_t eid);
int mctp_i2c_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len);

mctp_ret_codes_t mctp_i2c_discover_endpoints(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);
mctp_ret_codes_t mctp_i2c_discover_static_pool_endpoint(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);

#endif /* __MCTP_I2C_DISCOVERY_H__ */
