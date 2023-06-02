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
void set_g_val_for_pvt_binding(uint8_t bus_num, uint8_t dest_slave_addr, uint8_t src_slave_addr);

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
mctp_ret_codes_t mctp_i2c_discover_static_endpoint(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl);

#endif /* __MCTP_I2C_DISCOVERY_H__ */
