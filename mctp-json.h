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
#include <json-c/json.h>

#include "libmctp-smbus.h"

enum eid_types {
	EID_TYPE_BRIDGE,
	EID_TYPE_STATIC,
	EID_TYPE_POOL,
};

int mctp_json_get_tokener_parse(json_object **jo, const char *path);
int mctp_json_get_eid_type(json_object *jo, const char *binding_name, uint8_t *bus_num);

int mctp_json_i2c_get_common_params_mctp_demux(json_object *jo, uint8_t *bus_num,
				uint8_t *bus_num_smq, uint8_t *src_slave_addr, char **sockname);
int mctp_json_i2c_get_params_bridge_static_demux(json_object * jo, uint8_t *bus_num,
				uint8_t *dest_slave_addr, uint8_t *src_eid);
int mctp_json_i2c_get_params_static_demux(
	json_object *jo, uint8_t *bus_num,
	struct mctp_static_endpoint_mapper *endpoints);
int mctp_json_i2c_get_params_pool_demux(json_object *jo, uint8_t *bus_num,
				struct mctp_static_endpoint_mapper **static_endpoints_tab,
				uint8_t *static_endpoints_len);

void mctp_json_i2c_get_common_params_ctrl(json_object *jo, uint8_t *bus_num,
					  char **sockname, uint8_t *src_eid,
					  uint8_t *dest_slave_addr,
					  uint8_t *logical_busses,
					  uint8_t *src_slave_addr);
void mctp_json_i2c_get_params_bridge_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_eid, uint8_t *pool_start);
int mctp_json_i2c_get_params_static_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_eid_tab, uint8_t *dest_eid_len, uint8_t *uuid);
int mctp_json_i2c_get_params_pool_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_pool_eid_tab, uint8_t *dest_pool_eid_len);
