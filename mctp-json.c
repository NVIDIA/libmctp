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
/* */

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <errno.h>

#include "mctp-json.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"

#define MCTP_JSON_CONFIG_MAX_SIZE (128 * 1024)

static int parse_num(const char *param)
{
	intmax_t num;
	char *endptr;

	num = strtoimax(param, &endptr, 10);

	if ((*endptr != '\0') && (*endptr != ' ')) {
		MCTP_ERR("Invalid number: %s\n", param);
		num = 0;
	}

	return (int)num;
}

/**
 * @brief Open JSON file and parse string to json_object
 *
 * @param[in] path - path to configuration JSON file,
 *
 * @return int return success or failure.
 */
int mctp_json_get_tokener_parse(json_object **jo, const char *path)
{
	int rc;
	FILE *fp;
	int file_size;
	char *buffer = NULL;
	enum json_tokener_error json_error;

	*jo = NULL;

	fp = fopen(path, "r");

	if (fp == NULL) {
		MCTP_ERR("Unable to open: %s, err = %d\n", path, errno);
		return EXIT_FAILURE;
	} else {
		rc = fseek(fp, 0, SEEK_END);
		if (rc == -1) {
			MCTP_ERR("Failed to fseek\n");
			goto err_close;
		}

		file_size = ftell(fp);
		if (file_size == -1) {
			MCTP_ERR("Failed to ftell\n");
			goto err_close;
		}

		if (MCTP_JSON_CONFIG_MAX_SIZE <= file_size) {
			MCTP_ERR(
				"Config file size is too big = %d, expected up to %d\n",
				file_size, MCTP_JSON_CONFIG_MAX_SIZE);
			goto err_close;
		}

		rc = fseek(fp, 0, SEEK_SET);
		if (rc == -1) {
			MCTP_ERR("Failed to fseek\n");
			goto err_close;
		}

		buffer = malloc(file_size + 1);

		if (buffer == NULL) {
			MCTP_ERR("Failed to allocate %d bytes\n",
				 file_size + 1);
			goto err_close;
		}

		rc = fread(buffer, 1, file_size, fp);
		if (rc != file_size) {
			MCTP_ERR("Failed to fread, rc = %d\n", rc);
			goto err_free_and_close;
		}

		// json_tokener_parse parses string finished with \0
		buffer[file_size] = 0;
	}

	fclose(fp);

	/* Get parameters from *.json */
	*jo = json_tokener_parse_verbose(buffer, &json_error);

	free(buffer);

	if (*jo == NULL) {
		MCTP_ERR("Json tokener parse fail, json parser error = %d\n\n",
			 (int)json_error);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

err_free_and_close:
	if (buffer != NULL) {
		free(buffer);
	}
err_close:
	if (fp) {
		fclose(fp);
	}

	return EXIT_FAILURE;
}

/**
 * @brief Get eid type base on binding type
 *
 * @param[in] jo - json_object got after parse string from JSON file
 * @param[in] binding_name - Binding type identifier
 * @param[in] bus_num - I2C bus number
 *
 * @return int enum of eid type
*/
int mctp_json_get_eid_type(json_object *jo, const char *binding_name,
			   uint8_t *bus_num)
{
	if (strcmp(binding_name, "astpcie") == 0) {
		MCTP_ERR("Parameters for PCIe from JSON file not supported\n");
	} else if (strcmp(binding_name, "astspi") == 0) {
		MCTP_ERR("Parameters for SPI from JSON file not supported\n");
	} else if (strcmp(binding_name, "smbus") == 0) {
		json_object *jo_i2c_struct;
		json_object *jo_i2c_obj_main;
		json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

		const char *string_val;
		uint8_t val = 0;
		size_t i, j;

		jo_i2c_struct = json_object_object_get(jo, "i2c");

		jo_i2c_obj_main =
			json_object_object_get(jo_i2c_struct, "buses");
		size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

		for (i = 0; i < val_conf_i2c; i++) {
			jo_i2c_struct =
				json_object_array_get_idx(jo_i2c_obj_main, i);
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number_smq");
			if (jo_i2c_obj_i != NULL) {
				string_val =
					json_object_get_string(jo_i2c_obj_i);
				if (string_val != NULL) {
					if (strncmp(string_val, "i2c", 3) ==
					    0) {
						val = parse_num(string_val + 3);
					}
				}
			}

			if (val == *bus_num) {
				jo_i2c_obj_i = json_object_object_get(
					jo_i2c_struct, "endpoints");
				size_t val_endpoints =
					json_object_array_length(jo_i2c_obj_i);

				for (j = 0; j < val_endpoints; j++) {
					jo_i2c_struct =
						json_object_array_get_idx(
							jo_i2c_obj_i, j);
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid_type");
					string_val = json_object_get_string(
						jo_i2c_obj_j);

					if (strcmp(string_val, "bridge") == 0) {
						return EID_TYPE_BRIDGE;
					} else if (strcmp(string_val,
							  "static") == 0) {
						return EID_TYPE_STATIC;
					} else if (strcmp(string_val, "pool") ==
						   0) {
						return EID_TYPE_POOL;
					}
				}
			}
		}
	}
	return -1;
}

/**
 * Auxiliary function to get socket name from string parameter
 * Notice, that the string may start with null '\0' value ("\u0000" in json).
 * And, the function makes sure that the socket name starts with '\0', always.
 * If parameter socket_name cannot be found socket_name should not be touched.
 * @param[in]  jo_i2c_struct - json structure containing socket_name
 * @param[out] sockname - Socket name
 */
void mctp_json_get_socket_name(char **sockname, json_object *jo_i2c_struct)
{
	json_object *jo_obj_i =
		json_object_object_get(jo_i2c_struct, "socket_name");
	if (jo_obj_i != NULL) {
		int namelen = 0;
		const char *string_val = json_object_get_string(jo_obj_i);
		if (string_val[0] == 0) {
			namelen = 1 + strlen(&(string_val[1]));
			*sockname = calloc(namelen + 1, sizeof(char));
			memcpy(*sockname, string_val, namelen);
		} else {
			namelen = strlen(string_val);
			*sockname = calloc(namelen + 2, sizeof(char));
			memcpy(&((*sockname)[1]), string_val, namelen);
		}

		mctp_prinfo("Read socket name: \\0%s", &((*sockname)[1]));
	}
}

/**
 * @brief Get common paramiters from json_object for mctp-demux-daemon
 *        using I2C.
 *
 * @param[in]  jo - json_object got after parse string from JSON file
 * @param[in]  bus_num - I2C bus number
 * @param[out] sockname - Socket name
 *
 * @returns int return success or failure.
 */
int mctp_json_i2c_get_common_params_mctp_demux(json_object *jo,
					       uint8_t *bus_num,
					       uint8_t *bus_num_smq,
					       uint8_t *src_slave_addr,
					       char **sockname)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i = NULL;

	const char *string_val;
	uint8_t val = 0;
	size_t i;

	jo_i2c_struct = json_object_object_get(jo, "i2c");
	/* Get source slave address */
	jo_i2c_obj_main =
		json_object_object_get(jo_i2c_struct, "i2c_src_address");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_slave_addr = parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		if (jo_i2c_obj_i != NULL) {
			string_val = json_object_get_string(jo_i2c_obj_i);
			if (string_val != NULL) {
				if (strncmp(string_val, "i2c", 3) == 0) {
					val = parse_num(string_val + 3);
				}
			}
		}

		if (val == *bus_num) {
			/* Get bus number for slave mqueue*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number_smq");
			if (jo_i2c_obj_i != NULL) {
				string_val =
					json_object_get_string(jo_i2c_obj_i);
				if (string_val != NULL) {
					if (strncmp(string_val, "i2c", 3) ==
					    0) {
						*bus_num_smq =
							(uint8_t)parse_num(
								string_val + 3);
					}
				}
			} else {
				*bus_num_smq = val;
			}

			/* Get and set socketname */
			mctp_json_get_socket_name(sockname, jo_i2c_struct);
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Get paramiters from json_object for mctp-demux-daemon
 *        using I2C.
 *
 * @param[in]  jo - json_object got after parse string from JSON file
 * @param[in]  bus_num - I2C bus number
 * @param[out] sockname - Socket name
 * @param[out] dest_slave_addr - Destination slave address (e.g. FPGA)
 * @param[out] src_slave_addr - Source slave address (e.g. HMC)
 * @param[out] src_eid - EID of top-Most bus owner
 *
 * @returns int return success or failure.
 */
int mctp_json_i2c_get_params_bridge_static_demux(json_object *jo,
						 uint8_t *bus_num,
						 uint8_t *dest_slave_addr,
						 uint8_t *src_eid)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j;

	jo_i2c_struct = json_object_object_get(jo, "i2c");
	/* Get own EID */
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "src_eid");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_eid = (uint8_t)parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0) {
					/* Get destination slave address */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"i2c_slave_address");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					*dest_slave_addr =
						(uint8_t)parse_num(string_val);
				} else if (strcmp(string_val, "static") == 0) {
					/* Get destination slave address */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"i2c_slave_address");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					*dest_slave_addr =
						(uint8_t)parse_num(string_val);
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

int mctp_json_i2c_get_params_static_demux(
	json_object *jo, uint8_t *bus_num,
	struct mctp_static_endpoint_mapper *endpoints)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val = 0;
	size_t i, j, k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		if (jo_i2c_obj_i != NULL) {
			string_val = json_object_get_string(jo_i2c_obj_i);
			if (string_val != NULL) {
				if (strncmp(string_val, "i2c", 3) == 0) {
					val = parse_num(string_val + 3);
				}
			}
		}

		if (val == *bus_num) {
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number");
			string_val = json_object_get_string(jo_i2c_obj_i);
			val = parse_num(string_val + 3);
			endpoints[k].bus_num = val;

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "static") == 0) {
					/* Get static EID */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					endpoints[k].endpoint_num =
						(uint8_t)parse_num(string_val);
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"i2c_slave_address");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					endpoints[k].slave_address =
						(uint8_t)parse_num(string_val);
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "mux_addr");
					if (jo_i2c_obj_j == NULL) {
						continue;
					}
					endpoints[k].mux_addr =
						(uint8_t)parse_num(
							json_object_get_string(
								jo_i2c_obj_j));
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "mux_channel");
					if (jo_i2c_obj_j == NULL) {
						continue;
					}
					endpoints[k].mux_channel =
						(uint8_t)parse_num(
							json_object_get_string(
								jo_i2c_obj_j));
				}
			}
			if (++k >= MCTP_I2C_MAX_BUSES) {
				break;
			}
		}
	}

	return EXIT_SUCCESS;
}

int mctp_json_i2c_get_params_pool_demux(
	json_object *jo, uint8_t *bus_num,
	struct mctp_static_endpoint_mapper **static_endpoints_tab,
	uint8_t *static_endpoints_len)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j, k, l;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "pool") == 0) {
					/* Get pool of EID's */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid");
					size_t pool_of_endpoints =
						json_object_array_length(
							jo_i2c_obj_j);

					*static_endpoints_len =
						(uint8_t)pool_of_endpoints;

					*static_endpoints_tab = malloc(
						*static_endpoints_len *
						sizeof(struct mctp_static_endpoint_mapper));
					if (*static_endpoints_tab == NULL) {
						mctp_prerr(
							"Malloc static endpoints failed!");
						return EXIT_FAILURE;
					}

					for (k = 0; k < pool_of_endpoints;
					     k++) {
						jo_i2c_struct =
							json_object_array_get_idx(
								jo_i2c_obj_j,
								k);
						string_val =
							json_object_get_string(
								jo_i2c_struct);
						val = parse_num(string_val);
						// Initial default values
						(*static_endpoints_tab)[k]
							.endpoint_num = val;
						(*static_endpoints_tab)[k]
							.slave_address = 0;
						(*static_endpoints_tab)[k]
							.support_mctp = 0;
						for (l = 0; l < 16; l++) {
							(*static_endpoints_tab)[k]
								.udid[l] = 0;
						}
					}
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Get common paramiters from json_object for mctp-ctrl
 *        using I2C.
 *
 * @param[in]  jo - json_object got after parse string from JSON file
 * @param[in]  bus_num - I2C bus number
 * @param[out] sockname - Socket name
 * @param[out] src_eid - EID of top-Most bus owner
 * @param[out] dest_slave_addr - Destination slave address (e.g. FPGA)
 * @param[out] src_slave_addr - Source slave address (e.g. HMC)
 */
void mctp_json_i2c_get_common_params_ctrl(json_object *jo, uint8_t *bus_num,
					  char **sockname, uint8_t *src_eid,
					  uint8_t *dest_slave_addr,
					  uint8_t *logical_busses,
					  uint8_t *src_slave_addr)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val = 0;
	size_t i, j, k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	/* Get source slave address */
	jo_i2c_obj_main =
		json_object_object_get(jo_i2c_struct, "i2c_src_address");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_slave_addr = parse_num(string_val);

	/* Get own EID */
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "src_eid");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_eid = parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		if (jo_i2c_obj_i != NULL) {
			string_val = json_object_get_string(jo_i2c_obj_i);
			if (string_val != NULL) {
				if (strncmp(string_val, "i2c", 3) == 0) {
					val = parse_num(string_val + 3);
				}
			}
		}

		if (val == *bus_num) {
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number");
			string_val = json_object_get_string(jo_i2c_obj_i);
			val = parse_num(string_val + 3);
			logical_busses[k] = val;

			/* Get and set socketname */
			mctp_json_get_socket_name(sockname, jo_i2c_struct);

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0 ||
				    strcmp(string_val, "static") == 0) {
					/* Get destination slave address */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"i2c_slave_address");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					dest_slave_addr[k] =
						(uint8_t)parse_num(string_val);
				} else {
					dest_slave_addr[k] = 0;
				}
			}
			if (++k >= MCTP_I2C_MAX_BUSES) {
				break;
			}
		}
	}
}

/**
 * @brief Get paramiters for eid_type = bridge from json_object
 *        for mctp-ctrl using I2C.
 *
 * @param[in] jo - json_object got after parse string from JSON file
 * @param[in] bus_num - I2C bus number
 * @param[out] dest_eid - EID of endpoint
 * @param[out] pool_start - Bridge pool start
 */
void mctp_json_i2c_get_params_bridge_ctrl(json_object *jo, uint8_t *bus_num,
					  uint8_t *dest_eid,
					  uint8_t *pool_start)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0) {
					/* Get bridge EID */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					*dest_eid =
						(uint8_t)parse_num(string_val);
					/* Get bridge pool start */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"eid_pool_start");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					*pool_start =
						(uint8_t)parse_num(string_val);
				}
			}
		}
	}
}

/**
 * @brief Get paramiters for eid_type = static from json_object
 *        for mctp-ctrl using I2C.
 *
 * @param[in] jo - json_object got after parse string from JSON file
 * @param[in] bus_num - I2C bus number
 * @param[in] dest_eid_tab - Table of EID
 * @param[out] dest_eid_len - Length of table
 * @param[out] uuid - UUID
 */
int mctp_json_i2c_get_params_static_ctrl(json_object *jo, uint8_t *bus_num,
					 uint8_t *dest_eid_tab,
					 uint8_t *dest_eid_len, uint8_t *uuid)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val = 0;
	size_t i, j;
	uint8_t k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		if (jo_i2c_obj_i != NULL) {
			string_val = json_object_get_string(jo_i2c_obj_i);
			if (string_val != NULL) {
				if (strncmp(string_val, "i2c", 3) == 0) {
					val = parse_num(string_val + 3);
				}
			}
		}

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "static") == 0) {
					/* Get static EID */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					mctp_prdebug(
						"k = %d, val_endpoints = %zi",
						k, val_endpoints);
					dest_eid_tab[k++] =
						(uint8_t)parse_num(string_val);

					/* Get UUID */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "uuid");
					string_val = json_object_get_string(
						jo_i2c_obj_j);

					if (string_val == NULL)
						*uuid = 0;
					else
						*uuid = (uint8_t)parse_num(
							string_val);
				}
			}
		}
	}

	*dest_eid_len = k;

	return EXIT_SUCCESS;
}

/**
 * @brief Get paramiters for eid_type = static from json_object
 *        for mctp-ctrl using I2C.
 *
 * @param[in] jo - json_object got after parse string from JSON file
 * @param[in] bus_num - I2C bus number
 * @param[in] dest_eid_tab - Table of EID
 * @param[out] dest_eid_len - Length of table
 */
int mctp_json_i2c_get_params_pool_ctrl(json_object *jo, uint8_t *bus_num,
				       uint8_t *dest_eid_tab,
				       uint8_t *dest_eid_len)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val = 0;
	size_t i, j;
	uint8_t k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		if (jo_i2c_obj_i != NULL) {
			string_val = json_object_get_string(jo_i2c_obj_i);
			if (string_val != NULL) {
				if (strncmp(string_val, "i2c", 3) == 0) {
					val = parse_num(string_val + 3);
				}
			}
		}

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "endpoints");
			size_t val_endpoints =
				json_object_array_length(jo_i2c_obj_i);

			for (j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(
					jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(
					jo_i2c_struct, "eid_type");
				string_val =
					json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "pool") == 0) {
					/* Get pool of EID's */
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct, "eid");
					size_t pool_of_endpoints =
						json_object_array_length(
							jo_i2c_obj_j);

					*dest_eid_len =
						(uint8_t)pool_of_endpoints;

					for (k = 0; k < *dest_eid_len; k++) {
						jo_i2c_struct =
							json_object_array_get_idx(
								jo_i2c_obj_j,
								k);
						string_val =
							json_object_get_string(
								jo_i2c_struct);
						dest_eid_tab[k] =
							(uint8_t)parse_num(
								string_val);
					}
				}
			}
		}
	}

	return EXIT_SUCCESS;
}
