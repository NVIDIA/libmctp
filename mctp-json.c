/* */

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <errno.h>

#include "mctp-json.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"

json_object *parsed_json;
char *buffer;

int parse_num(const char *param)
{
	intmax_t num;
	char *endptr = NULL;

	num = strtoimax(param, &endptr, 10);

	if (*endptr != '\0' && *endptr != ' ') {
		fprintf(stderr, "Invalid number: %s\n", param);
		exit(1);
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
int mctp_json_get_tokener_parse(const char *path)
{
	int rc;
	FILE *fp;
	int file_size;

	fp = fopen(path, "r");

	if (fp == NULL) {
		parsed_json = NULL;
		printf("Unable to open: %s, err = %d\n", path, errno);
		goto err_close;
	}
	else {
		rc = fseek(fp, 0, SEEK_END);
		if (rc == -1) {
			printf("Failed to fseek\n");
			goto err_close;
		}

		file_size = ftell(fp);
		if (file_size == -1) {
			printf("Failed to ftell\n");
			goto err_close;
		}

		rc = fseek(fp, 0, SEEK_SET);
		if (rc == -1) {
			printf("Failed to fseek\n");
			goto err_close;
		}

		buffer = malloc(file_size);
		rc = fread(buffer, file_size, 1, fp);
		if (rc <= 0) {
			printf("Failed to fread\n");
			goto err_close;
		}
	}
	fclose(fp);

	/* Get parameters from *.json */
	parsed_json = json_tokener_parse(buffer);

	free(buffer);

	if (parsed_json == NULL) {
		printf("Json tokener parse fail\n\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

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
int mctp_json_get_eid_type(json_object *jo, const char *binding_name, uint8_t *bus_num)
{
	if (strcmp(binding_name, "astpcie") == 0) {
		printf("Parameters for PCIe from JSON file not supported\n");
	}
	else if (strcmp(binding_name, "astspi") == 0) {
		printf("Parameters for SPI from JSON file not supported\n");
	}
	else if (strcmp(binding_name, "smbus") == 0) {
		json_object *jo_i2c_struct;
		json_object *jo_i2c_obj_main;
		json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

		const char *string_val;
		uint8_t val;
		size_t i, j;

		jo_i2c_struct = json_object_object_get(jo, "i2c");

		jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
		size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

		for(i = 0; i < val_conf_i2c; i++) {
			jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number_smq");
			string_val = json_object_get_string(jo_i2c_obj_i);
			val = parse_num(string_val + 3);

			if (val == *bus_num) {
				jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
				size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

				for(j = 0; j < val_endpoints; j++) {
					jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
					string_val = json_object_get_string(jo_i2c_obj_j);

					if (strcmp(string_val, "bridge") == 0) {
						return EID_TYPE_BRIDGE;
					}
					else if (strcmp(string_val, "static") == 0) {
						return EID_TYPE_STATIC;
					}
					else if (strcmp(string_val, "pool") == 0) {
						return EID_TYPE_POOL;
					}
				}
			}
		}
	}
	return -1;
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
int mctp_json_i2c_get_common_params_mctp_demux(json_object *jo, uint8_t *bus_num,
				uint8_t *bus_num_smq, uint8_t *src_slave_addr, char **sockname)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i = NULL;

	const char *string_val;
	uint8_t val;
	size_t i;

	jo_i2c_struct = json_object_object_get(jo, "i2c");
	/* Get source slave address */
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "i2c_src_address");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_slave_addr = parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get bus number for slave mqueue*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "bus_number_smq");
			if ( jo_i2c_obj_i != NULL ) {
				string_val = json_object_get_string(jo_i2c_obj_i);
				*bus_num_smq = (uint8_t)parse_num(string_val + 3);
			} else {
				*bus_num_smq = val;
			}

			/* Get and set socketname */
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "socket_name");
			string_val = json_object_get_string(jo_i2c_obj_i);
			*sockname = calloc(strlen(string_val) + 2, sizeof(char));
			strcpy(*sockname + 1, string_val);
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
int mctp_json_i2c_get_params_bridge_static_demux(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_slave_addr, uint8_t *src_eid)
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

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

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
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "i2c_slave_address");
					string_val = json_object_get_string(jo_i2c_obj_j);
					*dest_slave_addr = (uint8_t)parse_num(string_val);
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
	uint8_t val;
	size_t i, j, k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for (i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number");
			string_val = json_object_get_string(jo_i2c_obj_i);
			val = parse_num(string_val + 3);
			endpoints[k].bus_num = val;

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "static") == 0) {
					/* Get static EID */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid");
					string_val = json_object_get_string(jo_i2c_obj_j);
					endpoints[k].endpoint_num =
						(uint8_t)parse_num(string_val);
					jo_i2c_obj_j = json_object_object_get(
						jo_i2c_struct,
						"i2c_slave_address");
					string_val = json_object_get_string(
						jo_i2c_obj_j);
					endpoints[k].slave_address =
						(uint8_t)parse_num(string_val);
				}
			}
			if (++k >= MCTP_I2C_MAX_BUSES) {
				break;
			}
		}
	}

	return EXIT_SUCCESS;
}

int mctp_json_i2c_get_params_pool_demux(json_object *jo, uint8_t *bus_num,
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

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "pool") == 0) {
					/* Get pool of EID's */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid");
					size_t pool_of_endpoints = json_object_array_length(jo_i2c_obj_j);

					*static_endpoints_len = (uint8_t)pool_of_endpoints;

					*static_endpoints_tab = malloc(*static_endpoints_len * sizeof(struct mctp_static_endpoint_mapper));
					if (*static_endpoints_tab == NULL) {
						mctp_prerr("Malloc static endpoints failed!");
						return EXIT_FAILURE;
					}

					for(k = 0; k < pool_of_endpoints; k++) {
						jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_j, k);
						string_val = json_object_get_string(jo_i2c_struct);
						val = parse_num(string_val);
						// Initial default values
						(*static_endpoints_tab)[k].endpoint_num = val;
						(*static_endpoints_tab)[k].slave_address = 0;
						(*static_endpoints_tab)[k].support_mctp = 0;
						for (l = 0; l < 16; l++) {
							(*static_endpoints_tab)[k].udid[l] = 0;
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
	uint8_t val;
	size_t i, j, k = 0;
	*sockname = NULL;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	/* Get source slave address */
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "i2c_src_address");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_slave_addr = parse_num(string_val);

	/* Get own EID */
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "src_eid");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_eid = parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct,
							      "bus_number");
			string_val = json_object_get_string(jo_i2c_obj_i);
			val = parse_num(string_val + 3);
			logical_busses[k] = val;

			if (*sockname == NULL) {
				/* Get and set socketname */
				jo_i2c_obj_i = json_object_object_get(
					jo_i2c_struct, "socket_name");
				string_val =
					json_object_get_string(jo_i2c_obj_i);
				*sockname = calloc(strlen(string_val) + 2,
						   sizeof(char));
				strcpy(*sockname + 1, string_val);
			}

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0 ||
				    strcmp(string_val, "static") == 0) {
					/* Get destination slave address */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "i2c_slave_address");
					string_val = json_object_get_string(jo_i2c_obj_j);
					dest_slave_addr[k] =
						(uint8_t)parse_num(string_val);
				}
				else {
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
				uint8_t *dest_eid, uint8_t *pool_start)
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

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0) {
					/* Get bridge EID */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid");
					string_val = json_object_get_string(jo_i2c_obj_j);
					*dest_eid = (uint8_t)parse_num(string_val);
					/* Get bridge pool start */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_pool_start");
					string_val = json_object_get_string(jo_i2c_obj_j);
					*pool_start = (uint8_t)parse_num(string_val);
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
 * @param[out] dest_eid_tab - Table of EID
 * @param[out] dest_eid_len - Length of table
 * @param[out] uuid - UUID
 */
int mctp_json_i2c_get_params_static_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t **dest_eid_tab, uint8_t *dest_eid_len, uint8_t *uuid)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j, k = 0;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	*dest_eid_len = 4;
	*dest_eid_tab = malloc(*dest_eid_len * sizeof(uint8_t));
	if (*dest_eid_tab == NULL) {
		mctp_prerr("Malloc static endpoints failed!");
		return EXIT_FAILURE;
	}

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "static") == 0) {
					/* Get static EID */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid");
					string_val = json_object_get_string(jo_i2c_obj_j);
					(*dest_eid_tab)[k++] =
						(uint8_t)parse_num(string_val);

					/* Get UUID */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "uuid");
					string_val = json_object_get_string(jo_i2c_obj_j);

					if (string_val == NULL)
						*uuid = 0;
					else
						*uuid = (uint8_t)parse_num(string_val);
				}
			}
		}
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Get paramiters for eid_type = static from json_object
 *        for mctp-ctrl using I2C.
 *
 * @param[in] jo - json_object got after parse string from JSON file
 * @param[in] bus_num - I2C bus number
 * @param[out] dest_eid_tab - Table of EID
 * @param[out] dest_eid_len - Length of table
 */
int mctp_json_i2c_get_params_pool_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t **dest_eid_tab, uint8_t *dest_eid_len)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j, k;

	jo_i2c_struct = json_object_object_get(jo, "i2c");

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i =
			json_object_object_get(jo_i2c_struct, "bus_number_smq");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "pool") == 0) {
					/* Get pool of EID's */
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid");
					size_t pool_of_endpoints = json_object_array_length(jo_i2c_obj_j);

					*dest_eid_len = (uint8_t)pool_of_endpoints;
					*dest_eid_tab = malloc(*dest_eid_len * sizeof(uint8_t));
					if (*dest_eid_tab == NULL) {
						mctp_prerr("Malloc static endpoints failed!");
						return EXIT_FAILURE;
					}

					for(k = 0; k < *dest_eid_len; k++) {
						jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_j, k);
						string_val = json_object_get_string(jo_i2c_struct);
						(*dest_eid_tab)[k] = (uint8_t)parse_num(string_val);
					}
				}
			}
		}
	}
	return EXIT_SUCCESS;
}
