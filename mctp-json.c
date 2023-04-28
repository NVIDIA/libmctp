/* */

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <errno.h>

#include "mctp-json.h"
#include "libmctp-log.h"

json_object *parsed_json;

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

int mctp_json_get_tokener_parse(const char *path)
{
	FILE *fp;
	char buffer[1024];

	fp = fopen(path, "r");

	if (fp == NULL) {
		parsed_json = NULL;
		printf("Unable to open: %s, err = %d\n", path, errno);
		return EXIT_FAILURE;
	}
	else {
		fread(buffer, 1024, 1, fp);
	}
	fclose(fp);

	/* Get parameters from *.json */
	parsed_json = json_tokener_parse(buffer);

	if (parsed_json == NULL) {
		printf("Json tokener parse fail\n\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int mctp_json_i2c_get_params_mctp_demux(json_object *jo, uint8_t *bus_num, char *sockname,
				uint8_t *dest_slave_addr, uint8_t *src_slave_addr,
				uint8_t *src_eid)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j;

	jo_i2c_struct = json_object_object_get(jo, "i2c");
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "i2c_src_address");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_slave_addr = parse_num(string_val);

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
			/* Get and set socketname */
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "socket_name");
			string_val = json_object_get_string(jo_i2c_obj_i);
			sockname = realloc(sockname, strlen(string_val));
			memcpy(sockname, string_val, strlen(string_val));

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0) {
					printf("bridge\n");
					jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "i2c_slave_address");
					string_val = json_object_get_string(jo_i2c_obj_j);
					*dest_slave_addr = (uint8_t)parse_num(string_val);
				}
				else if (strcmp(string_val, "static") == 0) {
					printf("static\n");
				}
				else if (strcmp(string_val, "pool") == 0) {
					printf("pool\n");
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

/* Are we need params in file for bridge?:
	bridge_eid - EID30 for FPGA, [uint8_t *dest_eid]
	bridge_pool_start - EID32(this is start endpoint to discovery) [uint8_t *pool_start_eid]
*/
int mctp_json_i2c_get_params_mctp_ctrl(json_object *jo, uint8_t *bus_num,
				char *sockname, uint8_t *src_eid)
{
	json_object *jo_i2c_struct;
	json_object *jo_i2c_obj_main;
	json_object *jo_i2c_obj_i, *jo_i2c_obj_j;

	const char *string_val;
	uint8_t val;
	size_t i, j;

	jo_i2c_struct = json_object_object_get(jo, "i2c");
	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "src_eid");
	string_val = json_object_get_string(jo_i2c_obj_main);
	*src_eid = parse_num(string_val);

	jo_i2c_obj_main = json_object_object_get(jo_i2c_struct, "buses");
	size_t val_conf_i2c = json_object_array_length(jo_i2c_obj_main);

	for(i = 0; i < val_conf_i2c; i++) {
		jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_main, i);
		jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "bus_number");
		string_val = json_object_get_string(jo_i2c_obj_i);
		val = parse_num(string_val + 3);

		if (val == *bus_num) {
			/* Get and set socketname */
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "socket_name");
			string_val = json_object_get_string(jo_i2c_obj_i);
			sockname = realloc(sockname, strlen(string_val));
			memcpy(sockname, string_val, strlen(string_val));

			/* Get parameters for endpoints*/
			jo_i2c_obj_i = json_object_object_get(jo_i2c_struct, "endpoints");
			size_t val_endpoints = json_object_array_length(jo_i2c_obj_i);

			for(j = 0; j < val_endpoints; j++) {	//iteracja po tab endpoints, potem po elem tab.
				jo_i2c_struct = json_object_array_get_idx(jo_i2c_obj_i, j);
				jo_i2c_obj_j = json_object_object_get(jo_i2c_struct, "eid_type");
				string_val = json_object_get_string(jo_i2c_obj_j);

				if (strcmp(string_val, "bridge") == 0) {
					printf("bridge");
					//If will be needed read: dest_eid - bridge_eid
				}
				else if (strcmp(string_val, "static") == 0) {
					printf("static");
				}
				else if (strcmp(string_val, "pool") == 0) {
					printf("pool");
				}
			}
		}
	}

	return EXIT_SUCCESS;
}