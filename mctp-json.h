#include <json-c/json.h>

enum eid_types {
	EID_TYPE_BRIDGE,
	EID_TYPE_STATIC,
	EID_TYPE_POOL,
};

int parse_num(const char *param);
int mctp_json_get_tokener_parse(const char *path);
int mctp_json_get_eid_type(json_object *jo, const char *binding_name, uint8_t *bus_num);

int mctp_json_i2c_get_common_params_mctp_demux(json_object *jo, uint8_t *bus_num,
				uint8_t *bus_num_smq, char **sockname);
int mctp_json_i2c_get_params_bridge_static_demux(json_object * jo, uint8_t *bus_num,
				uint8_t *dest_slave_addr, uint8_t *src_slave_addr,
				uint8_t *src_eid);
int mctp_json_i2c_get_params_static_demux(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_eid);
void mctp_json_i2c_get_common_params_ctrl(json_object *jo, uint8_t *bus_num,
				char **sockname, uint8_t *src_eid, uint8_t *dest_slave_addr,
				uint8_t *src_slave_addr);
void mctp_json_i2c_get_params_bridge_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t *dest_eid, uint8_t *pool_start);
int mctp_json_i2c_get_params_static_ctrl(json_object *jo, uint8_t *bus_num,
				uint8_t **dest_eid_tab, uint8_t *dest_eid_len, uint8_t *uuid);
