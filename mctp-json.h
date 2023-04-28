#include <json-c/json.h>

int parse_num(const char *param);
int mctp_json_get_tokener_parse(const char *path);
int mctp_json_i2c_get_params_mctp_demux(json_object * jo, uint8_t *bus_num, char *sockname,
				uint8_t *dest_slave_addr, uint8_t *src_slave_addr, uint8_t *src_eid);
int mctp_json_i2c_get_params_mctp_ctrl(json_object *jo, uint8_t *bus_num,
				char *sockname, uint8_t *src_eid);