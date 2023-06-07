/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBMCTP_SMBUS_H
#define _LIBMCTP_SMBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

#define MCTP_SMBUS_POLL_TIMEOUT     1000
#define MCTP_I2C_BUS_NUM_DEFAULT 2
#define MCTP_I2C_DEST_SLAVE_ADDR_DEFAULT 0x30
#define MCTP_I2C_SRC_SLAVE_ADDR_DEFAULT 0x18
#define MCTP_SMBUS_READ_TIMEOUT_WAIT 100 // microseconds
#define MCTP_SMBUS_READ_TIMEOUT_REPEAT 20

struct mctp_binding_smbus;

struct mctp_smbus_pkt_private {
	uint8_t i2c_bus;
	uint8_t dest_slave_addr;
	uint8_t src_slave_addr;
	uint8_t _reserved[32];
} __attribute__((packed));

struct mctp_static_endpoint_mapper {
	uint8_t endpoint_num;
	uint8_t slave_address;
	uint8_t support_mctp;
	uint8_t udid[16];
};

struct mctp_binding_smbus *mctp_smbus_init(uint8_t bus, uint8_t bus_smq, uint8_t dest_addr,
			     uint8_t src_addr, uint8_t eid_type);

int mctp_smbus_open_in_bus(struct mctp_binding_smbus *smbus, int in_bus, int src_slv_addr);
int mctp_smbus_open_out_bus(struct mctp_binding_smbus *smbus, int out_bus);
int mctp_smbus_read_only(struct mctp_binding_smbus *smbus);
int mctp_smbus_read(struct mctp_binding_smbus *smbus);
int mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd);
int mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd);
int mctp_smbus_get_in_fd(struct mctp_binding_smbus *smbus);
int mctp_smbus_get_out_fd(struct mctp_binding_smbus *smbus);
void mctp_smbus_register_bus(struct mctp_binding_smbus *smbus,
			     struct mctp *mctp, mctp_eid_t eid);
void mctp_smbus_free(struct mctp_binding_smbus *smbus);

uint8_t set_global_dest_slave_addr_from_pool(uint8_t eid);
int send_get_udid_command(struct mctp_binding_smbus *smbus, uint8_t *inbuf, uint8_t len);
int send_mctp_get_ver_support_command(struct mctp_binding_smbus *smbus, uint8_t which_endpoint);
int check_mctp_get_ver_support(struct mctp_binding_smbus *smbus, uint8_t which_endpoint,
			uint8_t *inbuf, uint8_t len);
int check_device_supports_mctp(struct mctp_binding_smbus *smbus);
int find_and_set_pool_of_endpoints(struct mctp_binding_smbus *smbus);

/* SMBUS binding API's */
int mctp_smbus_poll(struct mctp_binding_smbus *smbus, int timeout);
struct mctp_binding *mctp_binding_smbus_core(struct mctp_binding_smbus *smbus);

int mctp_smbus_init_pollfd(struct mctp_binding_smbus *smbus,
			     struct pollfd *pollfd);

#ifdef __cplusplus
}
#endif
#endif /* _LIBMCTP_SMBUS_H */
