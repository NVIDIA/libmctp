#ifndef __MCTP_CMDLINE_H
#define __MCTP_CMDLINE_H

#include "libmctp-astspi.h"

#define MCTP_WRITE_DATA_BUFF_SIZE 1024
#define MCTP_READ_DATA_BUFF_SIZE 1024
#define MCTP_PVT_BIND_BUFF_SIZE 64

#define MCTP_CMDLINE_WRBUFF_WIDTH 3

#define MCTP_CTRL_DELAY_DEFAULT 10

/* Command line options for various operations */
typedef enum mctp_cmdline_ops {
	MCTP_CMDLINE_OP_READ_DATA,
	MCTP_CMDLINE_OP_WRITE_DATA,
	MCTP_CMDLINE_OP_BIND_READ_DATA,
	MCTP_CMDLINE_OP_BIND_WRITE_DATA,
	MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV,
	MCTP_CMDLINE_OP_NONE,
} mctp_cmdline_ops_t;

/* Various commandline modes */
typedef enum mctp_mode_ops {
	MCTP_MODE_CMDLINE,
	MCTP_MODE_DAEMON,
	MCTP_SPI_MODE_TEST,
} mctp_mode_ops_t;

/* PCIE specific confguration */
struct mctp_cmdline_pcie {
	uint8_t own_eid;
	uint8_t bridge_eid;
	uint8_t bridge_pool_start;
};

/* SPI specific configuration */
struct mctp_cmdline_spi {
	mctp_spi_vdm_ops_t vdm_ops;
	mctp_spi_cmd_mode_t cmd_mode;
};

/* I2C specific configuration */
struct mctp_cmdline_i2c {
	uint8_t own_eid;
	uint8_t bridge_eid;
	uint8_t bridge_pool_start;
	uint8_t bus_num;
	uint8_t dest_slave_addr;
	uint8_t src_slave_addr;
};

/* Command line structure */
typedef struct mctp_cmdline_args_ {
	char name[10];
	int device_id;
	bool verbose;
	int delay;
	mctp_binding_ids_t binding_type;
	uint8_t bind_info[MCTP_PVT_BIND_BUFF_SIZE];
	int bind_len;
	int read;
	int write;
	uint8_t tx_data[MCTP_WRITE_DATA_BUFF_SIZE];
	int tx_len;
	uint8_t rx_data[MCTP_WRITE_DATA_BUFF_SIZE];
	uint16_t target_bdf;
	int use_socket;
	int mode;
	int list_device_op;
	mctp_cmdline_ops_t ops;
	mctp_eid_t dest_eid;
	mctp_eid_t dest_static_eid;
	uint8_t uuid;
	union {
		struct mctp_cmdline_pcie pcie;
		struct mctp_cmdline_spi spi;
		struct mctp_cmdline_i2c i2c;
	};
} mctp_cmdline_args_t;

#endif /* __MCTP_CMDLINE_H */
