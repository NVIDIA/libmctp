#ifndef __MCTP_CMDLINE_H
#define __MCTP_CMDLINE_H

#include "libmctp-astspi.h"

#define MCTP_WRITE_DATA_BUFF_SIZE 1024
#define MCTP_READ_DATA_BUFF_SIZE 1024
#define MCTP_PVT_BIND_BUFF_SIZE 64

#define MCTP_CMDLINE_WRBUFF_WIDTH 3

#define MCTP_CTRL_DELAY_DEFAULT 10

#define UUID_STR_LEN 36

/* Command line options for various operations */
typedef enum mctp_cmdline_ops {
	MCTP_CMDLINE_OP_READ_DATA,
	MCTP_CMDLINE_OP_WRITE_DATA,
	MCTP_CMDLINE_OP_BIND_READ_DATA,
	MCTP_CMDLINE_OP_BIND_WRITE_DATA,
	MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV,
	MCTP_CMDLINE_OP_NONE,
} mctp_cmdline_ops_t;

/* Various SPI read/write operations (NVIDIA VDM commands) */
typedef enum mctp_spi_vdm_ops {
	MCTP_SPI_SET_ENDPOINT_ID = 1,
	MCTP_SPI_GET_ENDPOINT_ID,
	MCTP_SPI_GET_ENDPOINT_UUID,
	MCTP_SPI_GET_VERSION,
	MCTP_SPI_GET_MESSAGE_TYPE,
} mctp_spi_vdm_ops_t;

/* Various SPI read/write operations (NVIDIA IANA VDM commands) */
typedef enum mctp_spi_iana_vdm_ops {
	MCTP_SPI_SET_ENDPOINT_UUID = 1,
	MCTP_SPI_BOOT_COMPLETE,
	MCTP_SPI_HEARTBEAT_SEND,
	MCTP_SPI_HEARTBEAT_ENABLE,
	MCTP_SPI_QUERY_BOOT_STATUS,
} mctp_spi_iana_vdm_ops_t;

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
	bool remove_duplicates;
};

/* SPI operations */
typedef enum mctp_spi_cmd_mode {
	MCTP_SPI_NONE = 0,
	MCTP_SPI_RAW_READ,
	MCTP_SPI_RAW_WRITE,
	MCTP_SPI_MAILBOX_WRITE,
	MCTP_SPI_MAILBOX_READ_READY,
	MCTP_SPI_MAILBOX_READ_DONE,
	MCTP_SPI_MAILBOX_SPB_RESET,
	MCTP_SPI_MAILBOX_WRITE_LEN,
	MCTP_SPI_POST_READ,
	MCTP_SPI_POST_WRITE,
	MCTP_SPI_GPIO_READ,
} mctp_spi_cmd_mode_t;

/**/
typedef enum mctp_spi_hrtb_ops {
	MCTP_SPI_HB_DISABLE_CMD = 0,
	MCTP_SPI_HB_ENABLE_CMD,
} mctp_spi_hrtb_ops_t;

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
	uint8_t src_slave_addr;
	uint8_t logical_busses[4];
	uint8_t dest_slave_addr[4];
};

/* USB specific configuration */
struct mctp_cmdline_usb {
	uint8_t own_eid;
	uint8_t bridge_eid;
	uint8_t bridge_pool_start;
	bool remove_duplicates;
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
	uint8_t *dest_eid_tab;
	uint8_t dest_eid_tab_len;
	uint8_t uuid;
	char uuid_str[UUID_STR_LEN];
	union {
		struct mctp_cmdline_pcie pcie;
		struct mctp_cmdline_spi spi;
		struct mctp_cmdline_i2c i2c;
		struct mctp_cmdline_usb usb;
	};
} mctp_cmdline_args_t;

#endif /* __MCTP_CMDLINE_H */
