#ifndef __MCTP_CMDLINE_H
#define __MCTP_CMDLINE_H

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
	uint8_t pci_own_eid;
	uint8_t i2c_own_eid;
	uint8_t pci_bridge_eid;
	uint8_t i2c_bridge_eid;
	uint8_t pci_bridge_pool_start;
	uint8_t i2c_bridge_pool_start;
} mctp_cmdline_args_t;

/* Function prototypes */
void mctp_ctrld_help(FILE *stream, int exit_code, const char *i2cd_name);
extern int mctp_command_line_run(mctp_cmdline_args_t *);

#endif /* __MCTP_CMDLINE_H */
