/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __MCTP_SPI_CMDLINE_H
#define __MCTP_SPI_CMDLINE_H

#include "libmctp.h"

/* SPI device and channel details */
#define AST_MCTP_SPI_DEV_NUM 0
#define AST_MCTP_SPI_CHANNEL_NUM 2

#define ASTP_SPI_RAW_RW_BUFF_LEN 64

/* Various SPI read/write operations (NVIDIA IANA VDM commands) */
typedef enum mctp_spi_iana_vdm_ops {
	MCTP_SPI_SET_ENDPOINT_UUID = 1,
	MCTP_SPI_BOOT_COMPLETE,
	MCTP_SPI_HEARTBEAT_SEND,
	MCTP_SPI_HEARTBEAT_ENABLE,
	MCTP_SPI_QUERY_BOOT_STATUS,
} mctp_spi_iana_vdm_ops_t;

/* Various SPI read/write operations (NVIDIA VDM commands) */
typedef enum mctp_spi_vdm_ops {
	MCTP_SPI_SET_ENDPOINT_ID = 1,
	MCTP_SPI_GET_ENDPOINT_ID,
	MCTP_SPI_GET_ENDPOINT_UUID,
	MCTP_SPI_GET_VERSION,
	MCTP_SPI_GET_MESSAGE_TYPE,
} mctp_spi_vdm_ops_t;

/**/
typedef enum mctp_spi_hrtb_ops {
	MCTP_SPI_HB_DISABLE_CMD = 0,
	MCTP_SPI_HB_ENABLE_CMD,
} mctp_spi_hrtb_ops_t;

/* Various commandline modes */
typedef enum mctp_spi_mode_ops {
	MCTP_SPI_MODE_CMDLINE,
	MCTP_SPI_MODE_DAEMON,
	MCTP_SPI_MODE_TEST,
} mctp_spi_mode_ops_t;

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

/* Command line structure */
typedef struct mctp_spi_cmdline_args_ {
	char name[10];
	int device_id;
	uint8_t verbose;
	mctp_binding_ids_t binding_type;
	int delay;
	mctp_spi_cmd_mode_t cmd_mode;
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
	mctp_eid_t src_eid;
	mctp_eid_t dest_eid;
	mctp_spi_iana_vdm_ops_t iana_vdm_ops;
	mctp_spi_vdm_ops_t vdm_ops;
} mctp_spi_cmdline_args_t;

/* Function prototypes */
void mctp_ctrld_help(FILE *stream, int exit_code, const char *i2cd_name);

/* MCTP SPI Test APIs */
int mctp_spi_set_endpoint_uuid(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_set_boot_complete(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_heartbeat_send(int fd, uint8_t tid);
int mctp_spi_heartbeat_enable(int fd, uint8_t tid, int enable);
int mctp_spi_query_boot_status(mctp_spi_cmdline_args_t *cmd);

int mctp_spi_init(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_deinit(void);
void mctp_spi_test_cmd(mctp_ctrl_t *ctrl, mctp_spi_cmdline_args_t *cmd);

#endif /* __MCTP_SPI_CMDLINE_H */
