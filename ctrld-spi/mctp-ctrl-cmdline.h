/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __MCTP_CMDLINE_H
#define __MCTP_CMDLINE_H

#include "libmctp.h"

#define MCTP_WRITE_DATA_BUFF_SIZE 1024
#define MCTP_READ_DATA_BUFF_SIZE 1024
#define MCTP_PVT_BIND_BUFF_SIZE 64

#define MCTP_CMDLINE_WRBUFF_WIDTH 3

/* SPI device and channel details */
#define AST_MCTP_SPI_DEV_NUM 0
#define AST_MCTP_SPI_CHANNEL_NUM 2

#define ASTP_SPI_RAW_RW_BUFF_LEN 64

/* Command line structure */
typedef struct mctp_cmdline_args_ {
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

#endif /* __MCTP_CMDLINE_H */
