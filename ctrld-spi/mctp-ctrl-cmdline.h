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

#define MCTP_WRITE_DATA_BUFF_SIZE   1024
#define MCTP_READ_DATA_BUFF_SIZE    1024
#define MCTP_PVT_BIND_BUFF_SIZE     64

#define MCTP_CMDLINE_WRBUFF_WIDTH   3

/* SPI device and channel details */
#define AST_MCTP_SPI_DEV_NUM            0
#define AST_MCTP_SPI_CHANNEL_NUM        2

#define ASTP_SPI_RAW_RW_BUFF_LEN        64

/* Command line options for various operations */
typedef enum mctp_cmdline_ops {
    MCTP_CMDLINE_OP_READ_DATA,
    MCTP_CMDLINE_OP_WRITE_DATA,
    MCTP_CMDLINE_OP_BIND_READ_DATA,
    MCTP_CMDLINE_OP_BIND_WRITE_DATA,
    MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV,
    MCTP_CMDLINE_OP_NONE,
} mctp_cmdline_ops_t;

typedef enum {
    CMD_SREG_W8 = 0x9,
    CMD_SREG_W16,
    CMD_SREG_W32,

    CMD_SREG_R8 = 0xD,
    CMD_SREG_R16,
    CMD_SREG_R32,

    CMD_MEM_W8 = 0x21,
    CMD_MEM_W16,
    CMD_MEM_W32,

    CMD_MEM_R8 = 0x25,
    CMD_MEM_R16,
    CMD_MEM_R32,

    CMD_RD_SNGL_FIFO8  = 0x28,
    CMD_RD_SNGL_FIFO16 = 0x29,
    CMD_RD_SNGL_FIFO32 = 0x2b,

    CMD_POLL_LOW  = 0x2C,
    CMD_POLL_HIGH = 0x2D,
    CMD_POLL_ALL  = 0x2F,

    CMD_MEM_BLK_W1 = 0x80,

    CMD_MEM_BLK_R1   = 0xA0,
    CMD_RD_BLK_FIFO1 = 0xC0,

    CMD_RD_SNGL_FIFO8_FSR  = 0x68,
    CMD_RD_SNGL_FIFO16_FSR = 0x69,
    CMD_RD_SNGL_FIFO32_FSR = 0x6B,
    CMD_BLK_RD_FIFO_FSR    = 0xE0,
} spb_spi_cmds_t;

typedef enum {
    SPI_CFG    = 0x00,
    SPI_STS    = 0x04,
    SPI_EC_STS = 0x08,
    SPI_IEN    = 0x0C,
    // ...
    SPI_SPIM2EC_MBX = 0x44,
    SPI_EC2SPIM_MBX = 0x48,
} spb_spi_regs_t;

typedef enum {
    EC_ACK           = 0x01000000,
    AP_REQUEST_WRITE = 0x02000000,
    AP_READY_TO_READ = 0x03000000,
    AP_FINISHED_READ = 0x04000000,
    AP_REQUEST_RESET = 0x05000000,
    EC_MSG_AVAILABLE = 0x10000000,
} spb_spi_mailbox_cmds_t;


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

/* SPI test command return types */
typedef enum mctp_spi_ret_type {
    MCTP_SPI_FAILURE,
    MCTP_SPI_SUCCESS,
} mctp_spi_ret_type_t;

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

/* SPI-xfer params */
typedef struct {
    int     send_len;
    int     recv_len;
    uint8_t sbuf[ASTP_SPI_RAW_RW_BUFF_LEN];
    uint8_t rbuf[ASTP_SPI_RAW_RW_BUFF_LEN];
} mctp_spi_raw_rw_t;

/* Command line structure */
typedef struct mctp_cmdline_args_ {
    char                    name[10];
    int                     device_id;
    bool                    verbose;
    mctp_binding_ids_t      binding_type;
    mctp_spi_cmd_mode_t     cmd_mode;
    uint8_t                 bind_info[MCTP_PVT_BIND_BUFF_SIZE];
    int                     bind_len;
    int                     read;
    int                     write;
    uint8_t                 tx_data[MCTP_WRITE_DATA_BUFF_SIZE];
    int                     tx_len;
    uint8_t                 rx_data[MCTP_WRITE_DATA_BUFF_SIZE];
    uint16_t                target_bdf;
    int                     use_socket;
    int                     mode;
    int                     list_device_op;
    mctp_cmdline_ops_t      ops;
    mctp_eid_t              dest_eid;
    mctp_spi_iana_vdm_ops_t iana_vdm_ops;
    mctp_spi_vdm_ops_t      vdm_ops;
} mctp_spi_cmdline_args_t;

/* Function prototypes */
void mctp_ctrld_help(FILE *stream, int exit_code, const char *i2cd_name);

/* MCTP SPI Test APIs */
int mctp_spi_set_endpoint_uuid(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_set_boot_complete(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_heartbeat_send(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_heartbeat_enable(mctp_spi_cmdline_args_t *cmd, mctp_spi_hrtb_ops_t enable);
int mctp_spi_query_boot_status(mctp_spi_cmdline_args_t *cmd);

int mctp_spi_init_test(mctp_spi_cmdline_args_t *cmd);
int mctp_spi_deinit_test(void);
void mctp_spi_test_cmd(mctp_spi_cmdline_args_t *cmd);

#endif /* __MCTP_CMDLINE_H */
