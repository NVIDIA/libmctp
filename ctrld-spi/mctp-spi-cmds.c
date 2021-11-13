/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-astpcie.h"

#include "libmctp-cmds.h"

#include "mctp-ctrl-log.h"
#include "mctp-ctrl.h"
#include "mctp-spi-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "ast-rwspi.h"
#include "glacier-spb-ap.h"

/* MCTP SPI Medium header params */
#define MCTP_SPI_TARGET_COMMAND_CODE    0x02
#define MCTP_SPI_PARAM1_RESVD           0x00
#define MCTP_SPI_PARAM2_RESVD           0x00
#define MCTP_SPI_PARAM3_RESVD           0x00

#define MCTP_SPI_HDR_LEN                4

/* MCTP Transport Header params */
#define MCTP_TRANSPORT_HDR_VER          0x01
#define MCTP_DEST_ENDPOINT              0x00
#define MCTP_SOURCE_ENDPOINT            0x08
#define MCTP_TRANSPORT_MESSAGE_TAG      0xc8

#define MCTP_TRANSPORT_HDR_LEN          4

#define AST_GPIO_AP_EROT_REQ_OUT        984   /* AB15: GPIOV0 */
#define AST_GPIO_EROT_AP_GNT_IN         985   /* AF14: GPIOV1 */
#define AST_GPIO_SP0_AP_INTR_N_IN       986   /* AD14: GPIOV2 */

#define AST_GPIO_POLL_LOW               0
#define AST_GPIO_POLL_HIGH              1

#define AST_GPIO_POLL_TIMEOUT           1000
#define AST_GPIO_PORT_OFFSET            8
#define AST_BASE_GPIO_ADDR              816

/* MCTP-over-SPI Header size */
#define MCTP_SPI_MEDIUM_HDR_LEN         4
#define MCTP_SPI_TRANSPORT_HDR_LEN      4

/* MCTP-over-SPI offsets */
#define MCTP_SPI_TARGET_MSG_CODE_OFFSET     0
#define MCTP_SPI_MSG_SIZE_PARAM0_OFFSET     1
#define MCTP_SPI_RSVD_PARAM1_OFFSET         2
#define MCTP_SPI_RSVD_PARAM2_OFFSET         3
#define MCTP_SPI_HDR_VERSION_OFFSET         4
#define MCTP_SPI_DEST_EID_OFFSET            5
#define MCTP_SPI_SRC_EID_OFFSET             6
#define MCTP_SPI_SOM_EOM_OFFSET             7
#define MCTP_SPI_IC_MSG_TYPE_OFFSET         8
#define MCTP_SPI_MSG_HDR_DATA_OFFSET        9

/* Static variables */
static int      spi_fd = -1;
volatile int    message_available = MCTP_RX_MSG_INTR_RST;
static int      g_gpio_grant_fd = -1;
static int      g_gpio_intr_fd = -1;

/* Static function prototypes */
static int      ast_gpio_read_interrupt_pin(void);
static int      ast_spi_on_mode_change(bool quad, uint8_t waitCycles);
static int      mctp_spi_xfer(int sendLen, uint8_t* sbuf,
                         int recvLen, uint8_t* rbuf,
                         bool deassert);

/* External variables */
extern volatile uint32_t *g_gpio_intr;


static uint8_t g_spi_hdr_default[MCTP_SPI_HDR_LEN] = {
    MCTP_SPI_TARGET_COMMAND_CODE,
    MCTP_SPI_PARAM1_RESVD,
    MCTP_SPI_PARAM2_RESVD,
    MCTP_SPI_PARAM3_RESVD
};


static uint8_t g_mctp_hdr_default[MCTP_TRANSPORT_HDR_LEN] = {
    MCTP_TRANSPORT_HDR_VER,
    MCTP_DEST_ENDPOINT,
    MCTP_SOURCE_ENDPOINT,
    MCTP_TRANSPORT_MESSAGE_TAG   
};

static SpbAp nvda_spb_ap = {
    .debug_level             = 0,
    .use_interrupt           = 1,
    .message_available       = &message_available,
    .gpio_read_interrupt_pin = ast_gpio_read_interrupt_pin,
    .on_mode_change          = ast_spi_on_mode_change,
    .spi_xfer                = mctp_spi_xfer,
};

/* Set Endpoint ID test packet */

/* -----------  MCTP Base commands start ------------ */
static uint8_t mctp_spi_set_endpoint_id_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, 0x80, MCTP_SPI_SET_ENDPOINT_ID, 0x00, 0x2b
};

static uint8_t mctp_spi_get_endpoint_id_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, 0x80, MCTP_SPI_GET_ENDPOINT_ID, 0x00, 0x2b
};

static uint8_t mctp_spi_get_endpoint_uuid_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, 0x80, MCTP_SPI_GET_ENDPOINT_UUID
};

static uint8_t mctp_spi_get_mctp_version_support_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, 0x80, MCTP_SPI_GET_VERSION, 0x00
};

static uint8_t mctp_spi_get_mctp_message_type_support_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, 0x80, MCTP_SPI_GET_MESSAGE_TYPE
};
/* -----------  MCTP Base commands end ------------ */


/* -----------  Nvidia IANA VDM commands start ------------ */

/* Set Endpoint UUID test packet */
static uint8_t mctp_spi_set_ep_uuid_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x09, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x00, MCTP_SPI_SET_ENDPOINT_UUID, 0x01, 0x00, 0x18
};

/* Set Endpoint UUID test packet */
static uint8_t mctp_spi_set_boot_complete_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x0d, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x7f, 0x47, 0x16, 0x00, 0x00, 0x80, 0x01, MCTP_SPI_BOOT_COMPLETE, 0x1
};

/* Heartbeat Enable test packet */
static uint8_t mctp_spi_heartbeat_enable_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x0e, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x7f, 0x47, 0x16, 0x00, 0x00, 0x80, 0x01, MCTP_SPI_HEARTBEAT_ENABLE, 0x1, MCTP_SPI_HB_ENABLE_CMD
};

/* Heartbeat Disable test packet */
static uint8_t mctp_spi_heartbeat_disable_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x0e, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x7f, 0x47, 0x16, 0x00, 0x00, 0x80, 0x01, MCTP_SPI_HEARTBEAT_ENABLE, 0x1, MCTP_SPI_HB_DISABLE_CMD
};

/* Heartbeat send test packet */
static uint8_t mctp_spi_heartbeat_send_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x0d, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x7f, 0x47, 0x16, 0x00, 0x00, 0x80, 0x01, MCTP_SPI_HEARTBEAT_SEND, 0x1
};

/* Query boot status test packet */
static uint8_t mctp_spi_query_boot_status_cmd[] = {
    /* SPI Medium Header */
     SPB_MCTP, 0x0d, 0x00, 0x00,
    /* MCTP transport header */
     0x01, 0x00, 0x09, 0xC8,
    /* MCTP pkt payload */
    0x7f, 0x47, 0x16, 0x00, 0x00, 0x80, 0x01, MCTP_SPI_QUERY_BOOT_STATUS, 0x1
};
/* -----------  Nvidia IANA VDM commands end ------------ */


void mctp_spi_print_msg(const char *str, uint8_t *msg, int len)
{
    int count = 0;
    int payload_start = (MCTP_SPI_MEDIUM_HDR_LEN + MCTP_SPI_TRANSPORT_HDR_LEN) - 1;

    /* Check length is valid or not */
    if (len < payload_start) {
        MCTP_CTRL_ERR("%s: Invalid Msg length %d\n", __func__, len);
        return;
    }

    MCTP_CTRL_DEBUG("\n---------------- %s [%d] ---------------- \n", str, len+1);

    MCTP_CTRL_DEBUG("SPI Medium header\t: ");
    for (int i = 0; i < MCTP_SPI_MEDIUM_HDR_LEN; i++) {
        MCTP_CTRL_DEBUG(" 0x%x ", msg[count++]);
    }

    MCTP_CTRL_DEBUG("\nMCTP Transport header\t: ");
    for (int i = 0; i < MCTP_SPI_TRANSPORT_HDR_LEN; i++) {
        MCTP_CTRL_DEBUG(" 0x%x ", msg[count++]);
    }

    MCTP_CTRL_DEBUG("\nMCTP Payload\t\t: ");
    for (int i = payload_start; i < len; i++) {
        MCTP_CTRL_DEBUG(" 0x%x ", msg[count++]);
    }

    MCTP_CTRL_DEBUG("\n----------------------------------------------------------\n");
}

static int ast_gpio_read_interrupt_pin()
{
    int rc;
    char buf[8];

    if (*g_gpio_intr) {
        MCTP_CTRL_DEBUG("%s: AST_GPIO_EROT_AP_GNT_IN event occured..\n", __func__);

        /* Clear the interrupt */
        *g_gpio_intr = SPB_GPIO_INTR_RESET;

        return AST_GPIO_POLL_HIGH;
    }

    return AST_GPIO_POLL_LOW;
}

static int ast_spi_on_mode_change(bool quad, uint8_t waitCycles)
{
    /*
     * Placeholder function to handle mode change here
     * (Eg: Quad/Dual etc...)
     */

    return 0;
}

static int mctp_spi_xfer(int sendLen, uint8_t* sbuf,
                         int recvLen, uint8_t* rbuf,
                         bool deassert)
{
    int status;

    // sbuf and rbuf must be the same size
    int len = sendLen + recvLen;
    uint8_t rbuf2[len];
    uint8_t sbuf2[len];

    memset(rbuf2, 0, len);
    memset(sbuf2, 0, len);

    memcpy(sbuf2, sbuf, sendLen);

    status = ast_spi_xfer(spi_fd, sbuf2, len, rbuf2, recvLen, deassert);

    // shift out send section
    memcpy(rbuf, rbuf2, recvLen);

    return 0;
}

int mctp_check_spi_drv_exist(void)
{

    FILE *fp;
    char buff[1035];
 
    /* Open the command for reading. */
    fp = popen("lsmod | grep fmc", "r");
    if (fp == NULL) {
        MCTP_CTRL_ERR("Failed to run command\n" );
        return -1;
    }
 
    /* Read the output a line at a time - output it. */
    while (fgets(buff, sizeof(buff), fp) != NULL) {
        MCTP_CTRL_DEBUG("Raw SPI driver exist: %s", buff);
        return 1;
    }
 
    /* close */
    pclose(fp);
 
    return 0;
}

int mctp_check_spi_flash_exist(void)
{

    FILE *fp;
    char buff[1035];
 
    /* Open the command for reading. */
    fp = popen("cat /proc/mtd | grep mtd0", "r");
    if (fp == NULL) {
        MCTP_CTRL_ERR("Failed to run command\n" );
        return -1;
    }
 
    /* Read the output a line at a time - output it. */
    while (fgets(buff, sizeof(buff), fp) != NULL) {
        MCTP_CTRL_DEBUG("Flash driver exist : %s", buff);
        return 1;
    }
 
    /* close */
    pclose(fp);
 
    return 0;
}


int mctp_load_spi_driver(void)
{
    char cmd[MCTP_SPI_LOAD_CMD_SIZE];
    int ret;

    /* Check Flash driver is loaded */
    ret = mctp_check_spi_flash_exist();
    if (ret > 0) {
        memset(cmd, '\0', MCTP_SPI_LOAD_CMD_SIZE);
        sprintf(cmd, "%s", MCTP_SPI_FLASH_DRIVER_UNLOAD_CMD);
        MCTP_CTRL_INFO("%s: Unloading Flash driver: %s\n", __func__, cmd);
        ret = system(cmd);
        if (ret > 0) {
            MCTP_CTRL_ERR("%s: Cannot open spi device\n", __func__);
            return MCTP_SPI_FAILURE;
        }
    } else {
        MCTP_CTRL_INFO("%s: Flash driver already unloaded: %d\n", __func__, ret);
    }

    /* Check Raw SPI driver is loaded */
    ret = mctp_check_spi_drv_exist();
    if (ret > 0) {
        MCTP_CTRL_INFO("%s: Raw SPI driver already loaded: %d\n", __func__, ret);
    } else {
        sleep(MCTP_SPI_LOAD_UNLOAD_DELAY);
        memset(cmd, '\0', MCTP_SPI_LOAD_CMD_SIZE);
        sprintf(cmd, "%s", MCTP_SPI_DRIVER_PATH);
        MCTP_CTRL_DEBUG("%s: Loading Raw SPI driver: %s\n", __func__, cmd);
        ret = system(cmd);
        MCTP_CTRL_INFO("%s: Loaded Raw SPI driver successfully: %d\n", __func__, ret);
        sleep(MCTP_SPI_LOAD_UNLOAD_DELAY);
    }
}

int mctp_spi_init(mctp_spi_cmdline_args_t *cmd)
{
    /* Initialize SPI before doing any ops */
    spi_fd = ast_spi_open(AST_MCTP_SPI_DEV_NUM,
                          AST_MCTP_SPI_CHANNEL_NUM, 0, 0, 0);
    if (spi_fd < 0) {
        MCTP_CTRL_ERR("%s: Cannot open spi device\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    /* Initialize SPB AP Library */
    if (spb_ap_initialize(&nvda_spb_ap) != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Cannot initialize SPB AP\n", __func__);
    }

    /* Give few milli-secs delay after init */
    usleep(MCTP_SPI_CMD_DELAY);

    return MCTP_SPI_SUCCESS;
}

int mctp_spi_deinit(void)
{
    /* Close the SPI dev */
    ast_spi_close(spi_fd);

    return MCTP_SPI_SUCCESS;
}

static inline int mctp_rx_wait_time(int threshold)
{
    int timeout = 0;

    do {
        timeout++;
        if (timeout > threshold) {
            MCTP_CTRL_ERR("%s: Timedout[%d sec] Response message not available\n",
                                            __func__, (threshold * MCTP_SPI_CMD_DELAY)/1000);
            return MCTP_SPI_FAILURE;
        }

        usleep(MCTP_SPI_CMD_DELAY);
    } while (message_available != MCTP_RX_MSG_INTR);

    /* Reset the status once consumed */
    message_available = MCTP_RX_MSG_INTR_RST;
    return MCTP_SPI_SUCCESS;
}

int mctp_spi_set_endpoint_id(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_set_endpoint_id_cmd)];

    mctp_spi_print_msg("MCTP_SPI_SET_ENDPOINT_ID",
                        mctp_spi_set_endpoint_id_cmd,
                        sizeof(mctp_spi_set_endpoint_id_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_set_endpoint_id_cmd),
                            mctp_spi_set_endpoint_id_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Set Endpoint ID msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_SET_ENDPOINT_ID request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_set_endpoint_id_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive Set EID complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_SET_ENDPOINT_ID",
                        recv_buff,
                        sizeof(mctp_spi_set_endpoint_id_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_SET_ENDPOINT_ID response successfully\n", __func__);
    return MCTP_SPI_SUCCESS;
}

int mctp_spi_get_endpoint_id(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_get_endpoint_id_cmd)];

    mctp_spi_print_msg("MCTP_SPI_GET_ENDPOINT_ID",
                        mctp_spi_get_endpoint_id_cmd,
                        sizeof(mctp_spi_get_endpoint_id_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_get_endpoint_id_cmd),
                            mctp_spi_get_endpoint_id_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Set Endpoint ID msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_GET_ENDPOINT_ID request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_get_endpoint_id_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive Set EID complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_GET_ENDPOINT_ID",
                        recv_buff,
                        sizeof(mctp_spi_get_endpoint_id_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_GET_ENDPOINT_ID response successfully\n");
    return MCTP_SPI_SUCCESS;
}

int mctp_spi_get_endpoint_uuid(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_get_endpoint_uuid_cmd)];

    mctp_spi_print_msg("MCTP_SPI_GET_ENDPOINT_UUID",
                        mctp_spi_get_endpoint_uuid_cmd,
                        sizeof(mctp_spi_get_endpoint_uuid_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_get_endpoint_uuid_cmd),
                            mctp_spi_get_endpoint_uuid_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Get Endpoint UUID msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_GET_ENDPOINT_UUID request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_get_endpoint_uuid_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive Get Endpoint UUID response msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_GET_ENDPOINT_UUID",
                        recv_buff,
                        sizeof(mctp_spi_get_endpoint_uuid_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_GET_ENDPOINT_UUID response successfully\n");
    return MCTP_SPI_SUCCESS;
}

int mctp_spi_get_version_support(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_get_mctp_version_support_cmd)];

    mctp_spi_print_msg("MCTP_SPI_GET_VERSION",
                        mctp_spi_get_mctp_version_support_cmd,
                        sizeof(mctp_spi_get_mctp_version_support_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_get_mctp_version_support_cmd),
                            mctp_spi_get_mctp_version_support_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send MCTP_SPI_GET_VERSION msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_GET_VERSION request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_get_mctp_version_support_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_GET_VERSION response msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_GET_VERSION",
                        recv_buff,
                        sizeof(mctp_spi_get_mctp_version_support_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_GET_VERSION response successfully\n");
    return MCTP_SPI_SUCCESS;
}


int mctp_spi_get_message_type(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_get_mctp_message_type_support_cmd)];

    mctp_spi_print_msg("MCTP_SPI_GET_MESSAGE_TYPE",
                        mctp_spi_get_mctp_message_type_support_cmd,
                        sizeof(mctp_spi_get_mctp_message_type_support_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_get_mctp_message_type_support_cmd),
                            mctp_spi_get_mctp_message_type_support_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send MCTP_SPI_GET_MESSAGE_TYPE msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_GET_MESSAGE_TYPE request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_get_mctp_message_type_support_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_GET_MESSAGE_TYPE response msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_GET_MESSAGE_TYPE",
                        recv_buff,
                        sizeof(mctp_spi_get_mctp_message_type_support_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_GET_MESSAGE_TYPE response successfully\n");
    return MCTP_SPI_SUCCESS;
}

/* Nvidia IANA specific functions */
int mctp_spi_set_endpoint_uuid(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_set_ep_uuid_cmd)];

    MCTP_CTRL_DEBUG("%s: \n", __func__);

    mctp_spi_print_msg("MCTP_SPI_SET_ENDPOINT_UUID",
                        mctp_spi_set_ep_uuid_cmd,
                        sizeof(mctp_spi_set_ep_uuid_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_set_ep_uuid_cmd),
                            mctp_spi_set_ep_uuid_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Boot complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_SET_ENDPOINT_UUID request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_set_ep_uuid_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive Boot complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_SET_ENDPOINT_UUID",
                        recv_buff,
                        sizeof(mctp_spi_set_ep_uuid_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_SET_ENDPOINT_UUID response successfully\n");
    return MCTP_SPI_SUCCESS;
}


int mctp_spi_set_boot_complete(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_set_boot_complete_cmd)];

    mctp_spi_print_msg("MCTP_SPI_BOOT_COMPLETE",
                        mctp_spi_set_boot_complete_cmd,
                        sizeof(mctp_spi_set_boot_complete_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_set_boot_complete_cmd),
                            mctp_spi_set_boot_complete_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Boot complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_BOOT_COMPLETE request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_set_boot_complete_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive Boot complete msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_BOOT_COMPLETE",
                        recv_buff,
                        sizeof(mctp_spi_set_boot_complete_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_BOOT_COMPLETE response successfully\n");
    return MCTP_SPI_SUCCESS;
}

int mctp_spi_heartbeat_send(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_heartbeat_send_cmd)];

    mctp_spi_print_msg("MCTP_SPI_HEARTBEAT_SEND",
                        mctp_spi_heartbeat_send_cmd,
                        sizeof(mctp_spi_heartbeat_send_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_heartbeat_send_cmd),
                            mctp_spi_heartbeat_send_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to send Heartbeat msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_HEARTBEAT_SEND request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_heartbeat_send_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_HEARTBEAT_SEND msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_HEARTBEAT_SEND",
                        recv_buff,
                        sizeof(mctp_spi_heartbeat_send_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_HEARTBEAT_SEND response successfully\n");

    return MCTP_SPI_SUCCESS;
}

int mctp_spi_heartbeat_enable(mctp_spi_cmdline_args_t *cmd, mctp_spi_hrtb_ops_t enable)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_heartbeat_enable_cmd) - 1];

    if (enable) {

        mctp_spi_print_msg("MCTP_SPI_HB_ENABLE_CMD",
                            mctp_spi_heartbeat_enable_cmd,
                            sizeof(mctp_spi_heartbeat_enable_cmd) - 1);

        status = spb_ap_send(sizeof(mctp_spi_heartbeat_enable_cmd),
                                mctp_spi_heartbeat_enable_cmd);
        if (status != SPB_AP_OK) {
            MCTP_CTRL_ERR("%s: Failed to Enable Heartbeat msg\n", __func__);
            return MCTP_SPI_FAILURE;
        }

        MCTP_CTRL_DEBUG("Sent MCTP_SPI_HEARTBEAT_ENABLE request successfully\n");

        /* Wait for the message interrupt */
        if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
            return MCTP_SPI_FAILURE;
        }
 
        /* Call the receive procedure */
        status = spb_ap_recv((sizeof(mctp_spi_heartbeat_enable_cmd) - 1),
                                recv_buff);
        if (status != SPB_AP_OK) {
            MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_HEARTBEAT_ENABLE msg\n", __func__);
            return MCTP_SPI_FAILURE;
        }
 
        mctp_spi_print_msg("MCTP_SPI_HEARTBEAT_ENABLE",
                            recv_buff,
                            (sizeof(mctp_spi_heartbeat_enable_cmd) - 1));
        MCTP_CTRL_DEBUG("Received MCTP_SPI_HEARTBEAT_ENABLE response successfully\n");
 
    } else {

        mctp_spi_print_msg("MCTP_SPI_HB_DISABLE_CMD",
                            mctp_spi_heartbeat_disable_cmd,
                            sizeof(mctp_spi_heartbeat_disable_cmd) - 1);

        status = spb_ap_send(sizeof(mctp_spi_heartbeat_disable_cmd) - 1,
                                mctp_spi_heartbeat_disable_cmd);
        if (status != SPB_AP_OK) {
            MCTP_CTRL_ERR("%s: Failed to Disable Heartbeat msg\n", __func__);
            return MCTP_SPI_FAILURE;
        }

        MCTP_CTRL_DEBUG("Sent MCTP_SPI_HEARTBEAT_DISABLE request successfully\n");

        /* Wait for the message interrupt */
        if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
            return MCTP_SPI_FAILURE;
        }
 
        /* Call the receive procedure */
        status = spb_ap_recv((sizeof(mctp_spi_heartbeat_disable_cmd) - 1),
                                recv_buff);
        if (status != SPB_AP_OK) {
            MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_HEARTBEAT_DISABLE msg\n", __func__);
            return MCTP_SPI_FAILURE;
        }
 
        mctp_spi_print_msg("MCTP_SPI_HEARTBEAT_DISABLE",
                            recv_buff,
                            (sizeof(mctp_spi_heartbeat_disable_cmd) - 1));
        MCTP_CTRL_DEBUG("Received MCTP_SPI_HEARTBEAT_DISABLE response successfully\n");
    }

    return MCTP_SPI_SUCCESS;
}

int mctp_spi_query_boot_status(mctp_spi_cmdline_args_t *cmd)
{
    SpbApStatus     status;
    uint8_t         recv_buff[sizeof(mctp_spi_query_boot_status_cmd)];

    mctp_spi_print_msg("MCTP_SPI_QUERY_BOOT_STATUS",
                        mctp_spi_query_boot_status_cmd,
                        sizeof(mctp_spi_query_boot_status_cmd) - 1);

    status = spb_ap_send(sizeof(mctp_spi_query_boot_status_cmd),
                            mctp_spi_query_boot_status_cmd);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to query boot status msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    MCTP_CTRL_DEBUG("Sent MCTP_SPI_QUERY_BOOT_STATUS request successfully\n");

    /* Wait for the message interrupt */
    if (mctp_rx_wait_time(MCTP_SPI_RX_TIMEOUT) != MCTP_SPI_SUCCESS) {
        return MCTP_SPI_FAILURE;
    }

    /* Call the receive procedure */
    status = spb_ap_recv(sizeof(mctp_spi_query_boot_status_cmd),
                            recv_buff);
    if (status != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed to receive MCTP_SPI_QUERY_BOOT_STATUS msg\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    mctp_spi_print_msg("MCTP_SPI_QUERY_BOOT_STATUS",
                        recv_buff,
                        sizeof(mctp_spi_query_boot_status_cmd));

    MCTP_CTRL_DEBUG("Received MCTP_SPI_QUERY_BOOT_STATUS response successfully\n");


    return MCTP_SPI_SUCCESS;
}

int mctp_spi_keepalive_event (mctp_ctrl_t *ctrl, mctp_spi_cmdline_args_t *cmdline)
{
    mctp_requester_rc_t     mctp_ret;
    size_t                  resp_msg_len;
    int                     rc;
    uint32_t                count = 0;

    if (ctrl->eid) {
        MCTP_CTRL_INFO("%s: EID: 0x%x\n", __func__, ctrl->eid);

        /*
         * Update source EIDs for Boot complete, Heartbeat enable/disable
         * and Heartbeat send command
         */
        mctp_spi_set_boot_complete_cmd[MCTP_SPI_SRC_EID_OFFSET] = ctrl->eid;
        mctp_spi_heartbeat_enable_cmd[MCTP_SPI_SRC_EID_OFFSET] = ctrl->eid;
        mctp_spi_heartbeat_disable_cmd[MCTP_SPI_SRC_EID_OFFSET] = ctrl->eid;
        mctp_spi_heartbeat_send_cmd[MCTP_SPI_SRC_EID_OFFSET] = ctrl->eid;
    }

    MCTP_CTRL_INFO("%s: Send 'Boot complete' message\n", __func__);
    rc = mctp_spi_set_boot_complete(cmdline);
    if (rc != MCTP_SPI_SUCCESS) {
        MCTP_CTRL_ERR("%s: Failed to send 'Boot complete' message\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    /* Give some delay before sending next command */
    usleep(MCTP_SPI_CMD_DELAY);

    MCTP_CTRL_INFO("%s: Send 'Enable Heartbeat' message\n", __func__);
    rc = mctp_spi_heartbeat_enable(cmdline, MCTP_SPI_HB_ENABLE_CMD);
    if (rc != MCTP_SPI_SUCCESS) {
        MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    /* Loop forever (Send Heartbeat signal to Glacier) */
    while (1) {

        /* Give some delay before sending next command */
        usleep(MCTP_SPI_CMD_DELAY);

        MCTP_CTRL_DEBUG("%s: Send 'Heartbeat'[%d] message\n", __func__, count++);
        rc = mctp_spi_heartbeat_send(cmdline);
        if (rc != MCTP_SPI_SUCCESS) {
            MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_SEND [%d]\n", __func__, count);
        }

        /*
         * sleep for 10 seconds (it should be less than 60 seconds as per Galcier
         * firmware
         */
         sleep(MCTP_SPI_HEARTBEAT_DELAY);

        if (*g_gpio_intr == SPB_GPIO_INTR_STOP) {
            MCTP_CTRL_DEBUG("%s: Done sending Heatbeat events [%d]\n", __func__, count++);
            break;
        }
    }

    MCTP_CTRL_INFO("%s: Send 'Enable Heartbeat' message\n", __func__);
    rc = mctp_spi_heartbeat_enable(cmdline, MCTP_SPI_HB_DISABLE_CMD);
    if (rc != SPB_AP_OK) {
        MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
        return MCTP_SPI_FAILURE;
    }

    return MCTP_CMD_SUCCESS;
}


void mctp_spi_test_cmd(mctp_spi_cmdline_args_t *cmd)
{
    int                     rc;
    mctp_spi_iana_vdm_ops_t ops = cmd->vdm_ops;
    int                     status;

    /* Check for Raw Read/write access */
    if (cmd->cmd_mode) {
        MCTP_CTRL_INFO("%s: MCTP base command code: %d\n", __func__, cmd->cmd_mode);

        switch(cmd->cmd_mode) {

            case MCTP_SPI_SET_ENDPOINT_ID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_SET_ENDPOINT_ID\n", __func__);
                rc = mctp_spi_set_endpoint_id(cmd);
                if (rc == MCTP_SPI_FAILURE) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_SET_ENDPOINT_ID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_ENDPOINT_ID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_ID\n", __func__);
                rc = mctp_spi_get_endpoint_id(cmd);
                if (rc == MCTP_SPI_FAILURE) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_ENDPOINT_ID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_ENDPOINT_UUID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_UUID\n", __func__);
                rc = mctp_spi_get_endpoint_uuid(cmd);
                if (rc == MCTP_SPI_FAILURE) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_ENDPOINT_UUID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_VERSION:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_VERSION\n", __func__);
                rc = mctp_spi_get_version_support(cmd);
                if (rc == MCTP_SPI_FAILURE) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_VERSION\n", __func__);
                }

                break;

            case MCTP_SPI_GET_MESSAGE_TYPE:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_MESSAGE_TYPE\n", __func__);
                rc = mctp_spi_get_message_type(cmd);
                if (rc == MCTP_SPI_FAILURE) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_MESSAGE_TYPE\n", __func__);
                }

                break;

            default:
                MCTP_CTRL_ERR("%s: Unsupported option\n", __func__);
                break;
        }

        return;
    }

    switch(ops) {
        case MCTP_SPI_SET_ENDPOINT_UUID:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_ENDPOINT_UUID\n", __func__);
            rc = mctp_spi_set_endpoint_uuid(cmd);
            if (rc == MCTP_SPI_FAILURE) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_ENDPOINT_UUID\n", __func__);
            }

            break;

        case MCTP_SPI_BOOT_COMPLETE:

            MCTP_CTRL_DEBUG("%s: MCTP_SPI_BOOT_COMPLETE\n", __func__);
            rc = mctp_spi_set_boot_complete(cmd);
            if (rc == MCTP_SPI_FAILURE) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_BOOT_COMPLETE\n", __func__);
            }
 
            break;

        case MCTP_SPI_HEARTBEAT_SEND:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_SEND\n", __func__);
            rc = mctp_spi_heartbeat_send(cmd);
            if (rc == MCTP_SPI_FAILURE) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_SEND\n", __func__);
            }
 
            break;

        case MCTP_SPI_HEARTBEAT_ENABLE:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
            rc = mctp_spi_heartbeat_enable(cmd, MCTP_SPI_HB_ENABLE_CMD);
            if (rc == MCTP_SPI_FAILURE) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
            }
 
            break;

        case MCTP_SPI_QUERY_BOOT_STATUS:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_QUERY_BOOT_STATUS\n", __func__);
            rc = mctp_spi_query_boot_status(cmd);
            if (rc == MCTP_SPI_FAILURE) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_QUERY_BOOT_STATUS\n", __func__);
            }

            break;

        default:
            MCTP_CTRL_DEBUG("%s: Invalid option\n", __func__);
            break;
    }

    return;
}
