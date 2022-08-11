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
#include <time.h>
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
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "ctrld/mctp-ctrl.h"
#include "ctrld/mctp-socket.h"

#include "mctp-ctrl-log.h"
#include "mctp-spi-ctrl.h"
#include "mctp-spi-ctrl-cmdline.h"
#include "mctp-spi-ctrl-cmds.h"

#include "vdm/nvidia/libmctp-vdm-cmds.h"
#include "vdm/nvidia/mctp-vdm-commands.h"

#define MCTP_NULL_ENDPOINT              0

int mctp_spi_set_endpoint_id(mctp_spi_cmdline_args_t *cmd)
{
    return 0;
}

int mctp_spi_get_endpoint_id(mctp_spi_cmdline_args_t *cmd)
{
    return 0;
}

int mctp_spi_get_endpoint_uuid(mctp_spi_cmdline_args_t *cmd)
{
    return 0;
}

int mctp_spi_get_version_support(mctp_spi_cmdline_args_t *cmd)
{
    return 0;
}


int mctp_spi_get_message_type(mctp_spi_cmdline_args_t *cmd)
{
    /* will implement it */
    return 0;
}

/* Nvidia IANA specific functions */
int mctp_spi_set_endpoint_uuid(mctp_spi_cmdline_args_t *cmd)
{
    /* will implement it */
    return 0;
}

int mctp_spi_keepalive_event (mctp_ctrl_t *ctrl)
{
    size_t resp_msg_len = 0;
    int    rc = 0;

    MCTP_CTRL_INFO("%s: Send 'Boot complete v2' message\n", __func__);
    rc = boot_complete_v2(ctrl->sock, MCTP_NULL_ENDPOINT, 0, 0);

    MCTP_ASSERT_RET(rc == 0, MCTP_CMD_FAILED,
	    "Failed to send 'Boot complete' message\n");

    /* Give some delay before sending next command */
    usleep(MCTP_SPI_CMD_DELAY_USECS);

    MCTP_CTRL_INFO("%s: Send 'Enable Heartbeat' message\n", __func__);
    rc = set_heartbeat_enable(ctrl->sock, MCTP_NULL_ENDPOINT, MCTP_SPI_HB_ENABLE_CMD);

    MCTP_ASSERT_RET(rc == 0, MCTP_CMD_FAILED, "Failed MCTP_SPI_HEARTBEAT_ENABLE\n");

    /* Give some delay before sending next command */
    usleep(MCTP_SPI_CMD_DELAY_USECS);

    while (1) {

        MCTP_CTRL_DEBUG("%s: Send 'Heartbeat' message\n", __func__);
        rc = heartbeat(ctrl->sock, MCTP_NULL_ENDPOINT);

	MCTP_ASSERT_RET(rc == 0, MCTP_CMD_FAILED, " Failed MCTP_SPI_HEARTBEAT_SEND\n");

        /*
         * sleep for 10 seconds (it should be less than 60 seconds as per Galcier
         * firmware
         */
         sleep(MCTP_SPI_HEARTBEAT_DELAY_SECS);
    }

    return MCTP_CMD_SUCCESS;
}

void mctp_spi_test_cmd(mctp_ctrl_t *ctrl, mctp_spi_cmdline_args_t *cmd)
{
    int                     rc = 0;
    mctp_spi_iana_vdm_ops_t ops = cmd->vdm_ops;
    int                     status = 0;

    /* Check for Raw Read/write access */
    if (cmd->cmd_mode) {
        MCTP_CTRL_INFO("%s: MCTP base command code: %d\n", __func__, cmd->cmd_mode);

        switch(cmd->cmd_mode) {

            case MCTP_SPI_SET_ENDPOINT_ID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_SET_ENDPOINT_ID\n", __func__);
                rc = mctp_spi_set_endpoint_id(cmd);
                if (rc != MCTP_REQUESTER_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_SET_ENDPOINT_ID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_ENDPOINT_ID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_ID\n", __func__);
                rc = mctp_spi_get_endpoint_id(cmd);
                if (rc != MCTP_REQUESTER_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_ENDPOINT_ID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_ENDPOINT_UUID:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_ENDPOINT_UUID\n", __func__);
                rc = mctp_spi_get_endpoint_uuid(cmd);
                if (rc != MCTP_REQUESTER_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_ENDPOINT_UUID\n", __func__);
                }

                break;

            case MCTP_SPI_GET_VERSION:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_VERSION\n", __func__);
                rc = mctp_spi_get_version_support(cmd);
                if (rc != MCTP_REQUESTER_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SPI_GET_VERSION\n", __func__);
                }

                break;

            case MCTP_SPI_GET_MESSAGE_TYPE:
                MCTP_CTRL_DEBUG("%s: MCTP_SPI_GET_MESSAGE_TYPE\n", __func__);
                rc = mctp_spi_get_message_type(cmd);
                if (rc != MCTP_REQUESTER_SUCCESS) {
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
            if (rc != MCTP_REQUESTER_SUCCESS ) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_ENDPOINT_UUID\n", __func__);
            }

            break;

        case MCTP_SPI_BOOT_COMPLETE:

            MCTP_CTRL_DEBUG("%s: MCTP_SPI_BOOT_COMPLETE\n", __func__);
	    rc = boot_complete_v1(ctrl->sock, MCTP_NULL_ENDPOINT);
            if (rc != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_BOOT_COMPLETE\n", __func__);
            }

            break;

        case MCTP_SPI_HEARTBEAT_SEND:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_SEND\n", __func__);
            rc = heartbeat(ctrl->sock, MCTP_NULL_ENDPOINT);
            if (rc != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_SEND\n", __func__);
            }

            break;

        case MCTP_SPI_HEARTBEAT_ENABLE:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
            rc = set_heartbeat_enable(ctrl->sock, MCTP_NULL_ENDPOINT, MCTP_SPI_HB_ENABLE_CMD);
            if (rc != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_HEARTBEAT_ENABLE\n", __func__);
            }

            break;

        case MCTP_SPI_QUERY_BOOT_STATUS:
            MCTP_CTRL_DEBUG("%s: MCTP_SPI_QUERY_BOOT_STATUS\n", __func__);
            rc = query_boot_status(ctrl->sock, MCTP_NULL_ENDPOINT);
            if (rc != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Failed MCTP_SPI_QUERY_BOOT_STATUS\n", __func__);
            }

            break;

        default:
            MCTP_CTRL_DEBUG("%s: Invalid option\n", __func__);
            break;
    }

    return;
}
