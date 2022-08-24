/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __MCTP_SPI_CTRL_H__
#define __MCTP_SPI_CTRL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl-cmdline.h"

/* Define Max buffer size */
#define MCTP_RX_BUFFER_MAX_SIZE 64

/* Command size */
#define MCTP_SPI_LOAD_CMD_SIZE 128

#define MCTP_SPI_CMD_DELAY_USECS 10000

#define MCTP_SPI_HEARTBEAT_DELAY_SECS 30

struct mctp_spi_pkt_private {
	int fd;
	int gpio_lookup;
	uint8_t controller;
} __attribute__((packed));

uint16_t mctp_ctrl_get_target_bdf(mctp_cmdline_args_t *cmd);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SPI_CTRL_H__ */
