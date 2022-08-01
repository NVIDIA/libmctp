/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */
#ifndef __MCTP_SPI_CTRL_CMDS_H__
#define __MCTP_SPI_CTRL_CMDS_H__

#ifdef __cplusplus
extern "C" {
#endif

//#include "ctrld/mctp-ctrl-cmds.h"

/* MCTP SPI Control daemon delay default */
#define MCTP_SPI_CTRL_DELAY_DEFAULT                         10

/* System command buffer size */
#define MCTP_SYSTEM_CMD_BUFF_SIZE                           1035

#define MCTP_BINDING_SPI                                    0x06

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SPI_CTRL_CMDS_H__ */
