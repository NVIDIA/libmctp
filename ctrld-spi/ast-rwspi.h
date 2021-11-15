/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __AST_RWSPI_H__
#define __AST_RWSPI_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Paramters:
//      dev:      0 or 1.  (0->/dev/spidev0, 1 -> /dev/spidev1)
//      channel:  0 or 1.  (0->channel 0, 1 -> channel 1) 
//      mode   :  SPI_MODE_0, SPI_MODE_1, SPI_MODE_2, SPI_MODE_3
//      disCS  :  1 (Add SPI_NO_CS flag, i.e assert, deassert flag in library)
//      single :  1 (Add SPI_3WIRE flag, i.e. single mode)
// Return:
//      spi device file handle
//
int ast_spi_open(int dev, int channel, int mode, int disCS, int single);
int ast_spi_close(int fd);
    
int ast_spi_xfer(int fd, unsigned char *txdata, int txlen,
                        unsigned char *rxdata, int rxlen, bool deassert);

// Paramters:
//      mode   :  SPI_MODE_0, SPI_MODE_1, SPI_MODE_2, SPI_MODE_3
int ast_spi_set_speed(int fd, int speed);
int ast_spi_set_bpw(int fd, int bpw);

int ast_spi_set_mode(int fd, int mode);
int ast_spi_set_udelay(int usecond);

#ifdef __cplusplus
}
#endif

#endif // __AST_RWSPI_H__
