/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef _ASTSPI_H
#define _ASTSPI_H

#include <stdbool.h>

#define SYSFS_GPIO_DIR "/sys/class/gpio"
#define POLL_TIMEOUT (3 * 1000) /* 3 seconds */
#define MAX_BUF 64

#define MCTP_SPI_CMD_DELAY_USECS 100
#
#define SPI_GPIO_INPUT_POLL 250

/* GPIO interrupt poll macros */
#define SPB_GPIO_INTR_NUM 986
#define SPB_GPIO_INTR_OCCURED 1
#define SPB_GPIO_INTR_RESET 0
#define SPB_GPIO_INTR_STOP 0x1000

enum ast_spi_intr_status {
	AST_SPI_INTR_NONE,
	AST_SPI_INTR_RECVD,
};

#ifdef __cplusplus
extern "C" {
#endif

// Parameters:
//      dev:      0 or 1.  (0->/dev/spidev0, 1 -> /dev/spidev1)
//      channel:  0 or 1.  (0->channel 0, 1 -> channel 1)
//      mode   :  SPI_MODE_0, SPI_MODE_1, SPI_MODE_2, SPI_MODE_3
//      disCS  :  1 (Add SPI_NO_CS flag, i.e assert, deassert flag in library)
//      single :  1 (Add SPI_3WIRE flag, i.e. single mode)
// Return:
//      spi device file handle
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

/* Function prototypes */
int ast_spi_gpio_poll_thread(void *data);
int ast_spi_gpio_intr_init(void);
enum ast_spi_intr_status ast_spi_gpio_intr_check(int gpio_fd, int timeout_ms,
						 bool polling);
int ast_spi_gpio_fd_close(int gpio_fd);
int ast_spi_gpio_intr_drain(int gpio_fd);
#ifdef __cplusplus
}
#endif

#endif /* _ASTSPI_H */
