/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef _ASTSPI_H
#define _ASTSPI_H

#include <stdbool.h>
#ifdef MCTP_HAVE_CONFIG_H
#include "config.h"
#endif

#if USE_MOCKED_DRIVERS
#define SYSFS_GPIO_DIR "/sys/class/gpio_mock"
#else
#define SYSFS_GPIO_DIR "/sys/class/gpio"
#endif

#define POLL_TIMEOUT   (3 * 1000) /* 3 seconds */
#define MAX_BUF	       64

#define MCTP_SPI_CMD_DELAY_USECS 100
#
#define SPI_GPIO_INPUT_POLL 250

/* GPIO interrupt poll macros */

#define SPB_GPIO_INTR_OCCURED 1
#define SPB_GPIO_INTR_RESET   0
#define SPB_GPIO_INTR_STOP    0x1000

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
int ast_spi_gpio_intr_init(unsigned int gpio);
enum ast_spi_intr_status ast_spi_gpio_intr_check(int gpio_fd, int timeout_ms,
						 bool polling);
int ast_spi_gpio_fd_close(int gpio_fd);
int ast_spi_gpio_intr_drain(int gpio_fd);
#ifdef __cplusplus
}
#endif

#endif /* _ASTSPI_H */
