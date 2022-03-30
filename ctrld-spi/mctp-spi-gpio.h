/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#ifndef __MCTP_SPI_GPIO_H__
#define __MCTP_SPI_GPIO_H__

 /****************************************************************
 * Constants
 ****************************************************************/
 
#define SYSFS_GPIO_DIR "/sys/class/gpio"
#define POLL_TIMEOUT (3 * 1000) /* 3 seconds */
#define MAX_BUF 64

/* Function prototypes */
int gpio_poll_thread(void *data);
int gpio_intr_init(void);
int gpio_intr_check(void);
int gpio_fd_close(void);

#endif /* __MCTP_SPI_GPIO_H__ */

