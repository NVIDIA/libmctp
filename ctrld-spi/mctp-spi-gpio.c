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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "mctp-spi-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-spi-gpio.h"
#include "mctp-ctrl-log.h"
#include "glacier-spb-ap.h"

volatile unsigned int *g_gpio_intr = NULL;

extern volatile int message_available;
extern SpbApStatus spb_ap_on_interrupt(int value);

static int g_gpio_fd = -1;

/****************************************************************
 * gpio_export
 ****************************************************************/
static int gpio_export(unsigned int gpio)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];
 
	fd = open(SYSFS_GPIO_DIR "/export", O_WRONLY);
	if (fd < 0) {
		perror("gpio/export");
		return fd;
	}
 
	len = snprintf(buf, sizeof(buf), "%d", gpio);
	write(fd, buf, len);
	close(fd);
 
	return 0;
}

/****************************************************************
 * gpio_unexport
 ****************************************************************/
static int gpio_unexport(unsigned int gpio)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];
 
	fd = open(SYSFS_GPIO_DIR "/unexport", O_WRONLY);
	if (fd < 0) {
		perror("gpio/export");
		return fd;
	}
 
	len = snprintf(buf, sizeof(buf), "%d", gpio);
	write(fd, buf, len);
	close(fd);
	return 0;
}

/****************************************************************
 * gpio_set_dir
 ****************************************************************/
static int gpio_set_dir(unsigned int gpio, unsigned int out_flag)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];
 
	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR  "/gpio%d/direction", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/direction");
		return fd;
	}
 
	if (out_flag)
		write(fd, "out", 4);
	else
		write(fd, "in", 3);
 
	close(fd);
	return 0;
}

/****************************************************************
 * gpio_set_value
 ****************************************************************/
static int gpio_set_value(unsigned int gpio, unsigned int value)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];
 
	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/set-value");
		return fd;
	}
 
	if (value)
		write(fd, "1", 2);
	else
		write(fd, "0", 2);
 
	close(fd);
	return 0;
}

/****************************************************************
 * gpio_set_edge
 ****************************************************************/

static int gpio_set_edge(unsigned int gpio, char *edge)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];

	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/edge", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/set-edge");
		return fd;
	}
 
	write(fd, edge, strlen(edge) + 1); 
	close(fd);
	return 0;
}

/****************************************************************
 * gpio_fd_open
 ****************************************************************/

static int gpio_fd_open(unsigned int gpio)
{
	int fd = 0, len = 0;
	char buf[MAX_BUF];

	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);
 
	fd = open(buf, O_RDONLY | O_NONBLOCK );
	if (fd < 0) {
		MCTP_CTRL_ERR("GPIO fd_open error\n");
	}
	return fd;
}

/****************************************************************
 * gpio_fd_close
 ****************************************************************/

int gpio_fd_close(void)
{

	/* Free Global GPIO interrupt pointer */
	free(g_gpio_intr);

	return close(g_gpio_fd);
}

/****************************************************************
 * GPIO Interrupt init
 ****************************************************************/
int gpio_intr_init(void)
{
    int             gpio_fd = 0;
    unsigned int    gpio = 0;

    gpio = SPB_GPIO_INTR_NUM;

    /* Set GPIO params */
    gpio_export(gpio);
    gpio_set_dir(gpio, 0);
    gpio_set_edge(gpio, "falling");
    gpio_fd = gpio_fd_open(gpio);

    /* Update global fd */
    g_gpio_fd = gpio_fd;

    /* Alloc memory for global pointer */
    g_gpio_intr = (uint32_t*) malloc(sizeof(uint32_t));

    return gpio_fd;
}

/****************************************************************
 * GPIO Interrupt check
 ****************************************************************/
int gpio_intr_check(void)
{
    int             nfds = 1;
    struct pollfd   fdset[1];
    char            *buf[MAX_BUF];
    int             gpio_fd = 0, timeout = 0, rc = 0;
    int             len = 0;

    /* Reset the interrupt */
    *g_gpio_intr = SPB_GPIO_INTR_RESET;

    memset((void*)fdset, 0, sizeof(fdset));

    fdset[0].fd = g_gpio_fd;
    fdset[0].events = POLLPRI;
    rc = poll(fdset, nfds, timeout);

    if (rc < 0) {
        MCTP_CTRL_ERR("%s: Failed[rc=%d]: GPIO[%d] Interrupt polling failed\n",
                                        __func__, rc, SPB_GPIO_INTR_NUM);
        return -1;
    }

    if (fdset[0].revents & POLLPRI) {
        lseek(fdset[0].fd, 0, SEEK_SET);
        len = read(fdset[0].fd, buf, MAX_BUF);
        *g_gpio_intr = SPB_GPIO_INTR_OCCURED;

        if (spb_ap_on_interrupt(1) == SPB_AP_MESSAGE_AVAILABLE) {
            MCTP_CTRL_DEBUG("%s: MCTP Rx Message available \n", __func__);
            message_available = MCTP_RX_MSG_INTR;
            return MCTP_RX_MSG_INTR;
        }
    }

    return 0;
}

/****************************************************************
 * GPIO polling thread
 ****************************************************************/
int gpio_poll_thread(void *data)
{
	struct pollfd   fdset[1];
	int             nfds = 1;
	int             gpio_fd = 0, timeout = 0, rc = 0;
	char            *buf[MAX_BUF];
	unsigned int    gpio = 0;
	int             len = 0;

	gpio_fd = gpio_intr_init();

	timeout = POLL_TIMEOUT;
 
	while (1) {

		memset((void*)fdset, 0, sizeof(fdset));

		fdset[0].fd = gpio_fd;
		fdset[0].events = POLLPRI;

		rc = poll(fdset, nfds, timeout);      

		if (rc < 0) {
            MCTP_CTRL_ERR("\npoll() failed!\n");
            return -1;
		}
 
        /* check if thread need to be stopped */
        if (*g_gpio_intr == SPB_GPIO_INTR_STOP) {
            MCTP_CTRL_DEBUG("Exiting %s \n", __func__);
            break;
        }

		if (fdset[0].revents & POLLPRI) {
			lseek(fdset[0].fd, 0, SEEK_SET);
			len = read(fdset[0].fd, buf, MAX_BUF);
            *g_gpio_intr = SPB_GPIO_INTR_OCCURED;

            if (spb_ap_on_interrupt(1) == SPB_AP_MESSAGE_AVAILABLE) {
                MCTP_CTRL_DEBUG("%s: MCTP Rx Message available \n", __func__);
                message_available = MCTP_RX_MSG_INTR;
            }
		}
	}

	gpio_fd_close();
	return 0;
}


