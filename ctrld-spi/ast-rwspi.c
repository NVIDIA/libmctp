/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <asm/ioctl.h>
#include <linux/spi/spidev.h>

#include "mctp-ctrl-log.h"
#include "ast-rwspi.h"

static uint8_t     spiBPW   = 8;
static uint8_t     spiMode  = 0;
static uint16_t    spiDelay = 0;
static uint32_t    spiSpeed = 1000000;
static int         spiFd;

static void ast_spi_print_tx_rx(unsigned char *txdata, int txlen,
                        unsigned char *rxdata, int rxlen)
{
    int i = 0;

    MCTP_CTRL_TRACE("------------------------------------------------------\n");
    MCTP_CTRL_TRACE("Tx [%d]: \t", (txlen - rxlen));
    for (i = 0; i < (txlen - rxlen); i++) {
        MCTP_CTRL_TRACE("0x%x ", txdata[i]);
    }
    MCTP_CTRL_TRACE("\n");
    MCTP_CTRL_TRACE("Rx [%d]: \t", rxlen);
    for (i = 0; i < rxlen; i++) {
        MCTP_CTRL_TRACE("0x%x ", rxdata[i]);
    }
    MCTP_CTRL_TRACE("\n------------------------------------------------------\n");
}

int ast_spi_xfer(int fd, unsigned char *txdata, int txlen,
                        unsigned char *rxdata, int rxlen, bool deassert)
{
    struct spi_ioc_transfer spi={0};
    int ret = 0;

    if (spiMode & SPI_3WIRE) {
        // send
        spi.tx_buf = (unsigned long)txdata;
        spi.rx_buf = (unsigned long)NULL; // single wire, this must be null
        spi.len = txlen;
        spi.speed_hz = spiSpeed;
        spi.bits_per_word = spiBPW;
        spi.cs_change = 0;
        spi.delay_usecs = spiDelay;

        ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
        if (ret < 0) {
            MCTP_CTRL_ERR("Cannot send message %s\n", strerror(errno));
            return ret;
        }

        // recv
        spi.tx_buf = (unsigned long)NULL; // single wire recv, this must be null
        spi.rx_buf = (unsigned long)(rxdata);
        spi.len = rxlen;
        spi.speed_hz = spiSpeed;
        spi.bits_per_word = spiBPW;
        spi.cs_change = 0;
        spi.delay_usecs = spiDelay;

        ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
        if (ret < 0) {
            MCTP_CTRL_ERR("Cannot recv message: %s\n", strerror(errno));
            return ret;
        }
    } else {

        if ((txlen - rxlen) > 0) {
            spi.tx_buf        = (unsigned long)txdata;
        } else {
            spi.tx_buf        = (unsigned long)NULL;
        }

        spi.rx_buf        = (unsigned long)rxdata;
        spi.len           = txlen;
        spi.delay_usecs   = rxlen;
        spi.cs_change     = deassert;
        spi.speed_hz      = spiSpeed;
        spi.bits_per_word = spiBPW;

        ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
        if (ret < 0) {
            MCTP_CTRL_ERR( "SPI Xfer data failure: %s\n", strerror(errno));
            return ret;
        }

        ast_spi_print_tx_rx(txdata, txlen, rxdata, rxlen);
    }
    
    return ret;
}

int ast_spi_set_speed(int fd, int speed)
{
    int ret = 0;
    
    ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    if (ret < 0)  {
        MCTP_CTRL_ERR( "SPI WR Speed Change failure: %s\n", strerror(errno)) ;
        ret = -1;
    }

    ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
    if (ret < 0)  {
        MCTP_CTRL_ERR( "SPI RD Speed Change failure: %s\n", strerror(errno)) ;
        ret = -1;
    }
    else 
        spiSpeed= speed;

    return ret;
  
}

int ast_spi_set_bpw(int fd, int bpw)
{
    int ret = 0;
    
    ret = ioctl (fd, SPI_IOC_WR_MODE, &bpw);
    if (ret < 0) {
        MCTP_CTRL_ERR( "SPI WR BitPerWord Change failure: %s\n", strerror(errno));
        ret = -1;
    }
    ret = ioctl (fd, SPI_IOC_RD_MODE, &bpw);
    if (ret < 0) {
        MCTP_CTRL_ERR( "SPI RD BitPerWord Change failure: %s\n", strerror(errno));
        ret = -1;
    }

    if (ret == 0)
        spiBPW = bpw;

    return ret;
}

int ast_spi_set_mode(int fd, int mode)
{
    int ret = 0;
    int tryMode = spiMode;
    
    tryMode = spiMode | mode & 0x07;
    ret= ioctl(fd, SPI_IOC_WR_MODE, &tryMode);
    if (ret < 0) {
        MCTP_CTRL_ERR( "SPI WR Mode Change failure: %s\n", strerror(errno));
        ret = -1;
    }
    ret= ioctl(fd, SPI_IOC_RD_MODE, &tryMode);
    if (ret < 0) {
        MCTP_CTRL_ERR( "SPI RD Mode Change failure: %s\n", strerror(errno));
        ret = -1;
    }

    if (ret == 0)
        spiMode = tryMode;

    return ret;
}

int ast_spi_set_udelay(int usecond)
{   
    spiDelay = usecond;

    return 0;
}

int ast_spi_open(int dev, int channel, int mode, int disableCS, int singleMode)
{
    int     fd = 0, ret = 0;
    char    spiDev[32]  = "";

    snprintf(spiDev, 31, "/dev/spidev%d.%d", dev, channel);
    if ((fd = open(spiDev, O_RDWR)) < 0) {
        MCTP_CTRL_ERR( "Unable to open SPI device: %s\n", strerror(errno));
        return -1;
    }

    spiFd = fd;
    spiMode = mode;
    if (singleMode)
        spiMode  |= SPI_3WIRE;

    if (disableCS) 
        spiMode  |= SPI_NO_CS;

    return fd;
}

int ast_spi_close(int fd)
{
    if (close(fd) < 0) {  
        MCTP_CTRL_ERR("Unable to close SPI device %s\n", strerror(errno));
        return -1;
    }
   
    return 0;
}
