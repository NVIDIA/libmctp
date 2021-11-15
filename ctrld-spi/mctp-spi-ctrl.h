#ifndef __MCTP_SPI_CTRL_H__
#define __MCTP_SPI_CTRL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "libmctp.h"

#define MCTP_PAYLOAD_SIZE   64

#define MCTP_HEADER_SIZE    4
#define SPI_HEADER_SIZE     4

#define SPI_TX_BUFF_SIZE                                                     \
	((MCTP_HEADER_SIZE) + (SPI_HEADER_SIZE) + (MCTP_PAYLOAD_SIZE))

#define SPI_GPIO_INPUT_POLL     250

/* Poll timeout */
#define MCTP_SPI_POLL_TIMEOUT   1000

struct mctp_binding_spi {
	struct mctp_binding     binding;
	int                     in_fd;
	int                     out_fd;
    int                     fd;
    int                     gpio_fd;
    int                     gpio_poll_num;
    int                     controller;
	unsigned long           bus_id;

	/* receive buffer */
	uint8_t                 rxbuf[1024];
	struct mctp_pktbuf      *rx_pkt;

	/* temporary transmit buffer */
	uint8_t                 txbuf[SPI_TX_BUFF_SIZE];
};

struct mctp_spi_pkt_private {
	int fd;
    int gpio_lookup;
    uint8_t controller;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif
#endif /*__MCTP_SPI_CTRL_H__ */
