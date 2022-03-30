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

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"

#define MCTP_PAYLOAD_SIZE   64

#define MCTP_HEADER_SIZE    4
#define SPI_HEADER_SIZE     4

#define SPI_TX_BUFF_SIZE                                                     \
	((MCTP_HEADER_SIZE) + (SPI_HEADER_SIZE) + (MCTP_PAYLOAD_SIZE))

#define SPI_GPIO_INPUT_POLL     250

/* Poll timeout */
#define MCTP_SPI_POLL_TIMEOUT   1000

/* Delay for sending suqsequent commands */
#define MCTP_SPI_CMD_DELAY_USECS        10000

/* Milli seconds to micro seconds */
#define MCTP_SPI_MSECS_TO_USECS_UNIT    1000

/* SPI Response interrupt timeout */
#define MCTP_SPI_RESP_INTR_TIMEOUT_MSECS    100

/* Maximum wait time for the response interrupt */
#define MCTP_SPI_RESP_MAX_TIMEOUT_SECS     5

/* Number of request retries as per MCTP-over-SPI spec */
#define MCTP_SPI_REQ_RETRIES    3

/* Delay for retrying send procedure */
#define MCTP_SPI_SEND_DELAY_NSECS        100

/* MCTP message interrupt macros */
#define MCTP_RX_MSG_INTR        1
#define MCTP_RX_MSG_INTR_RST    0

/* GPIO interrupt poll macros */
#define SPB_GPIO_INTR_NUM       986
#define SPB_GPIO_INTR_OCCURED   1
#define SPB_GPIO_INTR_RESET     0
#define SPB_GPIO_INTR_STOP      0x1000

/* Enable thread to send boot complete and  periodic heartbeat */
#define MCTP_SPI_SPB_INTERFACE          1

/* Enable this only when user want to send via sockets */
#define MCTP_SPI_USR_SOCKET_ENABLE      1

/* Delay for Heartbeat signal */
#define MCTP_SPI_HEARTBEAT_DELAY_SECS   30

/* Stay Idle delay */
#define MCTP_SPI_STAY_IDLE_DELAY_SECS   30

/* SPB AP init Threshold limit */
#define SPB_AP_INIT_THRESHOLD           3

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

/* Function prototypes */
int mctp_spi_keepalive_event (mctp_ctrl_t *ctrl, mctp_spi_cmdline_args_t *cmdline);
int mctp_load_spi_driver(void);

#ifdef __cplusplus
}
#endif
#endif /*__MCTP_SPI_CTRL_H__ */
