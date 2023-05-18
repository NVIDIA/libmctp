/*
 * Copyright (c) 2021, NVIDIA Corporation.  All Rights Reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and
 * proprietary rights in and to this software and related documentation.  Any
 * use, reproduction, disclosure or distribution of this software and related
 * documentation without an express license agreement from NVIDIA Corporation
 * is strictly prohibited.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <asm/ioctl.h>

#include <linux/spi/spidev.h>

#include "astspi.h"

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-astspi.h"
#include "libmctp-log.h"

#include "glacier-spb-ap.h"

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(x) "spi: " x
#endif

#define AST_GPIO_POLL_LOW 0
#define AST_GPIO_POLL_HIGH 1

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif

#define binding_to_spi(b) container_of(b, struct mctp_binding_spi, binding)

#define MCTP_COMMAND_CODE 0x02

/* Delay for sending suqsequent commands */
#define MCTP_SPI_LOAD_CMD_SIZE 128

/* MCTP message interrupt macros */
#define MCTP_RX_MSG_INTR 1
#define MCTP_RX_MSG_INTR_RST 0

/* MCTP SPI Control daemon delay default */
#define MCTP_SPI_CTRL_DELAY_DEFAULT 10

/* SPB AP init Threshold limit */
#define SPB_AP_INIT_THRESHOLD 3

/* System command buffer size */
#define MCTP_SYSTEM_CMD_BUFF_SIZE 1035

#define MCTP_SPI_DRIVER_PATH                                                   \
	"insmod /lib/modules/*/kernel/drivers/spi/fmc_spi.ko"

#define MCTP_SPI_LOAD_UNLOAD_DELAY_SECS 2

#define ERR_SPI_RX -1
#define ERR_SPI_RX_NO_DATA -2

struct mctp_binding_spi {
	struct mctp_binding binding;
	int spi_fd;
	int gpio_fd;
	int controller;

	unsigned long bus_id;

	/* receive buffer - with magics we can detect buffer overrun */
	uint32_t _magic1;
	uint8_t rxbuf[1024];
	uint32_t _magic2;
	struct mctp_pktbuf *rx_pkt;

	/* temporary transmit buffer */
	uint32_t _magic3;
	uint8_t txbuf[SPI_TX_BUFF_SIZE];
	uint32_t _magic4;

	SpbAp nvda_spb_ap;
};

static uint8_t spiBPW = 8;
static uint8_t spiMode = 0;
static uint16_t spiDelay = 0;
static uint32_t spiSpeed = 1000000;

static int g_gpio_intr;

static int spi_fd;
static void mctp_spi_hexdump(const char *prefix, int len, void *buf);
static int mctp_spi_xfer(int sendLen, uint8_t *sbuf, int recvLen, uint8_t *rbuf,
			 bool deassert);
static int ast_spi_xfer_3wire(int fd, unsigned char *txdata, int txlen,
			      unsigned char *rxdata, int rxlen, bool deassert);
static int ast_spi_xfer_normal(int fd, unsigned char *txdata, int txlen,
			       unsigned char *rxdata, int rxlen, bool deassert);
static int ast_spi_on_mode_change(bool quad, uint8_t waitCycles);
static void mctp_spi_verify_magics(struct mctp_binding_spi *spi);
static int mctp_spi_rx(struct mctp_binding_spi *spi);

struct mctp_spi_header {
	uint8_t command_code;
	uint8_t byte_count;
	uint8_t reserved[2];
};

static int ast_spi_on_mode_change(bool quad, uint8_t waitCycles)
{
	/*
	 * Placeholder function to handle mode change here
	 * (Eg: Quad/Dual etc...)
	 */

	return 0;
}

int mctp_check_spi_drv_exist(void)
{
	FILE *fp = NULL;
	char buff[MCTP_SYSTEM_CMD_BUFF_SIZE];
	const char *cmd = "lsmod | grep fmc";

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	MCTP_ASSERT_RET(fp != NULL, -1, "Failed to run command: %s", cmd);

	/* Read the output a line at a time - output it. */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		mctp_prdebug("Raw SPI driver exist: %s", buff);
		pclose(fp);
		return (1);
	}

	/* close */
	pclose(fp);
	return (0);
}

int mctp_check_spi_flash_exist(void)
{
	FILE *fp = NULL;
	char buff[MCTP_SYSTEM_CMD_BUFF_SIZE];
	const char *cmd = "cat /proc/mtd | grep mtd0";

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	MCTP_ASSERT_RET(fp != NULL, -1, "Failed to run command: %s", cmd);

	/* Read the output a line at a time - output it. */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		mctp_prdebug("Flash driver exist : %s", buff);
		pclose(fp);
		return (1);
	}

	/* close */
	pclose(fp);
	return (0);
}

int mctp_unload_flash_driver(void)
{
	ssize_t ret = 0;
	int fd = 0;

	const char *path = "/sys/bus/platform/drivers/aspeed-smc/unbind";
	const char *path2 = "/sys/bus/platform/drivers/spi-aspeed-smc/unbind";
	const char data[] = "1e620000.spi\n";

	mctp_prinfo("%s: Unloading Flash driver.\n", __func__);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		mctp_prinfo("%s: Could not open %s \n trying: %s\n", __func__, path, path2);
		fd = open(path2, O_WRONLY);
	}
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open %s.", path);

	ret = write(fd, data, sizeof(data));
	close(fd);

	MCTP_ASSERT_RET(ret == sizeof(data), ret, "Could not write to %s.",
			path);

	return (0);
}

int mctp_load_spi_driver(void)
{
	int ret = 0;
	char cmd[MCTP_SPI_LOAD_CMD_SIZE];

	/* Check Flash driver is loaded */
	ret = mctp_check_spi_flash_exist();
	if (ret > 0) {
		int status;

		status = mctp_unload_flash_driver();
		MCTP_ASSERT_RET(status == 0, MCTP_SPI_FAILURE,
				"Could not unload flash driver.");
	} else {
		mctp_prinfo("%s: Flash driver already unloaded: %d\n", __func__,
			    ret);
	}

	/* Check Raw SPI driver is loaded */
	ret = mctp_check_spi_drv_exist();
	if (ret > 0) {
		mctp_prinfo("%s: Raw SPI driver already loaded: %d\n", __func__,
			    ret);
	} else {
		sleep(MCTP_SPI_LOAD_UNLOAD_DELAY_SECS);
		memset(cmd, '\0', MCTP_SPI_LOAD_CMD_SIZE);
		sprintf(cmd, "%s", MCTP_SPI_DRIVER_PATH);
		mctp_prinfo("%s: Loading Raw SPI driver: %s\n", __func__, cmd);
		ret = system(cmd);
		mctp_prinfo("%s: Loaded Raw SPI driver successfully: %d\n",
			    __func__, ret);

		/* Need some wait time to complete the FMC Raw SPI driver initialization */
		sleep(MCTP_SPI_LOAD_UNLOAD_DELAY_SECS);
	}

	return MCTP_SPI_SUCCESS;
}

static int mctp_spi_xfer(int sendLen, uint8_t *sbuf, int recvLen, uint8_t *rbuf,
			 bool deassert)
{
	int status = 0;
	int len = sendLen + recvLen; // sbuf and rbuf must be the same size
	uint8_t rbuf2[len];
	uint8_t sbuf2[len];

	memset(rbuf2, 0, len);
	memset(sbuf2, 0, len);

	memcpy(sbuf2, sbuf, sendLen);

	MCTP_ASSERT_RET(spi_fd >= 0, -1, "spi_fd == -1?");

	status = ast_spi_xfer(spi_fd, sbuf2, len, rbuf2, recvLen, deassert);
	MCTP_ASSERT_RET(status >= 0, -1, "ast_spi_xfer failed: %d\n", status);

	// shift out send section
	memcpy(rbuf, rbuf2, recvLen);

	return (0);
}

static int mctp_spi_tx(struct mctp_binding_spi *spi, const uint8_t len,
		       struct mctp_astspi_pkt_private *pkt_pvt)
{
	SpbApStatus status = 0;

	MCTP_ASSERT_RET(len <= SPI_TX_BUFF_SIZE, -1, "spb_ap_send length: %id",
			len);

	mctp_trace_tx(spi->txbuf, len);
	mctp_prdebug("spb_ap_send");

	status = spb_ap_send(&spi->nvda_spb_ap, len, spi->txbuf);
	MCTP_ASSERT_RET(status == SPB_AP_OK, -1, "spb_ap_send failed: %d",
			status);

	return (0);
}

static int mctp_binding_spi_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_spi *spi = binding_to_spi(b);
	struct mctp_spi_header *spi_hdr_tx = (void *)spi->txbuf;
	struct mctp_astspi_pkt_private *pkt_pvt =
		(struct mctp_astspi_pkt_private *)pkt->msg_binding_private;
	const size_t pkt_length = mctp_pktbuf_size(pkt);
	size_t tx_buf_len = sizeof(*spi_hdr_tx);
	int ret;
	uint8_t spi_message_len;
	SpbApStatus status;

	mctp_spi_verify_magics(spi);
	/*
	 * The length field in the header excludes spi framing
	 * and escape sequences.
	 */

	spi_hdr_tx->command_code = MCTP_COMMAND_CODE;
	spi_hdr_tx->byte_count = pkt_length;

	spi_message_len = tx_buf_len + pkt_length;
	MCTP_ASSERT_RET(spi_message_len <= sizeof(spi->txbuf), -1,
			"tx message length exceeds max spi message length");

	memcpy(spi->txbuf + tx_buf_len, &pkt->data[pkt->start], pkt_length);
	tx_buf_len += pkt_length;

	ret = mctp_spi_tx(spi, spi_message_len, pkt_pvt);
	mctp_spi_verify_magics(spi);

	if (spb_ap_msgs_available(&spi->nvda_spb_ap) > 0) {
		/* We can't rely on msg_avaiable counts to issues read transactions
		 * becasue we only have one mailbox status which can't tell how many
		 * response pending in glaicer sides. The solution is to read from 
		 * glacier and read all pending responses once.
		 */
		while (1) {
			status = mctp_spi_rx(spi);
			if (status == ERR_SPI_RX_NO_DATA)
				break;
		}
		spi->nvda_spb_ap.msgs_available = 0;
	}


	MCTP_ASSERT_RET(ret >= 0, -1, "Error in tx of spi message");

	return (0);
}

static void mctp_spi_hexdump(const char *prefix, int len, void *buf)
{
	unsigned char *data = (unsigned char *)buf;
	int ii = 0;

	printf("%s> ", prefix);
	printf("SPI HDR (%u bytes): ", sizeof(struct mctp_spi_header));
	for (ii = 0; ii < sizeof(struct mctp_spi_header); ii++) {
		printf("%02x ", data[ii]);
	}
	printf("\nData: ");
	for (; ii < len; ii++) {
		printf("%02x ", data[ii]);
		if ((ii + 1) % 16 == 0)
			printf("\n     ");
	}
	printf("\n");
}

int mctp_spi_init_pollfd(struct mctp_binding_spi *spi, struct pollfd *pollfd)
{
	pollfd->fd = spi->nvda_spb_ap.gpio_fd;
	pollfd->events = POLLPRI;

	return 0;
}

static void mctp_spi_verify_magics(struct mctp_binding_spi *spi)
{
	/*
	 * The purpose of this function is to enforce
	 * integrity of the spi structure, especially
	 * around tx/rx buffers. If any data corruption
	 * happens, the assertions below will fire.
	 */

	MCTP_ASSERT(spi->_magic1 == SPI_BINDING_MAGIC1,
		    "Data corruption detected");
	MCTP_ASSERT(spi->_magic2 == SPI_BINDING_MAGIC2,
		    "Data corruption detected");
	MCTP_ASSERT(spi->_magic3 == SPI_BINDING_MAGIC3,
		    "Data corruption detected");
	MCTP_ASSERT(spi->_magic4 == SPI_BINDING_MAGIC4,
		    "Data corruption detected");
}

int mctp_spi_process(struct mctp_binding_spi *spi)
{
	/*
	 * We got notification from GPIO pin. There is no need to call poll(2)
	 * again. Let's check for what information we got and consume data from
	 * GPIO fd.
	 */
	SpbApStatus status;

	/*
	 * There is some chance we get notification about new message while we
	 * are checking for acknowledgement.
	 */
	ast_spi_gpio_intr_check(spi->gpio_fd, 0, false);
	status = spb_ap_on_interrupt(&spi->nvda_spb_ap);

	while (spb_ap_msgs_available(&spi->nvda_spb_ap) > 0)
		mctp_spi_rx(spi);
	return (0);
}

static int mctp_spi_rx(struct mctp_binding_spi *spi)
{
	ssize_t len;
	ssize_t payload_len;
	const size_t hdr_size = sizeof(struct mctp_spi_header);
	int ret = 0;
	SpbApStatus status = 0;
	struct mctp_spi_header *spi_hdr_rx;
	struct mctp_astspi_pkt_private pvt_data;

	spi_hdr_rx = (struct mctp_spi_header *)spi->rxbuf;

	memset(&pvt_data, 0, sizeof(pvt_data));

	status = spb_ap_recv(&spi->nvda_spb_ap, sizeof(spi->rxbuf), spi->rxbuf);
	MCTP_ASSERT_RET(status == SPB_AP_OK, ERR_SPI_RX_NO_DATA,
			"spb_ap_recv failed: 	%s", spb_ap_strstatus(status));

	mctp_spi_verify_magics(spi);

	payload_len = spi_hdr_rx->byte_count;
	len = payload_len + hdr_size;

	MCTP_ASSERT_RET(len >= hdr_size, ERR_SPI_RX, "Invalid packet size: %zi", len);
	MCTP_ASSERT_RET(payload_len > 0, ERR_SPI_RX, "Invalid payload size: %zi",
			payload_len);

	/* command_code != 0x02 => Not a payload intended for us */
	MCTP_ASSERT_RET(spi_hdr_rx->command_code == MCTP_COMMAND_CODE, 0,
			"Got bad command code %d", spi_hdr_rx->command_code);

	mctp_trace_rx(spi->rxbuf, payload_len);

	spi->rx_pkt = mctp_pktbuf_alloc(&(spi->binding), 0);
	MCTP_ASSERT(spi->rx_pkt != NULL, "spi->rx_pkt is NULL");

	ret = mctp_pktbuf_push(spi->rx_pkt, spi->rxbuf + hdr_size, payload_len);
	MCTP_ASSERT_RET(ret == 0, ERR_SPI_RX, "Can't push to pktbuf: %d", ret);

	mctp_spi_verify_magics(spi);
	memcpy(spi->rx_pkt->msg_binding_private, &pvt_data, sizeof(pvt_data));
	mctp_bus_rx(&(spi->binding), spi->rx_pkt);

	/* spi->rx_pkt will be freed in MCTP stack. */
	spi->rx_pkt = NULL;

	return 0;
}

int mctp_spi_set_spi_fd(struct mctp_binding_spi *spi, int fd)
{
	spi->spi_fd = fd;

	return 0;
}

int mctp_spi_register_bus(struct mctp_binding_spi *spi, struct mctp *mctp,
			  mctp_eid_t eid)
{
	int rc = 0;

	rc = mctp_register_bus(mctp, &spi->binding, eid);
	MCTP_ASSERT_RET(rc == 0, rc, "Could not register SPI bus: %d", rc);

	spi->bus_id = 0;
	mctp_binding_set_tx_enabled(&spi->binding, true);

	return rc;
}

static int mctp_binding_spi_start(struct mctp_binding *b)
{
	mctp_binding_set_tx_enabled(b, true);

	return 0;
}

struct mctp_binding_spi *
mctp_spi_bind_init(struct mctp_astspi_device_conf *conf)
{
	struct mctp_binding_spi *spi = NULL;
	int count = 0;
	SpbApStatus status = 0;

	spi = __mctp_alloc(sizeof(*spi));
	memset(&(spi->binding), 0, sizeof(spi->binding));

	mctp_prinfo("Loading SPI driver...");

	if (mctp_load_spi_driver() != MCTP_SPI_SUCCESS) {
		mctp_prerr("Could not load SPI driver.\n");
		__mctp_free(spi);
		return (NULL);
	}

	mctp_prinfo("Initializing GPIO intr notifications...");
	spi->gpio_fd = ast_spi_gpio_intr_init(conf->gpio);
	if (spi->gpio_fd < 0) {
		mctp_prerr("Could not open GPIO fd.");
		__mctp_free(spi);
		return (NULL);
	}

	mctp_prinfo("Opening SPI device...");
	spi->spi_fd = ast_spi_open(conf->dev, conf->channel, conf->mode,
				   conf->disablecs, conf->singlemode);
	if (spi->spi_fd < 0) {
		mctp_prerr("Could not open SPI fd.");
		close(spi->gpio_fd);
		__mctp_free(spi);
		return (NULL);
	}

	spi_fd = spi->spi_fd;

	spi->nvda_spb_ap.debug_level = 0;
	spi->nvda_spb_ap.on_mode_change = ast_spi_on_mode_change;
	spi->nvda_spb_ap.spi_xfer = mctp_spi_xfer;
	spi->nvda_spb_ap.gpio_fd = spi->gpio_fd;

	mctp_prinfo("Performing SPB AP init...");
	do {
		/* Initialize SPB AP Library */
		status = spb_ap_initialize(&spi->nvda_spb_ap);

		if (status != SPB_AP_OK) {
			/* Increment the count */
			count++;

			mctp_prerr(
				"%s: Cannot initialize SPB AP (%d), retrying[%d]\n",
				__func__, status, count);
			usleep(MCTP_SPI_CMD_DELAY_USECS);
		} else {
			mctp_prinfo(
				"%s: Initialized SPB interface successfully\n",
				__func__);
		}
	} while (count < SPB_AP_INIT_THRESHOLD && status != SPB_AP_OK);

	mctp_prinfo("SPB AP init completed...");

	/* Return Failure, Glacier could be in bad state */
	if (status != SPB_AP_OK) {
		mctp_prerr("%s: Unable to initialize Glacier module\n",
			   __func__);
		close(spi->gpio_fd);
		close(spi->spi_fd);
		__mctp_free(spi);
		spi_fd = -1;
		return (NULL);
	}

	/* Give few milli-secs delay after init */
	usleep(MCTP_SPI_CMD_DELAY_USECS);

	spi->rx_pkt = NULL;
	spi->binding.name = "spi";
	spi->binding.version = 1;
	spi->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	spi->binding.pkt_priv_size = sizeof(struct mctp_astspi_pkt_private);

	spi->binding.start = mctp_binding_spi_start;
	spi->binding.tx = mctp_binding_spi_tx;

	spi->_magic1 = SPI_BINDING_MAGIC1;
	spi->_magic2 = SPI_BINDING_MAGIC2;
	spi->_magic3 = SPI_BINDING_MAGIC3;
	spi->_magic4 = SPI_BINDING_MAGIC4;

	return spi;
}

void mctp_spi_set_controller(struct mctp_binding_spi *spi, uint8_t inst)
{
	spi->controller = inst;
}

void mctp_spi_free(struct mctp_binding_spi *spi)
{
	if (!(spi->spi_fd < 0)) {
		close(spi->spi_fd);
	}

	__mctp_free(spi);
}

struct mctp_binding *mctp_binding_astspi_core(struct mctp_binding_spi *spi)
{
	return &spi->binding;
}

static void ast_spi_print_tx_rx(unsigned char *txdata, int txlen,
				unsigned char *rxdata, int rxlen)
{
	int ii = 0;

	mctp_prdebug(
		"------------------------------------------------------\n");
	mctp_prdebug("Tx [%d]: \t", (txlen - rxlen));
	for (ii = 0; ii < (txlen - rxlen); ii++) {
		mctp_prdebug("0x%x ", txdata[ii]);
	}
	mctp_prdebug("\n");
	mctp_prdebug("Rx [%d]: \t", rxlen);
	for (ii = 0; ii < rxlen; ii++) {
		mctp_prdebug("0x%x ", rxdata[ii]);
	}
	mctp_prdebug(
		"\n------------------------------------------------------\n");
}

int ast_spi_xfer(int fd, unsigned char *txdata, int txlen,
		 unsigned char *rxdata, int rxlen, bool deassert)
{
	if (spiMode & SPI_3WIRE) {
		return (ast_spi_xfer_3wire(fd, txdata, txlen, rxdata, rxlen,
					   deassert));
	}

	return (ast_spi_xfer_normal(fd, txdata, txlen, rxdata, rxlen,
				    deassert));
}

static int ast_spi_xfer_3wire(int fd, unsigned char *txdata, int txlen,
			      unsigned char *rxdata, int rxlen, bool deassert)
{
	struct spi_ioc_transfer spi = { 0 };
	int ret = 0;

	// send
	spi.tx_buf = (unsigned long)txdata;
	spi.rx_buf = (unsigned long)NULL; // single wire, this must be null
	spi.len = txlen;
	spi.speed_hz = spiSpeed;
	spi.bits_per_word = spiBPW;
	spi.cs_change = 0;
	spi.delay_usecs = spiDelay;

	ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
	MCTP_ASSERT_RET(ret >= 0, ret, "Cannot send message %d (%s)", errno,
			strerror(errno));

	// recv
	spi.tx_buf = (unsigned long)NULL; // single wire recv, this must be null
	spi.rx_buf = (unsigned long)(rxdata);
	spi.len = rxlen;
	spi.speed_hz = spiSpeed;
	spi.bits_per_word = spiBPW;
	spi.cs_change = 0;
	spi.delay_usecs = spiDelay;

	ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
	MCTP_ASSERT_RET(ret >= 0, ret, "Cannot recv message: %d (%s)", errno,
			strerror(errno));

	return (ret);
}

static int ast_spi_xfer_normal(int fd, unsigned char *txdata, int txlen,
			       unsigned char *rxdata, int rxlen, bool deassert)
{
	struct spi_ioc_transfer spi = { 0 };
	int ret;

	if ((txlen - rxlen) > 0) {
		spi.tx_buf = (unsigned long)txdata;
	} else {
		spi.tx_buf = (unsigned long)NULL;
	}

	spi.rx_buf = (unsigned long)rxdata;
	spi.len = txlen;
	spi.delay_usecs = rxlen;
	spi.cs_change = deassert;
	spi.speed_hz = spiSpeed;
	spi.bits_per_word = spiBPW;

	ret = ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
	MCTP_ASSERT_RET(ret >= 0, ret, "SPI Xfer data failure: %d (%s)", errno,
			strerror(errno));

	ast_spi_print_tx_rx(txdata, txlen, rxdata, rxlen);

	return (ret);
}

int ast_spi_set_speed(int fd, int speed)
{
	int ret = 0;

	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
	MCTP_ASSERT_RET(ret >= 0, -1, "SPI WR Speed Change failure: %d (%s)",
			errno, strerror(errno));

	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
	MCTP_ASSERT_RET(ret >= 0, -1, "SPI RD Speed Change failure: %d (%s)",
			errno, strerror(errno));

	spiSpeed = speed;

	return (ret);
}

int ast_spi_set_bpw(int fd, int bpw)
{
	int ret = 0;

	ret = ioctl(fd, SPI_IOC_WR_MODE, &bpw);
	MCTP_ASSERT_RET(ret >= 0, -1,
			"SPI WR BitPerWord Change failure: %d (%s)", errno,
			strerror(errno));

	ret = ioctl(fd, SPI_IOC_RD_MODE, &bpw);
	MCTP_ASSERT_RET(ret >= 0, -1,
			"SPI RD BitPerWord Change failure: %d (%s)", errno,
			strerror(errno));

	spiBPW = bpw;

	return (ret);
}

int ast_spi_set_mode(int fd, int mode)
{
	int ret = 0;
	int tryMode = spiMode;

	tryMode = spiMode | mode & 0x07;
	ret = ioctl(fd, SPI_IOC_WR_MODE, &tryMode);
	MCTP_ASSERT_RET(ret >= 0, -1, "SPI WR Mode Change failure: %d (%s)",
			errno, strerror(errno));

	ret = ioctl(fd, SPI_IOC_RD_MODE, &tryMode);
	MCTP_ASSERT_RET(ret >= 0, -1, "SPI RD Mode Change failure: %d (%s)",
			errno, strerror(errno));

	spiMode = tryMode;

	return (ret);
}

int ast_spi_set_udelay(int usecond)
{
	spiDelay = usecond;

	return (0);
}

int ast_spi_open(int dev, int channel, int mode, int disablecs, int singlemode)
{
	int fd = 0;
	char spiDev[32] = "";

	snprintf(spiDev, 31, "/dev/spidev%d.%d", dev, channel);

	fd = open(spiDev, O_RDWR);
	MCTP_ASSERT_RET(fd >= 0, -1, "Unable to open SPI device: %d (%s)",
			errno, strerror(errno));

	spiMode = mode;
	if (singlemode)
		spiMode |= SPI_3WIRE;

	if (disablecs)
		spiMode |= SPI_NO_CS;

	return (fd);
}

int ast_spi_close(int fd)
{
	int ret = 0;

	ret = close(fd);
	MCTP_ASSERT_RET(ret == 0, fd, "close(2) failed: %d (%s)", errno,
			strerror(errno));

	return (0);
}

static int ast_spi_gpio_export(unsigned int gpio)
{
	int fd = 0, len = 0;
	ssize_t ret = 0;
	char buf[MAX_BUF];
	const char path[] = SYSFS_GPIO_DIR "/export";

	fd = open(path, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open: %s due to %d (%s)", path,
			errno, strerror(errno));

	memset(buf, '\0', sizeof(buf));
	len = snprintf(buf, sizeof(buf), "%d", gpio);

	ret = write(fd, buf, len);
	/* EBUSY means the settings were already set. */
	MCTP_ASSERT(ret == len || (ret == -1 && errno == EBUSY),
		    "write(2) failed: %d (%s)", errno, strerror(errno));
	close(fd);

	return (0);
}

static int ast_spi_gpio_unexport(unsigned int gpio)
{
	int fd = 0, len = 0;
	ssize_t ret;
	char buf[MAX_BUF];
	const char path[] = SYSFS_GPIO_DIR "/unexport";

	fd = open(path, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open: %s due to %d (%s)", path,
			errno, strerror(errno));

	memset(buf, '\0', sizeof(buf));
	len = snprintf(buf, sizeof(buf), "%d", gpio);

	ret = write(fd, buf, len);
	MCTP_ASSERT(ret == len, "write(2) failed: %d (%s)", errno,
		    strerror(errno));

	close(fd);
	return (0);
}

static int ast_spi_gpio_set_dir(unsigned int gpio, unsigned int out_flag)
{
	int fd = 0;
	ssize_t ret;
	char buf[MAX_BUF];

	memset(buf, '\0', sizeof(buf));
	snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/direction", gpio);

	fd = open(buf, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open: %s due to %d (%s)",
			(char *)buf, errno, strerror(errno));

	if (out_flag) {
		ret = write(fd, "out", 4);
		MCTP_ASSERT(ret == 4, "write(2) failed: %d (%s)", errno,
			    strerror(errno));
	} else {
		ret = write(fd, "in", 3);
		MCTP_ASSERT(ret == 3, "write(2) failed: %d (%s)", errno,
			    strerror(errno));
	}
	close(fd);
	return (0);
}

static int ast_spi_gpio_set_value(unsigned int gpio, unsigned int value)
{
	int fd = 0;
	ssize_t ret;
	char buf[MAX_BUF];

	memset(buf, '\0', sizeof(buf));
	snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);

	fd = open(buf, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open: %s due to %d (%s)", buf,
			errno, strerror(errno));

	if (value) {
		ret = write(fd, "1", 2);
		MCTP_ASSERT(ret == 1, "write(2) failed: %d (%s)", errno,
			    strerror(errno));
	} else {
		ret = write(fd, "0", 2);
		MCTP_ASSERT(ret == 1, "write(2) failed: %d (%s)", errno,
			    strerror(errno));
	}
	close(fd);
	return (0);
}

static int ast_spi_gpio_set_edge(unsigned int gpio, char *edge)
{
	ssize_t ret;
	int fd = 0;
	char buf[MAX_BUF];

	memset(buf, '\0', sizeof(buf));
	snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/edge", gpio);

	fd = open(buf, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, fd, "Could not open: %s due to %d (%s)", buf,
			errno, strerror(errno));

	ret = write(fd, edge, strlen(edge) + 1);
	MCTP_ASSERT(ret == strlen(edge) + 1, "write(2) failed: %d (%s)", errno,
		    strerror(errno));

	close(fd);
	return (0);
}

static int ast_spi_gpio_fd_open(unsigned int gpio)
{
	int fd = 0;
	char buf[MAX_BUF];

	snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);

	fd = open(buf, O_RDONLY | O_NONBLOCK);
	MCTP_ASSERT_RET(fd >= 0, fd, "GPIO fd_open error");

	return (fd);
}

int ast_spi_gpio_fd_close(int gpio_fd)
{
	return (close(gpio_fd));
}

int ast_spi_gpio_intr_init(unsigned int gpio)
{
	int gpio_fd = 0;

	/* Set GPIO params */
	ast_spi_gpio_export(gpio);
	ast_spi_gpio_set_dir(gpio, 0);
	ast_spi_gpio_set_edge(gpio, "falling");
	gpio_fd = ast_spi_gpio_fd_open(gpio);

	g_gpio_intr = 0;

	return (gpio_fd);
}

ssize_t ast_spi_gpio_intr_read(int gpio_fd)
{
	char buf[MAX_BUF];
	ssize_t ret;
	off_t offset;

	offset = lseek(gpio_fd, 0, SEEK_SET);
	MCTP_ASSERT(offset == 0, "lseek(2) failed: %d (%s)", errno,
		    strerror(errno));

	ret = read(gpio_fd, buf, sizeof(buf));
	MCTP_ASSERT_RET(ret > 0, ret, "read(2) failed: %d (%s)", errno,
			strerror(errno));

	return (ret);
}

short ast_spi_gpio_poll(int gpio_fd, int timeout_ms)
{
	int rc = 0;
	const int nfds = 1;
	struct pollfd fdset[nfds];

	memset(fdset, 0, sizeof(fdset));

	fdset[0].fd = gpio_fd;
	fdset[0].events = POLLPRI;

	rc = poll(fdset, nfds, timeout_ms);
	MCTP_ASSERT(rc >= 0, "Failed[rc=%d]: GPIO[%d] Interrupt polling failed",
		    rc, SPB_GPIO_INTR_NUM);

	if (rc == 0)
		return (0);

	return (fdset[0].revents);
}

int ast_spi_gpio_intr_drain(int gpio_fd)
{
	short revents = 0;
	int count = 0;

	do {
		revents = ast_spi_gpio_poll(gpio_fd, 0);

		if (revents == POLLPRI) {
			ast_spi_gpio_intr_read(gpio_fd);
			count++;
		}
	} while (revents == POLLPRI);

	return (count);
}

enum ast_spi_intr_status ast_spi_gpio_intr_check(int gpio_fd, int timeout_ms,
						 bool polling)
{
	short revents = 0;

	if (polling) {
		revents = ast_spi_gpio_poll(gpio_fd, timeout_ms);
		if (!(revents & POLLPRI)) {
			return (AST_SPI_INTR_NONE);
		}
	}

	ast_spi_gpio_intr_read(gpio_fd);
	return (AST_SPI_INTR_RECVD);
}
