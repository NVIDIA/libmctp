#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define pr_fmt(x) "smbus: " x

#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp.h"
#include "mctp-json.h"

struct mctp_binding_smbus {
	struct mctp_binding binding;
	int out_fd;
	int in_fd;
	unsigned long bus_id;

	/* receive buffer */
	uint8_t rxbuf[1024];
	struct mctp_pktbuf *rx_pkt;
	/* temporary transmit buffer */
	uint8_t txbuf[256];

	/* bus number */
	uint8_t bus_num;
	/* bus number */
	uint8_t bus_num_smq;
	/* dest slave address */
	uint8_t dest_slave_addr;
	/* src slave address */
	uint8_t src_slave_addr;
};

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif

#define binding_to_smbus(b) container_of(b, struct mctp_binding_smbus, binding)
#define total_tab_elements(a) (sizeof(a) / sizeof(a)[0])

#define MCTP_SMBUS_BUS_NUM 2
#define MCTP_SMBUS_DESTINATION_SLAVE_ADDRESS                                   \
	0x30 // BMC-FPGA-0x52, HMC-FPGA-0x30 (7 bit format)
#define MCTP_SMBUS_SOURCE_SLAVE_ADDRESS                                        \
	0x18 // BMC-     0x51, HMC-     0x18 (7 bit format)

#define MCTP_COMMAND_CODE 0x0F

#define MCTP_I2C_POLL_DELAY 1000

#define SMBUS_PEC_BYTE_SIZE	1
#define SMBUS_COMMAND_CODE_SIZE 1
#define SMBUS_LENGTH_FIELD_SIZE 1
#define SMBUS_ADDR_OFFSET_SLAVE 0x1000

/* Global definitions: i2c bus number, destination slave address, source slave address */
uint8_t g_mctp_smbus_bus_num = MCTP_SMBUS_BUS_NUM;
uint8_t g_mctp_smbus_bus_num_smq = MCTP_SMBUS_BUS_NUM;
uint8_t g_mctp_smbus_dest_slave_address = MCTP_SMBUS_DESTINATION_SLAVE_ADDRESS;
uint8_t g_mctp_smbus_src_slave_address = MCTP_SMBUS_SOURCE_SLAVE_ADDRESS;
uint8_t g_mctp_smbus_eid_type = EID_TYPE_BRIDGE;

struct mctp_smbus_header_tx {
	uint8_t command_code;
	uint8_t byte_count;
	uint8_t source_slave_address;
};

struct mctp_smbus_header_rx {
	uint8_t destination_slave_address;
	uint8_t command_code;
	uint8_t byte_count;
	uint8_t source_slave_address;
};

extern struct mctp_static_endpoint_mapper *static_endpoints;
extern uint8_t static_endpoints_len;

/**
 * @brief Print prepared MCTP packet ready to send via i2c.
 * 
 * @param[in] buffer - Buffor of MCTP packet
 * @param[in] len - Byte length of MCTP packet
 */
static void print_hex(const void *buffer, size_t len)
{
	size_t ii;
	const uint8_t *addr = (const uint8_t *)buffer;

	printf("Len: %d\n", len);

	for (ii = 0; ii < len; ii++)
		fprintf(stderr, "%02hhx%c", addr[ii], ii % 8 == 7 ? '\n' : ' ');
	if (len % 8 != 0)
		fprintf(stderr, "\n");
}

static uint8_t crc8_calculate(uint16_t d)
{
	int i;

#define POLYCHECK (0x1070U << 3)
	for (i = 0; i < 8; i++) {
		if (d & 0x8000) {
			d = d ^ POLYCHECK;
		}
		d = d << 1;
	}
#undef POLYCHECK
	return (uint8_t)(d >> 8);
}

/* Incremental CRC8 over count bytes in the array pointed to by p */
static uint8_t pec_calculate(uint8_t crc, uint8_t *p, size_t count)
{
	int i;

	for (i = 0; i < count; i++) {
		crc = crc8_calculate((crc ^ p[i]) << 8);
	}

	return crc;
}

static uint8_t calculate_pec_byte(uint8_t *buf, size_t len, uint8_t address,
				  uint16_t flags)
{
	uint8_t addr = (address << 1) | (flags & I2C_M_RD ? 1 : 0);
	uint8_t pec = pec_calculate(0, &addr, 1);

	pec = pec_calculate(pec, buf, len);

	return pec;
}

/**
 * @brief Prepare i2c message from MCTP packet
 * 
 * @param[in] smbus - Struct mctp_binding_smbus
 * @param[in] len - Byte length of MCTP packet to send via i2c
 * @return int > 0 - successfull, errno - failure.
 */
static int mctp_smbus_tx(struct mctp_binding_smbus *smbus, uint8_t len)
{
	struct i2c_msg msg = {
		.addr = g_mctp_smbus_dest_slave_address, /* 7-bit address */
		.flags = 0,
		.len = len,
		.buf = (__uint8_t *)smbus->txbuf,
	};
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg, 1 };
	int rc;

	mctp_trace_tx(smbus->txbuf, len);
	print_hex(smbus->txbuf, len);

	rc = ioctl(smbus->out_fd, I2C_RDWR, &msgrdwr);
	MCTP_ASSERT_RET(rc >= 0, rc, "Invalid ioctl ret val: %d (%s)", errno,
			strerror(errno));
	return rc;
}

static int mctp_binding_smbus_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	mctp_prdebug("%s: Prepared MCTP packet\n", __func__);

	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	struct mctp_smbus_header_tx *hdr;
	size_t pkt_length = mctp_pktbuf_size(pkt);
	int rv;

	uint8_t *buf_ptr;
	uint8_t i2c_message_len;

	/* the length field in the header excludes smbus framing
	 * and escape sequences */
	hdr = (struct mctp_smbus_header_tx *)smbus->txbuf;
	hdr->command_code = MCTP_COMMAND_CODE;
	hdr->byte_count = (uint8_t)pkt_length + 1;
	/* 8 bit address */
	hdr->source_slave_address =
		(g_mctp_smbus_src_slave_address << 1) | 0x01;

	buf_ptr = (uint8_t *)smbus->txbuf + sizeof(*hdr);
	memcpy(buf_ptr, &pkt->data[pkt->start], pkt_length);

	buf_ptr = buf_ptr + pkt_length;
	*buf_ptr = calculate_pec_byte(smbus->txbuf, sizeof(*hdr) + pkt_length,
				      g_mctp_smbus_dest_slave_address, 0);

	//MCTP packet length of [ header, data, pec byte ]
	i2c_message_len = sizeof(*hdr) + pkt_length + SMBUS_PEC_BYTE_SIZE;

	rv = mctp_smbus_tx(smbus, i2c_message_len);
	MCTP_ASSERT_RET(rv >= 0, -1, "mctp_smbus_tx failed: %d", rv);

	return 0;
}

int mctp_smbus_open_in_bus(struct mctp_binding_smbus *smbus, int in_bus,
			   int src_slv_addr)
{
	char filename[60];
	size_t filename_size = 0;
	char slave_mqueue[20];
	size_t mqueue_size = 0;
	int fd = 0;
	size_t size = sizeof(filename);
	int address_7_bit = src_slv_addr;
	int ret = -1;

	snprintf(filename, size,
		 "/sys/bus/i2c/devices/i2c-%d/%d-%04x/slave-mqueue", in_bus,
		 in_bus, SMBUS_ADDR_OFFSET_SLAVE | address_7_bit);

	mctp_prdebug("%s: Open: %s\n", __func__, filename);
	ret = open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	mctp_prdebug("%s: ret = : %d\n", __func__, ret);

	if (ret >= 0)
		return ret;

	// Device doesn't exist.  Create it.
	filename_size = sizeof(filename);
	snprintf(filename, filename_size,
		 "/sys/bus/i2c/devices/i2c-%d/new_device", in_bus);
	filename[filename_size - 1] = '\0';

	mctp_prdebug("%s: Register new device: %s\n", __func__, filename);

	fd = open(filename, O_WRONLY);
	MCTP_ASSERT_RET(fd >= 0, -1, "Can't open root device: %s", filename);

	mqueue_size = sizeof(slave_mqueue);

	mctp_prdebug("%s: mqueue_size: %d\n", __func__, mqueue_size);

	snprintf(slave_mqueue, mqueue_size, "slave-mqueue %#04x",
		 SMBUS_ADDR_OFFSET_SLAVE | address_7_bit);
	mctp_prdebug("%s: slave_mqueue: %s\n", __func__, slave_mqueue);
	size = write(fd, slave_mqueue, mqueue_size);
	close(fd);

	MCTP_ASSERT_RET(size == mqueue_size, -1,
			"Can't create mqueue device on %s", filename);

	size = sizeof(filename);
	snprintf(filename, size,
		 "/sys/bus/i2c/devices/i2c-%d/%d-%04x/slave-mqueue", in_bus,
		 in_bus, SMBUS_ADDR_OFFSET_SLAVE | address_7_bit);
	return open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
}

int mctp_smbus_open_out_bus(struct mctp_binding_smbus *smbus, int out_bus)
{
	char filename[60];
	size_t size = sizeof(filename);
	snprintf(filename, size, "/dev/i2c-%d", out_bus);
	filename[size - 1] = '\0';

	mctp_prdebug("%s: open file: %s\n", __func__, filename);
	return open(filename, O_RDWR | O_NONBLOCK);
}

/*
 * Simple poll implementation for use
 */
int mctp_smbus_poll(struct mctp_binding_smbus *smbus, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = smbus->in_fd;
	fds[0].events = POLLIN;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	MCTP_ASSERT_RET(rc >= 0, -1, "SMBUS poll error status (errno=%d)",
			errno);

	return 0;
}

int send_get_udid_command(struct mctp_binding_smbus *smbus, uint8_t *inbuf, uint8_t len)
{
	int rc;
	uint8_t outbuf[1] = { 0x03 }; // Set 'Get UDID' command
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data msgset[1];
	int slave_addr = 0x61; // As 7-bit

	/* Prepare message to send Get UDID */
	msgs[0].addr = slave_addr;
	msgs[0].flags = 0;
	msgs[0].len = 1;
	msgs[0].buf = outbuf;

	msgs[1].addr = slave_addr;
	msgs[1].flags = I2C_M_RD | I2C_M_NOSTART;
	msgs[1].len = len;
	msgs[1].buf = inbuf;

	msgset[0].msgs = msgs;
	msgset[0].nmsgs = 2;

	rc = ioctl(smbus->out_fd, I2C_RDWR, &msgset);
	if (rc < 0) {
		MCTP_ASSERT_RET(rc >= 0, rc, "Invalid ioctl ret val: %d (%s)",
				errno, strerror(errno));
		return EXIT_FAILURE;
	}

	mctp_prdebug("%s: TX and RX Get UDID command", __func__);
	mctp_trace_tx(outbuf, msgs[0].len);
	mctp_trace_rx(inbuf, msgs[1].len);

	return EXIT_SUCCESS;
}

int send_mctp_get_ver_support_command(struct mctp_binding_smbus *smbus, uint8_t which_endpoint)
{
	int rc;
	// MCTP frame - Get MCTP version support
	uint8_t outbuf_mctp[] = { 0x0f, 0x0a, 0x31, 0x01, 0x00, 0x08, 0xc8,
				    0x00, 0x80, 0x04, 0x00, 0x00, 0x94 };
	struct i2c_msg msgs[1];
	struct i2c_rdwr_ioctl_data msgset[1];

	msgs[0].addr = static_endpoints[which_endpoint].slave_address;
	msgs[0].flags = 0;
	msgs[0].len = total_tab_elements(outbuf_mctp);
	msgs[0].buf = outbuf_mctp;

	msgset[0].msgs = msgs;
	msgset[0].nmsgs = 1;

	rc = ioctl(smbus->out_fd, I2C_RDWR, &msgset);
	if (rc < 0) {
		MCTP_ASSERT_RET(rc >= 0, rc, "Invalid ioctl ret val: %d (%s)",
				errno, strerror(errno));
		return EXIT_FAILURE;
	}

	mctp_prdebug("%s: TX Get MCTP version support command", __func__);
	mctp_trace_tx(outbuf_mctp, msgs[0].len);

	/* Wait for answer */
	sleep(1);
	rc = mctp_smbus_read_only(smbus);

	/* Check "Command Code" if a good response was received and
	 * "Completion Code", 0x00-support, 0x80-not support.
	 * See DSP0236 v1.3.0 sec. 12.6. Tab. 18
	 */
	if (smbus->rxbuf[10] == 0x04) {
		if (smbus->rxbuf[11] == 0x00) {
			static_endpoints[which_endpoint].support_mctp = 1;
			mctp_prdebug("%s: Message type number supported", __func__);
		} else {
			mctp_prdebug("%s: Message type number not supported (Completion Code = 0x%x)",
				__func__, smbus->rxbuf[11]);
			return EXIT_FAILURE;
		}
	} else {
		mctp_prdebug("%s: Received wrong Command Code", __func__);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int check_mctp_get_ver_support(struct mctp_binding_smbus *smbus, uint8_t which_endpoint,
			uint8_t *inbuf, uint8_t len)
{
	int rc;
	uint8_t interface_ASF = 0;
	uint8_t i;

	// Check ASF bit from UDID
	interface_ASF = inbuf[8];
	interface_ASF = (interface_ASF >> 5) & 0x01;

	if (interface_ASF == 1) {
		for (i = 0; i < 16; i++) {
			static_endpoints[which_endpoint].udid[i] = inbuf[i + 1];
		}
		/* Get MCTP version support */
		rc = send_mctp_get_ver_support_command(smbus, which_endpoint);
		if (rc != 0) {
			mctp_prdebug("%s: Get MCTP version support failed!", __func__);
		}
	}

	mctp_prdebug("\n%s: Static endpoint", __func__);
	mctp_prdebug("Endpoint = %d", static_endpoints[which_endpoint].endpoint_num);
	mctp_prdebug("Slave address = 0x%x", static_endpoints[which_endpoint].slave_address);
	mctp_prdebug("Support MCTP = %d", static_endpoints[which_endpoint].support_mctp);
	mctp_prdebug("UDID = ");
	for (i = 0; i < 16; i++) {
		mctp_prdebug("0x%x ", static_endpoints[which_endpoint].udid[i]);
	}

	return EXIT_SUCCESS;
}

int check_device_supports_mctp(struct mctp_binding_smbus *smbus)
{
	uint8_t inbuf[18];
	uint8_t inbuf_len = total_tab_elements(inbuf);

	send_get_udid_command(smbus, inbuf, inbuf_len);
	check_mctp_get_ver_support(smbus, 0, inbuf, inbuf_len);

	return EXIT_SUCCESS;
}

int mctp_smbus_read_only(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	int ret = 0;

	ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("Failed to seek");
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));

	if (len < 0) {
		mctp_prerr("Can't read from smbus device: %m");
		return -1;
	}

	mctp_trace_rx(smbus->rxbuf, len);

	return len;
}

int mctp_smbus_read(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	struct mctp_smbus_header_rx *hdr;
	int ret = 0;

	ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("Failed to seek");
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));
	if (len < sizeof(*hdr)) {
		// This condition hits from time to time, even with
		// a properly written poll loop, although it's not clear
		// why. Return an error so that the upper layer can
		// retry.
		return 0;
	}

	hdr = (void *)smbus->rxbuf;

	if (hdr->destination_slave_address !=
	    (g_mctp_smbus_src_slave_address << 1)) { // The recipient of the message is 'Src_slave_addr'
		mctp_prerr("Got bad slave address %d",
			   hdr->destination_slave_address);
		return 0;
	}
	if (hdr->command_code != MCTP_COMMAND_CODE) {
		mctp_prerr("Got bad command code %d", hdr->command_code);
		// Not a payload intended for us
		return 0;
	}

	if (hdr->byte_count != (len - sizeof(*hdr))) {
		// Got an incorrectly sized payload
		mctp_prerr("Got smbus payload sized %d, expecting %lu",
			   hdr->byte_count, len - sizeof(*hdr));
		return 0;
	}

	if (len < 0) {
		mctp_prerr("Can't read from smbus device: %m");
		return -1;
	}

	smbus->rx_pkt = mctp_pktbuf_alloc(&smbus->binding, 0);
	MCTP_ASSERT(smbus->rx_pkt != NULL, "Could not allocate pktbuf.");

	if (mctp_pktbuf_push(smbus->rx_pkt, &smbus->rxbuf[sizeof(*hdr)],
			     len - sizeof(*hdr) - SMBUS_PEC_BYTE_SIZE) != 0) {
		mctp_prerr("Can't push tok pktbuf: %m");
		return -1;
	}

	mctp_trace_rx(smbus->rxbuf, len);
	print_hex(smbus->rxbuf, len);

	mctp_bus_rx(&smbus->binding, smbus->rx_pkt);
	smbus->rx_pkt = NULL;

	return ret;
}

int mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->in_fd = fd;
	return 0;
}

int mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->out_fd = fd;
	return 0;
}

int mctp_smbus_get_in_fd(struct mctp_binding_smbus *smbus)
{
	return smbus->in_fd;
}

int mctp_smbus_get_out_fd(struct mctp_binding_smbus *smbus)
{
	return smbus->out_fd;
}

/*
 * Returns generic binder handler from SMBus binding handler
 */
struct mctp_binding *mctp_binding_smbus_core(struct mctp_binding_smbus *smbus)
{
	return &smbus->binding;
}

int mctp_smbus_init_pollfd(struct mctp_binding_smbus *smbus,
			   struct pollfd *pollfd)
{
	pollfd->fd = smbus->in_fd;
	pollfd->events = POLLIN;

	return 0;
}

void mctp_smbus_register_bus(struct mctp_binding_smbus *smbus,
			     struct mctp *mctp, mctp_eid_t eid)
{
	smbus->bus_id = mctp_register_bus(mctp, &smbus->binding, eid);
	mctp_binding_set_tx_enabled(&smbus->binding, true);
}

/*
 * Start function. Opens driver, read bdf and medium_id
 */
static int mctp_smbus_start(struct mctp_binding *b)
{
	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	int infd = -1, outfd = -1;

	MCTP_ASSERT_RET(smbus != NULL, -1, "Invalid binding private data.");

	mctp_prdebug("%s: Set param: %d, %d, %d", __func__, smbus->bus_id,
		     smbus->bus_num, smbus->dest_slave_addr);

	/* Open I2C out node */
	mctp_prdebug("%s: Setting up I2C output fd", __func__);
	outfd = mctp_smbus_open_out_bus(smbus, smbus->bus_num);
	MCTP_ASSERT_RET(outfd >= 0, -1, "Failed to open I2C Tx node: %d",
			outfd);

	/* Set out fd */
	mctp_smbus_set_out_fd(smbus, outfd);

	/* Open I2C in node */
	mctp_prdebug("%s: Setting up I2C input fd: %d %d", __func__,
		     smbus->bus_num_smq, smbus->dest_slave_addr);
	infd = mctp_smbus_open_in_bus(smbus, smbus->bus_num_smq,
				      smbus->src_slave_addr);
	MCTP_ASSERT_RET(infd >= 0, -1, "Failed to open I2C Rx node: %d", infd);

	/* Set in fd */
	mctp_smbus_set_in_fd(smbus, infd);

	/* Enable Tx */
	mctp_binding_set_tx_enabled(b, true);

	return 0;
}

struct mctp_binding_smbus *mctp_smbus_init(uint8_t bus, uint8_t bus_smq, uint8_t dest_addr,
					   uint8_t src_addr, uint8_t eid_type)
{
	struct mctp_binding_smbus *smbus;

	/* Actualize global MCTP SMBus params */
	g_mctp_smbus_bus_num = bus;
	g_mctp_smbus_bus_num_smq = bus_smq;
	g_mctp_smbus_dest_slave_address = dest_addr;
	g_mctp_smbus_src_slave_address = src_addr;
	g_mctp_smbus_eid_type = eid_type;

	smbus = __mctp_alloc(sizeof(*smbus));
	memset(&(smbus->binding), 0, sizeof(smbus->binding));

	smbus->in_fd = -1;
	smbus->out_fd = -1;

	smbus->rx_pkt = NULL;
	smbus->binding.name = "smbus";
	smbus->binding.version = 1;

	smbus->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	smbus->binding.pkt_header = 0;
	smbus->binding.pkt_trailer = 0;
	smbus->binding.pkt_priv_size = sizeof(struct mctp_smbus_pkt_private);

	/* Setting the default bus number */
	smbus->bus_num = bus;
	smbus->bus_num_smq = bus_smq;
	/* Setting the default destination and source slave address */
	smbus->dest_slave_addr = dest_addr;
	smbus->src_slave_addr = src_addr;

	smbus->binding.start = mctp_smbus_start;
	smbus->binding.tx = mctp_binding_smbus_tx;

	return smbus;
}

void mctp_smbus_free(struct mctp_binding_smbus *smbus)
{
	__mctp_free(smbus);
}
