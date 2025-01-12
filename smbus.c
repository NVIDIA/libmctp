#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/queue.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define pr_fmt(x) "smbus: " x

#ifdef MCTP_HAVE_CONFIG_H
#include "config.h"
#endif

#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp.h"
#include "mctp-json.h"

struct mctp_binding_smbus {
	struct mctp_binding binding;
	int out_fd[MCTP_I2C_MAX_BUSES];
	int in_fd;
	unsigned long bus_id;

	/* receive buffer */
	uint8_t rxbuf[1024];
	struct mctp_pktbuf *rx_pkt;
	/* temporary transmit buffer */
	uint8_t *txbuf_ptr;

	/* bus number */
	uint8_t bus_num[MCTP_I2C_MAX_BUSES];
	/* bus number */
	uint8_t bus_num_smq;
	/* dest slave address */
	uint8_t dest_slave_addr[MCTP_I2C_MAX_BUSES];
	/* src slave address */
	uint8_t src_slave_addr;

	/* i2c lock timeout*/
	uint16_t timeout;

	/* static endpoints configuration */
	struct mctp_static_endpoint_mapper *static_endpoints;
	uint8_t static_endpoints_len;
};

// tx thread for blocking I2C syscall
pthread_t tx_thread;
// the conditional wait for the request
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
// the conditional wait for the response
pthread_cond_t cond_resp = PTHREAD_COND_INITIALIZER;
// the mutex for conditional wait
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
/* the flag to terminate thread */
bool terminate_tx_thread = false;
// tx queue list
struct qentry {
	TAILQ_ENTRY(qentry) entries;
	void *data;
};
TAILQ_HEAD(listhead, qentry);
struct listhead head;
// internal mctp packet structure for tx thread
struct smbus_tx_thread_info {
	/* dest eid */
	uint8_t eid;
	int fd;
	uint8_t *buf;
	uint16_t len;
	bool mux_grab;
	int addr;
	uint16_t timeout;
};
/* I2C M HOLD is a custom flag to hold I2C mux 
	with specific I2C dest address */
#ifndef I2C_M_HOLD
#define I2C_M_HOLD 0x0100
#endif

#define MCTP_SMBUS_I2C_M_HOLD_TIMEOUT_MS 800
#define MCTP_SMBUS_I2C_TX_RETRIES_MAX                                          \
	10 /* 10 retries with a 20ms sleep, so a total of 20ms at worst*/
#define MCTP_SMBUS_I2C_TX_RETRIES_US 2000 /* 2ms * 10 = 20ms*/

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif

#define binding_to_smbus(b)   container_of(b, struct mctp_binding_smbus, binding)
#define total_tab_elements(a) (sizeof(a) / sizeof(a)[0])

#define MCTP_SMBUS_BUS_NUM 2
#define MCTP_SMBUS_DESTINATION_SLAVE_ADDRESS                                   \
	0x30 // BMC-FPGA-0x52, HMC-FPGA-0x30 (7 bit format)
#define MCTP_SMBUS_SOURCE_SLAVE_ADDRESS                                        \
	0x18 // BMC-     0x51, HMC-     0x18 (7 bit format)

#define MCTP_COMMAND_CODE 0x0F

/* Default smbus slave address for get UDID command */
#define MCTP_SMBUS_DEFAULT_GET_UDID_SLAVE_ADDRESS 0x61

#define MCTP_I2C_POLL_DELAY 1000

#define SMBUS_PEC_BYTE_SIZE	1
#define SMBUS_COMMAND_CODE_SIZE 1
#define SMBUS_LENGTH_FIELD_SIZE 1
#define SMBUS_ADDR_OFFSET_SLAVE 0x1000
#define SMBUS_HDR_LENGTH	3
#define SMBUS_PAD_LENGTH	1

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

/**
 * @brief Print prepared MCTP packet ready to send via i2c.
 * 
 * @param[in] buffer - Buffor of MCTP packet
 * @param[in] len - Byte length of MCTP packet
 */
#if DEBUG
static void print_hex(const void *buffer, size_t len)
{
	size_t ii;
	const uint8_t *addr = (const uint8_t *)buffer;

	for (ii = 0; ii < len; ii++)
		mctp_prinfo("%02hhx%c", addr[ii], ii % 8 == 7 ? '\n' : ' ');
	if (len % 8 != 0)
		mctp_prinfo("\n");
}
#endif

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
	size_t i;

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

static int get_out_fd(struct mctp_binding_smbus *smbus, uint8_t eid)
{
	for (uint8_t i = 0; i < smbus->static_endpoints_len; ++i) {
		if (smbus->static_endpoints[i].endpoint_num == eid) {
			return smbus->static_endpoints[i].out_fd;
		}
	}

	return smbus->out_fd[0];
}

static int get_dest_i2c_addr(struct mctp_binding_smbus *smbus, uint8_t eid)
{
	for (uint8_t i = 0; i < smbus->static_endpoints_len; ++i) {
		if (smbus->static_endpoints[i].endpoint_num == eid) {
			return smbus->static_endpoints[i].slave_address;
		}
	}

	return smbus->dest_slave_addr[0];
}

static void *smbus_tx_thread(void *arg __attribute__((unused)))
{
	/* timeout 10s is used to recover the lock if crash */
	uint16_t hold_timeout = MCTP_SMBUS_HOLD_TIMEOUT;

	int retry = MCTP_SMBUS_I2C_TX_RETRIES_MAX;
	int rc;
	int secs, nsecs;
	struct timespec start, end, tm;
	struct qentry *entry;
	struct smbus_tx_thread_info *info;
	uint8_t *buf;
	uint16_t len;
	uint8_t dest_eid;

	// detach the thread
	pthread_detach(pthread_self());

	while (true) {
		pthread_mutex_lock(&thread_mutex);
		if (TAILQ_EMPTY(&head)) {
			pthread_cond_wait(&cond, &thread_mutex);
		}

		if (terminate_tx_thread) {
			break;
		}

		entry = TAILQ_FIRST(&head);
		info = (struct smbus_tx_thread_info *)entry->data;
		buf = info->buf;
		len = info->len;
		dest_eid = info->eid;

		struct i2c_msg msgs[2] = {
			{
				.addr = 0, /* 7-bit address */
				.flags = 0,
				.len = len,
				.buf = (__uint8_t *)buf,
			},
			{
				.addr = 0,
				.flags = I2C_M_HOLD,
				.len = sizeof(hold_timeout),
				.buf = (uint8_t *)&hold_timeout,
			},
		};
		struct i2c_rdwr_ioctl_data msgrdwr = { msgs, 1 };

		if (info->mux_grab) {
			msgrdwr.nmsgs = 2;
		}

		mctp_trace_tx(buf, len);

		msgs[0].addr = info->addr;
		if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
			mctp_prerr("fail to do clock_gettime");
		}

		do {
			/* blocking i2c transaction */
			rc = ioctl(info->fd, I2C_RDWR, &msgrdwr);
			if (rc < 0) {
				if ((errno == EAGAIN || errno == EPROTO ||
				     errno == ETIMEDOUT || errno == ENXIO ||
				     errno == EIO || errno == EBUSY)) {
					if (retry % 200 == 0) {
						/* Only trace every 200 retries*/
						MCTP_ERR(
							"[%d]Invalid ioctl ret val: %d (%s)",
							dest_eid, errno,
							strerror(errno));
					}
					usleep(MCTP_SMBUS_I2C_TX_RETRIES_US);
				} else {
					/* unknown error */
					MCTP_ERR(
						"[%d]Invalid ioctl ret val: %d (%s)",
						dest_eid, errno,
						strerror(errno));
					break;
				}
			}
		} while ((rc < 0) && (retry--));

		// free tx buffer
		free(buf);

		if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
			mctp_prerr("fail to do clock_gettime");
		}
		secs = end.tv_sec - start.tv_sec;
		nsecs = end.tv_nsec - start.tv_nsec;
		// adjust time
		if (nsecs < 0) {
			secs--;
			nsecs += 1000000000;
		}
		/* acquired the lock and sent the transcation */
		if (info->mux_grab && (rc >= 0)) {
			mctp_prinfo("[%d]Mux grabbed time: %d.%03d timeout %d",
				    dest_eid, secs, (nsecs + 500000) / 1000000,
				    info->timeout);

			clock_gettime(CLOCK_MONOTONIC, &tm);

			uint64_t t = tm.tv_sec * (uint64_t)1000000000L +
				     tm.tv_nsec + info->timeout * 1000000L;
			tm.tv_sec = t / 1000000000L;
			tm.tv_nsec = t % 1000000000L;

			rc = pthread_cond_timedwait(&cond_resp, &thread_mutex,
						    &tm);
			if (rc != 0) {
				if (rc != ETIMEDOUT) {
					mctp_prerr(
						"fail to pthread_cond_timedwait %d",
						rc);
				}
				mctp_prerr("%s: [%d] - resp timeout ", __func__,
					   dest_eid);

				uint16_t hold_timeout = 0; /* ms */
				struct i2c_msg msg = {
					.addr = 0,
					.flags = I2C_M_HOLD,
					.len = sizeof(hold_timeout),
					.buf = (uint8_t *)&hold_timeout,
				};
				struct i2c_rdwr_ioctl_data msgrdwr = { &msg,
								       1 };

				mctp_prinfo("Closing mux for EID: %d\n",
					    dest_eid);

				rc = ioctl(info->fd, I2C_RDWR, &msgrdwr);
				if (rc < 0) {
					mctp_prerr("failed to unlock bus");
				}
			}
		}
		// free tx info
		free(info);

		TAILQ_REMOVE(&head, entry, entries);
		pthread_mutex_unlock(&thread_mutex);
	}

	// clean up tx queue
	while (!TAILQ_EMPTY(&head)) {
		entry = TAILQ_FIRST(&head);
		info = (struct smbus_tx_thread_info *)entry->data;
		free(info->buf);
		free(info);
		TAILQ_REMOVE(&head, entry, entries);
	}
	pthread_exit(NULL);
}

int mctp_smbus_close_mux(struct mctp_binding_smbus *smbus, uint8_t eid);
/**
 * @brief Prepare i2c message from MCTP packet
 * 
 * @param[in] smbus - Struct mctp_binding_smbus
 * @param[in] len - Byte length of MCTP packet to send via i2c
 * @param[in] dest_eid - The destination EID
 * @param[in] dest_addr - The destination slave address
 * @return int > 0 - successfull, errno - failure.
 */
static int mctp_smbus_tx(struct mctp_binding_smbus *smbus, uint8_t len,
			 int dest_eid, int dest_addr)
{
	uint8_t *buf = malloc(len);
	if (buf == NULL) {
		MCTP_ERR("failed to malloc buffer");
	}
	memcpy(buf, smbus->txbuf_ptr, len);

	struct smbus_tx_thread_info *info =
		(struct smbus_tx_thread_info *)malloc(
			sizeof(struct smbus_tx_thread_info));

	struct mctp_hdr *hdr = (void *)(smbus->txbuf_ptr +
					sizeof(struct mctp_smbus_header_tx));

	info->mux_grab = false;
	if (hdr->flags_seq_tag & MCTP_HDR_FLAG_EOM) {
		info->mux_grab = true;
	}

	int out_fd = get_out_fd(smbus, dest_eid);
	mctp_prdebug("Tx Out FD: %d \n", out_fd);

	if (out_fd < 0) {
		MCTP_ERR("The dest eid is not supported on any SMBUS");
		return 0;
	}
	pthread_mutex_lock(&thread_mutex);
	info->eid = dest_eid;
	info->fd = out_fd;
	info->buf = buf;
	info->len = len;
	info->timeout = smbus->timeout;
	info->addr = dest_addr;

	struct qentry *node = malloc(sizeof(struct qentry));
	node->data = info;

	pthread_cond_signal(&cond);
	// add the buffer to tx queue
	TAILQ_INSERT_TAIL(&head, node, entries);
	pthread_mutex_unlock(&thread_mutex);

	return 0;
}

static int mctp_binding_smbus_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	mctp_prdebug("%s: Prepared MCTP packet\n", __func__);

	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	struct mctp_smbus_header_tx *hdr;
	size_t pkt_length = mctp_pktbuf_size(pkt);
	int rv, i;

	uint8_t *buf_ptr;
	uint8_t i2c_message_len;

	/* the length field in the header excludes smbus framing
	 * and escape sequences */
	hdr = (struct mctp_smbus_header_tx *)((uint8_t *)pkt->data);
	memset(hdr, 0, SMBUS_HDR_LENGTH);
	hdr->command_code = MCTP_COMMAND_CODE;
	hdr->byte_count = (uint8_t)pkt_length + 1;
	/* 8 bit address */
	hdr->source_slave_address = (smbus->src_slave_addr << 1) | 0x01;

	buf_ptr = (uint8_t *)hdr + sizeof(*hdr);
	smbus->txbuf_ptr = (uint8_t *)hdr;

	struct mctp_hdr *mctp_hdr = (struct mctp_hdr *)(buf_ptr);
	int dest_eid = mctp_hdr->dest;
	/* For SetEndpoint control command, fetch the EID from the data packet */
	if (dest_eid == 0) {
		uint8_t *mctp_body =
			(uint8_t *)(smbus->txbuf_ptr +
				    sizeof(struct mctp_smbus_header_tx) +
				    sizeof(struct mctp_hdr));
		if (mctp_body[0] == 0x00 && mctp_body[2] == 0x01) {
			dest_eid = mctp_body[4];
		}
	}
	int dest_addr = get_dest_i2c_addr(smbus, dest_eid);

	// Check if static endpoints support mctp, if no just drop send message
	for (i = 0; i < smbus->static_endpoints_len; i++) {
		if (smbus->static_endpoints[i].slave_address == dest_addr) {
			if (smbus->static_endpoints[i].support_mctp == 0) {
				mctp_prerr(
					"EID: %d, address: %d, bus: %d does not support MCTP, dropping packet\n",
					smbus->static_endpoints[i].endpoint_num,
					smbus->static_endpoints[i].slave_address,
					smbus->static_endpoints[i].bus_num);
				return 0;
			}
		}
	}

	buf_ptr = buf_ptr + pkt_length;
	*buf_ptr = calculate_pec_byte(smbus->txbuf_ptr,
				      sizeof(*hdr) + pkt_length,
				      (uint8_t)dest_addr, 0);

	//MCTP packet length of [ header, data, pec byte ]
	i2c_message_len = sizeof(*hdr) + pkt_length + SMBUS_PEC_BYTE_SIZE;

	rv = mctp_smbus_tx(smbus, i2c_message_len, dest_eid, dest_addr);
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

	(void)smbus;

	snprintf(filename, size,
		 "/sys/bus/i2c/devices/i2c-%d/%d-%04x/slave-mqueue", in_bus,
		 in_bus, SMBUS_ADDR_OFFSET_SLAVE | address_7_bit);

	mctp_prdebug("%s: Open: %s", __func__, filename);
	ret = open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (ret < 0) {
		mctp_prerr(
			"%s: Open syscall failed with rc %d (errno = %d, %s)",
			__func__, ret, errno, strerror(errno));
	}
	mctp_prdebug("%s: ret = : %d", __func__, ret);

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

	mctp_prdebug("%s: mqueue_size: %zu", __func__, mqueue_size);

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
	(void)smbus;

#if USE_MOCKED_DRIVERS
// Fuzz tests and UT require mocked smbus driver,
// this is instead of an mqueue or any other standard i2c
#define SMBUS_MOCKED_DRIVER "/dev/smbus"

	mctp_prdebug("%s: Open: %s, out bus = %d\n", __func__,
		     SMBUS_MOCKED_DRIVER, out_bus);
	int outfd =
		open(SMBUS_MOCKED_DRIVER, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (outfd < 0) {
		mctp_prerr(
			"%s: Open syscall failed with rc %d (errno = %d, %s)",
			__func__, rc, errno, strerror(errno));
	}
	mctp_prdebug("%s: ret = : %d\n", __func__, outfd);
	MCTP_ASSERT_RET(outfd >= 0, -1, "Failed to open I2C Tx node: %d",
			outfd);
	return outfd;
#else
	char filename[60];
	size_t size = sizeof(filename);

	snprintf(filename, size, "/dev/i2c-%d", out_bus);
	filename[size - 1] = '\0';

	mctp_prdebug("%s: open file: %s\n", __func__, filename);
	return open(filename, O_RDWR | O_NONBLOCK);
#endif
}

int mctp_smbus_close_mux(struct mctp_binding_smbus *smbus, uint8_t eid)
{
	uint16_t hold_timeout = 0; /* ms */
	struct i2c_msg msg = {
		.addr = 0,
		.flags = I2C_M_HOLD,
		.len = sizeof(hold_timeout),
		.buf = (uint8_t *)&hold_timeout,
	};
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg, 1 };
	int rc;
	(void)smbus;

	mctp_prdebug("Closing mux for EID: %d\n", eid);

	int out_fd = get_out_fd(smbus, eid);

	rc = ioctl(out_fd, I2C_RDWR, &msgrdwr);
	MCTP_ASSERT_RET(rc >= 0, rc, "Invalid ioctl ret val: %d (%s)", errno,
			strerror(errno));

	pthread_cond_signal(&cond_resp);
	return rc;
}

/*
 * Simple poll implementation for use
 */
int mctp_smbus_poll(struct mctp_binding_smbus *smbus)
{
	struct pollfd fds[1];
	int rc;
	const uint8_t n = sizeof(fds) / sizeof(struct pollfd);

	fds[0].fd = smbus->in_fd;
	fds[0].events = POLLPRI;

	rc = poll(fds, n, smbus->timeout);

	if (rc > 0) {
		if (fds[0].revents & POLLPRI) {
			// the response is received.
			return fds[0].revents;
		}
	}

	MCTP_ASSERT_RET(rc >= 0, -1, "SMBUS poll error status (errno=%d)",
			errno);

	return 0;
}

int send_get_udid_command(struct mctp_binding_smbus *smbus, size_t idx,
			  uint8_t *inbuf, uint8_t len)
{
	int rc;
	uint8_t outbuf[1] = { 0x03 }; // Set 'Get UDID' command
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data msgset[1];
	int slave_addr = MCTP_SMBUS_DEFAULT_GET_UDID_SLAVE_ADDRESS;

	if (smbus->out_fd[idx] < 0) {
		mctp_prdebug("%s: Out FD at %zu is not valid, skip.", __func__,
			     idx);
		return EXIT_FAILURE;
	}

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

	rc = ioctl(smbus->out_fd[idx], I2C_RDWR, &msgset);
	if (rc < 0) {
		MCTP_ERR("Invalid ioctl ret val: %d (%s)", errno,
			 strerror(errno));
		return EXIT_FAILURE;
	}

	mctp_prdebug("%s: TX and RX Get UDID command", __func__);
	mctp_trace_tx(outbuf, msgs[0].len);
	mctp_trace_rx(inbuf, msgs[1].len);

	return EXIT_SUCCESS;
}

int send_mctp_get_ver_support_command(struct mctp_binding_smbus *smbus,
				      uint8_t idx)
{
	int rc;
	int i = 0;
	// MCTP frame - Get MCTP version support
	uint8_t outbuf_mctp
		[12] = { 0x0f, 0x09, 0x31, 0x01, 0x00, 0x08, 0xc8,
			 0x00, 0x80, 0x04, 0x00, 0x00 /* PEC to calculate */ };
	struct i2c_msg msgs[1];
	struct i2c_rdwr_ioctl_data msgset[1];
	const uint8_t addr = smbus->static_endpoints[idx].slave_address;

	msgs[0].addr = addr;
	msgs[0].flags = 0;
	msgs[0].len = total_tab_elements(outbuf_mctp);
	msgs[0].buf = outbuf_mctp;

	outbuf_mctp[11] = calculate_pec_byte(outbuf_mctp,
					     sizeof(outbuf_mctp) - 1, addr, 0);

	msgset[0].msgs = msgs;
	msgset[0].nmsgs = 1;

	rc = ioctl(smbus->out_fd[idx], I2C_RDWR, &msgset);
	if (rc < 0) {
		MCTP_ERR("Invalid ioctl ret val: %d (%s)", errno,
			 strerror(errno));
		return EXIT_FAILURE;
	}

	mctp_prdebug("%s: TX Get MCTP version support command", __func__);
	mctp_trace_tx(outbuf_mctp, msgs[0].len);

	/* Wait for answer */
	while (1) {
		usleep(MCTP_SMBUS_READ_TIMEOUT_WAIT);
		rc = mctp_smbus_read_only(smbus);

		if (rc != -1) {
			if ((smbus->rxbuf[8] == MCTP_MESSAGE_TYPE_MCTP_CTRL) &&
			    (smbus->rxbuf[10] ==
			     MCTP_COMMAND_CODE_GET_MCTP_VERSION_SUPPORT)) {
				mctp_prdebug("%s: Received correct command",
					     __func__);
				break;
			}
		}
		i++;
		if (i >= MCTP_SMBUS_READ_TIMEOUT_REPEAT) {
			mctp_prdebug("%s: RX timeout", __func__);
			return EXIT_FAILURE;
		}
	}

	/* Check "Command Code" if a good response was received and
	 * "Completion Code", 0x00-support, 0x80-not support.
	 * See DSP0236 v1.3.0 sec. 12.6. Tab. 18
	 */
	if (smbus->rxbuf[10] == MCTP_COMMAND_CODE_GET_MCTP_VERSION_SUPPORT) {
		if (smbus->rxbuf[11] == MCTP_CONTROL_MSG_STATUS_SUCCESS) {
			smbus->static_endpoints[idx].support_mctp = 1;
			mctp_prdebug("%s: Message type number supported",
				     __func__);
		} else {
			mctp_prdebug(
				"%s: Message type number not supported (Completion Code = 0x%x)",
				__func__, smbus->rxbuf[11]);
			return EXIT_FAILURE;
		}
	} else {
		mctp_prdebug("%s: Received wrong Command Code", __func__);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int check_mctp_get_ver_support(struct mctp_binding_smbus *smbus, size_t idx,
			       uint8_t which_endpoint, uint8_t *inbuf,
			       uint8_t len)
{
	int rc;
	uint8_t interface_ASF = 0;
	uint8_t i;

	(void)which_endpoint;
	(void)len;

	if (smbus->out_fd[idx] < 0) {
		mctp_prdebug("%s: Out FD at %zu is not valid, skip.", __func__,
			     idx);
		return EXIT_FAILURE;
	}

	// Check ASF bit from UDID
	interface_ASF = inbuf[8];
	interface_ASF = (interface_ASF >> 5) & 0x01;

	if (interface_ASF != 0x01) {
		mctp_prdebug(
			"%s: ASF bit is not set, proceeding with MCTP version "
			"check anyway.",
			__func__);
	}

	for (i = 0; i < 16; i++) {
		smbus->static_endpoints[idx].udid[i] = inbuf[i + 1];
	}
	/* Get MCTP version support */
	rc = send_mctp_get_ver_support_command(smbus, idx);
	if (rc != 0) {
		mctp_prdebug("%s: Get MCTP version support failed!", __func__);
	}

	mctp_prdebug("\n%s: Static endpoint", __func__);
	mctp_prdebug("Endpoint = %d",
		     smbus->static_endpoints[idx].endpoint_num);
	mctp_prdebug("Slave address = 0x%x",
		     smbus->static_endpoints[idx].slave_address);
	mctp_prdebug("Support MCTP = %d",
		     smbus->static_endpoints[idx].support_mctp);
	mctp_prdebug("UDID = ");
	for (i = 0; i < 16; i++) {
		mctp_prdebug("0x%x ", smbus->static_endpoints[idx].udid[i]);
	}

	return EXIT_SUCCESS;
}

int find_and_set_pool_of_endpoints(struct mctp_binding_smbus *smbus)
{
	uint8_t inbuf[20] = { 0 };
	uint8_t inbuf_len = 19;
	uint8_t quantity_of_udid = 1; //at the moment only one CX7 card
	uint8_t i, slave_address;

	// TODO: Improve this function to get more UDID
	//       from other devices if are will be available
	send_get_udid_command(smbus, 0, inbuf, inbuf_len);
	// Get slave address from UDID
	slave_address = inbuf[17];
	slave_address = slave_address >> 1;

	for (i = 0; i < quantity_of_udid; i++) {
		mctp_prdebug("%d\n", i);
		smbus->static_endpoints[i].slave_address = slave_address;
	}

	return EXIT_SUCCESS;
}

int check_device_supports_mctp(struct mctp_binding_smbus *smbus)
{
	uint8_t inbuf[19] = { 0 };
	uint8_t inbuf_len = 19;

	for (size_t i = 0;
	     i < sizeof(smbus->bus_num) / sizeof(smbus->bus_num[0]); ++i) {
		if (smbus->bus_num[i] == 0xFF) {
			continue;
		}
		send_get_udid_command(smbus, i, inbuf, inbuf_len);
	}

	return EXIT_SUCCESS;
}

int mctp_smbus_read_only(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	int ret = 0;

	ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("%s: Failed to seek with rc %d (errno = %d, %s)",
			   __func__, ret, errno, strerror(errno));
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));

	if (len < 0) {
		mctp_prerr("Can't read from smbus device.");
		return -1;
	}

	mctp_trace_rx(smbus->rxbuf, len);

	return len;
}

int mctp_smbus_read(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	struct mctp_smbus_header_rx *hdr;
	struct mctp_hdr *mctp_hdr;
	bool eom;
	int ret = 0;

	ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("%s: Failed to seek with rc %d (errno = %d, %s)",
			   __func__, ret, errno, strerror(errno));
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));
	if (len < (ssize_t)sizeof(*hdr)) {
		// This condition hits from time to time, even with
		// a properly written poll loop, although it's not clear
		// why. Return an error so that the upper layer can
		// retry.
		return 0;
	}

	hdr = (void *)smbus->rxbuf;

	if (hdr->destination_slave_address !=
	    (MCTP_SMBUS_SOURCE_SLAVE_ADDRESS
	     << 1)) { // The recipient of the message is 'Src_slave_addr'
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
		mctp_prerr("Got smbus payload sized %d, expecting %zu",
			   hdr->byte_count, len - sizeof(*hdr));
		mctp_trace_rx(smbus->rxbuf, 255);
		return 0;
	}

	if (len < 0) {
		mctp_prerr("Can't read from smbus device.");
		return -1;
	}

	smbus->rx_pkt = mctp_pktbuf_alloc(&smbus->binding, 0);
	MCTP_ASSERT_RET(smbus->rx_pkt != NULL, -1,
			"Could not allocate pktbuf.");

	if (mctp_pktbuf_push(smbus->rx_pkt, &smbus->rxbuf[sizeof(*hdr)],
			     len - sizeof(*hdr) - SMBUS_PEC_BYTE_SIZE) != 0) {
		mctp_prerr("Can't push tok pktbuf.");
		return -1;
	}

	mctp_hdr = mctp_pktbuf_hdr(smbus->rx_pkt);
	eom = (mctp_hdr->flags_seq_tag & MCTP_HDR_FLAG_EOM) != 0;
	if (eom) {
		mctp_prinfo("Mux released\n");

		mctp_smbus_close_mux(smbus, mctp_hdr->src);
	}

	mctp_trace_rx(smbus->rxbuf, len);

	mctp_bus_rx(&smbus->binding, smbus->rx_pkt);
	smbus->rx_pkt = NULL;

	return ret;
}

/*
 * Returns generic binder handler from SMBus binding handler
 */
struct mctp_binding *mctp_binding_smbus_core(struct mctp_binding_smbus *smbus)
{
	return &smbus->binding;
}

int mctp_smbus_init_pollfd(struct mctp_binding_smbus *smbus,
			   struct pollfd **pollfd)
{
	const uint8_t fds_num = 1;
	*pollfd = __mctp_alloc(fds_num * sizeof(struct pollfd));
	(*pollfd)->fd = smbus->in_fd;
	(*pollfd)->events = POLLPRI;

	return fds_num;
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
	int outfd = -1;

	MCTP_ASSERT_RET(smbus != NULL, -1, "Invalid binding private data.");

	mctp_prdebug("%s: Set param: %lu, %hhu, %hhu", __func__, smbus->bus_id,
		     smbus->bus_num_smq, smbus->dest_slave_addr[0]);

#if USE_MOCKED_DRIVERS
	// With mocked drivers we have only one driver,
	//  used for both directions for sending and receiving
	//  i2c data.
	smbus->static_endpoints_len = 1;
#endif

	/* Open all applicable I2C nodes */
	for (uint8_t i = 0; i < smbus->static_endpoints_len; ++i) {
		if (smbus->static_endpoints[i].bus_num == 0xFF) {
			continue;
		}
		/* Check if we have already opened the fd before */
		for (uint8_t j = 0; i > 0 && j < i; ++j) {
			if (smbus->static_endpoints[j].bus_num ==
			    smbus->static_endpoints[i].bus_num) {
				mctp_prdebug("%s: Reusing I2C output fd",
					     __func__);
				smbus->out_fd[i] = smbus->out_fd[j];
				break;
			}
		}
		if (smbus->out_fd[i] == -1) {
			mctp_prdebug("%s: Setting up I2C output fd", __func__);
			outfd = mctp_smbus_open_out_bus(smbus,
							smbus->bus_num[i]);
			if (outfd >= 0) {
				smbus->out_fd[i] = outfd;
				smbus->static_endpoints[i].out_fd = outfd;
			} else {
				MCTP_ERR(
					"Failed to open I2C Tx node /dev/i2c-%d, errno: %d",
					smbus->bus_num[i], errno);
			}
		}
	}

	/* Open default i2c node for non-static endpoints */
	if ((smbus->static_endpoints_len == 0) && (outfd == -1)) {
		mctp_prdebug("%s: Setting up I2C output fd", __func__);
		outfd = mctp_smbus_open_out_bus(smbus, smbus->bus_num[0]);
		MCTP_ASSERT_RET(outfd >= 0, -1,
				"Failed to open I2C Tx node: %d", outfd);
		smbus->out_fd[0] = outfd;
	}

	/* Open I2C in node */
	mctp_prdebug("%s: Setting up I2C input fd: %d %d", __func__,
		     smbus->bus_num_smq, smbus->dest_slave_addr[0]);
	smbus->in_fd = mctp_smbus_open_in_bus(smbus, smbus->bus_num_smq,
					      smbus->src_slave_addr);

#if USE_MOCKED_DRIVERS
	smbus->in_fd = smbus->out_fd[0];
#endif

	MCTP_ASSERT_RET(smbus->in_fd >= 0, -1, "Failed to open I2C Rx node: %d",
			smbus->in_fd);

	/* Enable Tx */
	mctp_binding_set_tx_enabled(b, true);

	return 0;
}

struct mctp_binding_smbus *
mctp_smbus_init(uint8_t bus, uint8_t bus_smq, uint8_t dest_addr,
		uint8_t src_addr, uint16_t timeout,
		uint8_t static_endpoints_len,
		struct mctp_static_endpoint_mapper *static_endpoints)
{
	struct mctp_binding_smbus *smbus;

	smbus = __mctp_alloc(sizeof(*smbus));
	memset(&(smbus->binding), 0, sizeof(smbus->binding));

	smbus->in_fd = -1;
	memset(smbus->out_fd, -1, sizeof(smbus->out_fd));

	smbus->rx_pkt = NULL;
	smbus->binding.name = "smbus";
	smbus->binding.version = 1;
	smbus->binding.mctp_send_tx_queue = NULL;

	smbus->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	smbus->binding.pkt_header = SMBUS_HDR_LENGTH;
	smbus->binding.pkt_trailer = SMBUS_PAD_LENGTH;
	smbus->binding.pkt_priv_size = sizeof(struct mctp_smbus_pkt_private);

	/* Setting the default bus number */
	smbus->bus_num[0] = bus;
	smbus->bus_num_smq = bus_smq;
	/* Setting the default destination and source slave address */
	smbus->dest_slave_addr[0] = dest_addr;
	smbus->src_slave_addr = src_addr;

	/* Setting I2C MUX timeout for hold or unload message */
	if (timeout == 0) {
		timeout = MCTP_SMBUS_I2C_M_HOLD_TIMEOUT_MS;
	}
	smbus->timeout = timeout;

	/* Override slave addresses and bus numbers if static endpoints are used */
	smbus->static_endpoints_len = static_endpoints_len;
	smbus->static_endpoints = static_endpoints;
	for (uint8_t i = 0; i < static_endpoints_len; ++i) {
		smbus->dest_slave_addr[i] = static_endpoints[i].slave_address;
		smbus->bus_num[i] = static_endpoints[i].bus_num;
	}

	smbus->binding.start = mctp_smbus_start;
	smbus->binding.tx = mctp_binding_smbus_tx;

	TAILQ_INIT(&head);
	pthread_condattr_t condattr;
	pthread_condattr_init(&condattr);
	pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
	pthread_cond_init(&cond_resp, &condattr);

	if (pthread_create(&tx_thread, NULL, smbus_tx_thread, NULL) != 0) {
		MCTP_ERR("failed to pthread_create\n");
	}
	return smbus;
}

void mctp_smbus_free(struct mctp_binding_smbus *smbus)
{
	terminate_tx_thread = true;
	pthread_cond_destroy(&cond);
	pthread_cond_destroy(&cond_resp);
	__mctp_free(smbus);
}
