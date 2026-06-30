/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding V3.1
 * (NVBug 6294887, CWE-191 integer underflow), smbus.c.
 *
 * Vulnerability
 * -------------
 * mctp_smbus_read() reads an SMBus frame into smbus->rxbuf and, after the
 * header sanity checks, pushes the MCTP payload into a freshly allocated
 * pktbuf with:
 *
 *     mctp_pktbuf_push(rx_pkt, &rxbuf[sizeof(*hdr)],
 *                      len - sizeof(*hdr) - SMBUS_PEC_BYTE_SIZE);
 *
 * sizeof(*hdr) == 4 (struct mctp_smbus_header_rx) and SMBUS_PEC_BYTE_SIZE == 1.
 * A 4-byte frame (len == 4) passes the existing checks:
 *   - len < sizeof(*hdr)            -> 4 < 4  == false
 *   - byte_count != len-sizeof(hdr) -> set byte_count = 0, 0 != 0 == false
 * so the push length becomes (size_t)(4 - 4 - 1) == SIZE_MAX. mctp_pktbuf_push
 * computes pkt->end + SIZE_MAX, which wraps below pkt->size, bypassing its
 * bounds check, and then runs memcpy(p, data, SIZE_MAX) -> unbounded copy
 * (heap-buffer-overflow).
 *
 * Fix (smbus.c, ~line 955)
 * ------------------------
 *     if ((size_t)len <= sizeof(*hdr) + SMBUS_PEC_BYTE_SIZE) {
 *         mctp_prerr("SMBus frame too short: len=%zd", (ssize_t)len);
 *         return 0;
 *     }
 *
 * A/B method
 * ----------
 * This file is compiled with `#include "../../smbus.c"` so it can see the
 * private struct mctp_binding_smbus and drive the *real* mctp_smbus_read():
 *   - it builds a binding, registers a bus, points smbus->in_fd at the read
 *     end of a pipe, writes the malformed 4-byte frame into the pipe, and
 *     calls mctp_smbus_read(smbus).
 *   - On the FIXED tree the short-frame guard fires, mctp_smbus_read() returns
 *     0, no pktbuf is allocated and no memcpy runs: the test passes cleanly
 *     under AddressSanitizer.
 *   - On the PRE-fix tree (guard reverted) the SIZE_MAX-length memcpy in
 *     mctp_pktbuf_push faults under AddressSanitizer (heap-buffer-overflow).
 *
 * Build (sandbox, dedicated source compile -- cannot link the full libmctp
 * because smbus.c is #included here; pass only core.c alloc.c log.c):
 *
 *   gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer \
 *       -I<scratch> -I. -Itests \
 *       tests/security/test_v3_1.c core.c alloc.c log.c -o t
 *   ASAN_OPTIONS=detect_leaks=0 ./t
 */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Pull in the real binding implementation so we can reach the private
 * struct mctp_binding_smbus and the real mctp_smbus_read(). Because smbus.c
 * is included here, it must NOT also be passed on the compiler command line. */
#include "../../smbus.c"

/* SMBus wire constants, mirrored from smbus.c so the malformed frame is built
 * against the values the code under test actually checks. */
#define SEC_DEST_ADDR (MCTP_SMBUS_SOURCE_SLAVE_ADDRESS << 1) /* 0x18<<1=0x30 */
#define SEC_CMD_CODE  MCTP_COMMAND_CODE			     /* 0x0F */

/* mctp_bus_rx delivers fully reassembled messages here; for the V3.1 frame the
 * fixed code never reaches delivery (the guard drops the short frame). */
static int g_rx_msgs;
static void sec_rx_message(uint8_t eid __attribute__((unused)),
			   bool tag_owner __attribute__((unused)),
			   uint8_t msg_tag __attribute__((unused)),
			   void *data __attribute__((unused)),
			   void *msg __attribute__((unused)),
			   size_t len __attribute__((unused)))
{
	g_rx_msgs++;
}

/*
 * Build a minimal-but-real SMBus binding without mctp_smbus_init() (which
 * spawns the tx worker thread and opens real i2c fds). We only need the fields
 * mctp_smbus_read() and mctp_bus_rx() touch: the binding vtable/sizes, an
 * in_fd to read() from, and a registered bus.
 */
static void sec_smbus_init(struct mctp_binding_smbus *smbus, struct mctp *mctp,
			   int in_fd)
{
	memset(smbus, 0, sizeof(*smbus));

	smbus->in_fd = in_fd;
	smbus->rx_pkt = NULL;

	/* Identical framing parameters to mctp_smbus_init(): a 4-byte SMBus
	 * header (pkt_header) and 1-byte PEC trailer (pkt_trailer) around an
	 * MCTP_BTU body. These drive mctp_pktbuf_alloc()'s buffer size. */
	smbus->binding.name = "smbus-sec";
	smbus->binding.version = 1;
	smbus->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	smbus->binding.pkt_header = SMBUS_HDR_LENGTH;
	smbus->binding.pkt_trailer = SMBUS_PAD_LENGTH;
	smbus->binding.pkt_priv_size = sizeof(struct mctp_smbus_pkt_private);
	smbus->binding.tx = mctp_binding_smbus_tx;

	/* A registered bus is required: mctp_bus_rx() asserts binding->bus. */
	mctp_smbus_register_bus(smbus, mctp, 8);
}

/*
 * V3.1: a 4-byte SMBus frame that satisfies every pre-existing header check
 * yet underflows the push length to SIZE_MAX on the pre-fix tree.
 *
 * Frame layout = struct mctp_smbus_header_rx (4 bytes, no MCTP body, no PEC):
 *   [0] destination_slave_address = MCTP_SMBUS_SOURCE_SLAVE_ADDRESS<<1 (0x30)
 *   [1] command_code              = MCTP_COMMAND_CODE (0x0F)
 *   [2] byte_count                = 0   (so byte_count == len-sizeof(hdr) == 0)
 *   [3] source_slave_address      = 0x18 (unchecked)
 *
 * No EOM flag is involved (there is no MCTP header at all), so the fixed path
 * does not touch the i2c mux / ioctl.
 */
static void test_v3_1_smbus_read_len_underflow(void)
{
	struct mctp_binding_smbus smbus;
	struct mctp *mctp;
	int pipefd[2];
	int rc;
	const uint8_t frame[4] = {
		SEC_DEST_ADDR, /* destination_slave_address */
		SEC_CMD_CODE,  /* command_code              */
		0x00,	       /* byte_count == 0           */
		0x18,	       /* source_slave_address      */
	};
	ssize_t w;

	/* mctp_smbus_read() lseek(SEEK_SET)s then read()s in_fd. A pipe is not
	 * seekable, so lseek returns -1 and mctp_smbus_read returns early before
	 * the read(). Use a real temp file (in the writable scratch dir) so the
	 * seek+read path -- and the vulnerable push below it -- is exercised. */
	(void)pipefd;

	mctp = mctp_init();
	assert(mctp);
	mctp_set_rx_all(mctp, sec_rx_message, NULL);

	/* Seekable backing fd holding exactly the 4-byte malformed frame
	 * (mctp_smbus_read() lseek()s in_fd, so a pipe won't do). */
	char tmpl[] = "/tmp/mctp_v3_1_frame.XXXXXX";
	int fd = mkstemp(tmpl);
	assert(fd >= 0);
	unlink(tmpl); /* keep the fd, drop the name */
	w = write(fd, frame, sizeof(frame));
	assert(w == (ssize_t)sizeof(frame));
	rc = (int)lseek(fd, 0, SEEK_SET);
	assert(rc == 0);

	sec_smbus_init(&smbus, mctp, fd);

	/*
	 * Drive the real vulnerable function with the malformed frame.
	 *
	 * FIXED tree: the short-frame guard fires, returns 0, allocates no
	 *             pktbuf and runs no memcpy.
	 * PRE-fix tree: push length underflows to SIZE_MAX and the memcpy in
	 *             mctp_pktbuf_push faults here under AddressSanitizer.
	 */
	rc = mctp_smbus_read(&smbus);

	/* Post-fix assertions: the frame was rejected as too short, nothing was
	 * delivered up the stack, and no rx pktbuf was left allocated. */
	assert(rc == 0);
	assert(g_rx_msgs == 0);
	assert(smbus.rx_pkt == NULL);

	close(fd);
	mctp_destroy(mctp);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	printf("test: test_v3_1_smbus_read_len_underflow\n");
	test_v3_1_smbus_read_len_underflow();

	printf("V3.1 security regression test passed\n");
	return EXIT_SUCCESS;
}
