/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding V20.1
 *   NVBug 6295098, CWE-125 (Out-of-bounds Read), mctp-socket.c
 *   ::mctp_client_recv_from_eid()
 *
 * THE BUG
 * -------
 * mctp_client_recv_from_eid() receives a response into a caller-freed buffer
 * via mctp_recv(). Under MCTP_IN_KERNEL, mctp_recv() peeks the datagram length
 * with recv(MSG_PEEK|MSG_TRUNC), malloc()s `bufLen + 1`, writes the message at
 * offset 1 (byte 0 is the MCTP message type), and sets *resp_msg_len = bufLen+1.
 * It admits datagrams as small as a single byte.
 *
 * mctp_client_recv_from_eid() then casts the buffer at offset 1 to an 8-byte
 * `struct mctp_vendor_msg_hdr` and dereferences command_code:
 *
 *     resp = (struct mctp_vendor_msg_hdr *)(*mctp_resp_msg + 1);
 *     ... cmd_code == resp->command_code ...
 *
 * struct mctp_vendor_msg_hdr is { u32 iana; u8 rq_dgram_inst; u8 vendor_msg_type;
 * u8 command_code; u8 msg_version; } packed, so command_code sits at struct
 * offset 6 -> buffer offset 7. For a short (e.g. 3-byte) response the allocation
 * is only 4 bytes, so reading offset 7 is a 3-byte out-of-bounds heap READ
 * driven straight from whatever the demux/socket delivered.
 *
 * THE FIX (mctp-socket.c, just before the cast)
 *     if (*resp_msg_len < 1 + sizeof(struct mctp_vendor_msg_hdr)) {
 *         free(*mctp_resp_msg);
 *         *mctp_resp_msg = NULL;
 *         return MCTP_REQUESTER_INVALID_RECV_LEN;
 *     }
 * A response too short to contain [msg_type][vendor_msg_hdr] is rejected before
 * the struct is ever dereferenced.
 *
 * A/B METHOD
 * ----------
 * This test drives the REAL static mctp_client_recv_from_eid() by #include'ing
 * the translation unit (mctp-socket.c). That file has no main(), so nothing
 * needs to be renamed away; this file supplies main().
 *
 *   - Built against the CURRENT (fixed) source under ASan: the short response is
 *     rejected with MCTP_REQUESTER_INVALID_RECV_LEN, *mctp_resp_msg is NULL and
 *     freed, and the test PASSES (no OOB read).
 *   - Built against a scratch copy with ONLY the length guard reverted: the cast
 *     reads command_code at buffer offset 7 of a 4-byte allocation and ASan
 *     aborts with "heap-buffer-overflow ... READ of size 1".
 *
 * The transport is a real socketpair(AF_UNIX, SOCK_DGRAM): we write a 3-byte
 * datagram into one end and point mctp_fd at the other. mctp_recv()'s
 * recv(MSG_PEEK|MSG_TRUNC) + recvfrom(MSG_TRUNC) de-frames it exactly like the
 * AF_MCTP datagram socket the daemon uses (datagram boundaries + truncation
 * semantics are identical for AF_UNIX SOCK_DGRAM). A short SO_RCVTIMEO is set on
 * the read end and the write end is closed so the FIXED path (which returns
 * without re-reading) cannot block; the PRE-FIX path faults on the very first
 * iteration, before any re-read.
 *
 * This file is compiled WITH `#include "../../mctp-socket.c"`, so mctp-socket.c
 * must NOT also be passed on the compiler command line. mctp_client_send() etc.
 * inside that unit reference no json-c / libusb symbols on the recv path; only
 * log.c (mctp_prlog / mctp_trace_common) is needed at link time.
 */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

/*
 * The host's <linux/mctp.h> may predate extended addressing. mctp-socket.c's
 * (off-path) mctp_client_send_ext() needs sockaddr_mctp_ext / SOL_MCTP /
 * MCTP_OPT_ADDR_EXT. When building in the sandbox these are supplied by a
 * force-included compat shim (-include .sec-v20_1/mctp_uapi_compat.h); under the
 * project's meson build the real UAPI provides them. Nothing on the function
 * under test (mctp_client_recv_from_eid -> mctp_recv) touches them.
 */

/*
 * Pull in the real translation unit so we can reach the static
 * mctp_client_recv_from_eid() and the MCTP_IN_KERNEL mctp_recv() path. The unit
 * has no main(), so no renaming is required.
 */
#ifndef MCTP_IN_KERNEL
#define MCTP_IN_KERNEL 1
#endif
#include "../../mctp-socket.c"

/* Core-26.05's in-kernel socket path obtains direct-address information from
 * these netlink-owned globals. The receive-only path under test never reads
 * them, but the included translation unit still requires definitions. */
struct g_interface_data local_interface;
struct g_hw_info endpoint_hwinfo;

/* A response shorter than [msg_type(1)] + sizeof(struct mctp_vendor_msg_hdr).
 * 3 bytes -> mctp_recv() allocates 4 bytes; command_code lives at buffer
 * offset 7, i.e. 3 bytes past the end -> the OOB the fix prevents. */
#define SHORT_RESP_LEN 3

static void test_v20_1_recv_short_vendor_response(void)
{
	int sv[2];
	uint8_t shortpkt[SHORT_RESP_LEN] = { 0x7f, 0x01, 0x02 };
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	const mctp_eid_t eid = 9;
	const uint8_t cmd_code = MCTP_VENDOR_CMD_QUERYBOOTSTATUS;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	mctp_requester_rc_t rc;
	ssize_t wlen;
	int srv;

	/* Make the precondition explicit and self-checking: the response is too
	 * short to hold [msg_type][vendor_msg_hdr], so command_code (buffer
	 * offset 7) lands past the malloc(SHORT_RESP_LEN + 1) allocation. */
	assert((size_t)SHORT_RESP_LEN + 1 <
	       1 + sizeof(struct mctp_vendor_msg_hdr));
	printf("  resp bytes=%d alloc=%d vendor_hdr=%zu command_code@buf_off=%zu\n",
	       SHORT_RESP_LEN, SHORT_RESP_LEN + 1,
	       sizeof(struct mctp_vendor_msg_hdr),
	       1 + offsetof(struct mctp_vendor_msg_hdr, command_code));

	srv = socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	assert(srv == 0);

	/* Short read timeout on the consumer end: the FIXED path returns without
	 * re-reading, but if any future code re-reads we time out instead of
	 * blocking the test forever. */
	srv = setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	assert(srv == 0);

	/* Deliver one short datagram, then close the writer so a second
	 * recv(MSG_PEEK|MSG_TRUNC) sees EOF/empty rather than blocking. */
	wlen = write(sv[1], shortpkt, sizeof(shortpkt));
	assert(wlen == (ssize_t)sizeof(shortpkt));
	close(sv[1]);

	/*
	 * Drive the REAL function.
	 *
	 * FIXED source  : *resp_msg_len (== 4) < 1 + sizeof(vendor_msg_hdr)
	 *                 (== 9), so the guard frees the buffer, NULLs it, and
	 *                 returns MCTP_REQUESTER_INVALID_RECV_LEN. We land below.
	 *
	 * PRE-FIX source: no guard, so `resp = buf + 1` is cast to the 8-byte
	 *                 vendor header and `resp->command_code` reads buffer
	 *                 offset 7 of a 4-byte allocation -> ASan aborts HERE with
	 *                 "heap-buffer-overflow ... READ of size 1" before the
	 *                 process can reach the asserts below.
	 */
	rc = mctp_client_recv_from_eid(eid, sv[0], cmd_code, &resp, &resp_len);

	/* Only reached on the FIXED tree. */
	assert(rc == MCTP_REQUESTER_INVALID_RECV_LEN);
	assert(resp == NULL); /* fix frees and NULLs the short buffer */
	printf("  mctp_client_recv_from_eid() rejected short response (rc=%d) - no OOB read\n",
	       rc);

	/* Defensive: if a non-fixed build somehow returned SUCCESS without
	 * faulting, the buffer would be live and shorter than the header. */
	if (rc == MCTP_REQUESTER_SUCCESS)
		free(resp);

	close(sv[0]);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	printf("test: test_v20_1_recv_short_vendor_response\n");
	test_v20_1_recv_short_vendor_response();

	printf("V20.1 security regression test passed "
	       "(mctp_client_recv_from_eid rejects short vendor responses)\n");
	return EXIT_SUCCESS;
}
