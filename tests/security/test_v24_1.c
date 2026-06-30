/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding V24.1
 *   NVBug 6295108, CWE-787 (Out-of-bounds Write), utils/mctp-tun.c::tun_read()
 *
 * THE BUG
 * -------
 * tun_read() reads a frame from the tun fd into a fixed 64 KiB staging buffer
 * (tun->tun_buf, sized tun_buf_size = MAX_MTU = 64*1024) via readv(), strips
 * the 4-byte tun_pi header, then does:
 *
 *     rlen -= sizeof(tun_pi);
 *     pkt = mctp_pktbuf_alloc(&tun->binding, rlen);
 *     memcpy(mctp_pktbuf_hdr(pkt), tun->tun_buf, rlen);
 *
 * mctp_pktbuf_alloc() ignores the requested `rlen` when SIZING the buffer: it
 * allocates from the binding's FIXED pkt_size:
 *     size = pkt_size + pkt_header + pkt_trailer
 * For the tun binding pkt_size = MCTP_PACKET_SIZE(32*1024) = 32772, header = 4,
 * trailer = 4, so data[] is 32780 bytes and the writable region returned by
 * mctp_pktbuf_hdr() (data + mctp_hdr_off, mctp_hdr_off == pkt_header == 4) is
 * 32780 - 4 = 32776 bytes. The memcpy then copies `rlen` bytes there with NO
 * upper bound, and it does NOT go through mctp_pktbuf_push()'s bounds check.
 *
 * A frame whose post-header payload exceeds 32776 but is <= 64 KiB therefore
 * overflows the heap allocation -> attacker-controlled heap-buffer-overflow
 * WRITE driven straight from /dev/net/tun.
 *
 * THE FIX (utils/mctp-tun.c, between the subtraction and the alloc/memcpy)
 *     if ((size_t)rlen > tun->binding.pkt_size) {
 *         mctp_prerr("tun frame too large (%zd > %zu)", rlen,
 *                    tun->binding.pkt_size);
 *         return -1;
 *     }
 * pkt_size (32772) is a slightly tighter (hence safe) bound than the true
 * 32776-byte capacity, so the oversized frame is rejected before the memcpy.
 *
 * A/B METHOD
 * ----------
 * This test drives the REAL static tun_read() by #include'ing the translation
 * unit (utils/mctp-tun.c). mctp-tun.c's own main() is renamed away across the
 * #include only (#define main ... / #undef main) so this file supplies main().
 *
 *   - Built against the CURRENT (fixed) source under ASan: tun_read() returns
 *     -1 for the oversized frame and the test PASSES (no overflow).
 *   - Built against a scratch copy with ONLY the clamp reverted: the memcpy
 *     runs and ASan aborts with a heap-buffer-overflow WRITE.
 *
 * The transport is a real pipe(2): we write
 *     [4-byte tun_pi | OVERSIZE-byte payload]
 * into the write end, point tun->tun_fd at the read end, and call tun_read().
 * readv() with iovec [tun_pi, tun_buf] de-frames it exactly like the daemon.
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
#include <endian.h>
#include <linux/if_tun.h> /* struct tun_pi */
#include "libmctp-usb.h"

/*
 * Pull in the real daemon translation unit so we can reach the static
 * tun_read() plus the private struct ctx / struct mctp_binding_raw and the
 * mctp_tun_init() helper. Its main() is neutralised by renaming it across the
 * #include only, so this file's own main() below is untouched. MAX_MTU lives in
 * there as a file-scope const we reuse below. Core-26.05's disabled mctp-tun
 * utility still carries the obsolete four-argument USB-init call; replace that
 * unreachable call while compiling this focused tun_read() test so the test
 * exercises only the code path under review.
 */
#define mctp_usb_init(...) ((struct mctp_binding_usb *)NULL)
#define main tun_main_unused
#include "../../utils/mctp-tun.c"
#undef main
#undef mctp_usb_init

/*
 * mctp-tun.c's (now-renamed, never-called) tun_main_unused() references the USB
 * binding symbols, which live in usb.c -> libusb-1.0, not built in this sandbox
 * and irrelevant to tun_read(). Provide unreachable stubs purely to satisfy the
 * linker. None of these is ever executed by this test.
 */
struct mctp_binding *mctp_binding_usb_core(struct mctp_binding_usb *usb
					   __attribute__((unused)))
{
	return NULL;
}
int mctp_usb_init_pollfd(struct mctp_binding_usb *usb __attribute__((unused)),
			 struct pollfd **pollfds __attribute__((unused)))
{
	return 0;
}
int mctp_usb_handle_event(struct mctp_binding_usb *usb __attribute__((unused)))
{
	return 0;
}

/* Payload size for the malicious frame: strictly greater than the tun binding
 * pkt_size (MCTP_PACKET_SIZE(32*1024) = 32772) and <= MAX_MTU (64 KiB), so it
 * fits the 64 KiB staging buffer but overflows the fixed pktbuf allocation. */
#define OVERSIZE_PAYLOAD 40000

/* mctp_bus_rx() takes ownership of the pkt and frees it; in bridge-less
 * standalone use here the binding has no bus, so we never actually reach
 * delivery on the fixed path (we return -1 first). To be safe against any
 * future code path, give the binding a no-op tx and a registered core. */
static int probe_tx(struct mctp_binding *b __attribute__((unused)),
		    struct mctp_pktbuf *pkt __attribute__((unused)))
{
	return 0;
}

static void test_v24_1_tun_read_oversize_frame(void)
{
	struct ctx _ctx;
	struct ctx *ctx = &_ctx;
	struct mctp_binding_raw *tun;
	struct tun_pi pi;
	uint8_t *payload;
	uint8_t *frame;
	size_t frame_len;
	int pipefd[2];
	ssize_t wlen;
	int rc;
	size_t cap;

	memset(ctx, 0, sizeof(*ctx));

	/* Build the tun binding exactly as the daemon's mctp_tun_init() does:
	 * pkt_size = MCTP_PACKET_SIZE(32*1024), pkt_header = pkt_trailer = 4. */
	tun = mctp_tun_init();
	assert(tun);
	tun->binding.tx = probe_tx;

	/* The capacity actually writable at mctp_pktbuf_hdr() for this binding,
	 * to make the precondition of the test explicit and self-checking. */
	cap = (tun->binding.pkt_size + tun->binding.pkt_header +
	       tun->binding.pkt_trailer) -
	      tun->binding.pkt_header;
	printf("  tun pkt_size=%zu writable-at-hdr=%zu payload=%d MAX_MTU=%zu\n",
	       tun->binding.pkt_size, cap, OVERSIZE_PAYLOAD, MAX_MTU);

	/* Precondition for a *meaningful* A/B test: the payload must overflow
	 * the real buffer (else there is nothing for the fix to prevent) yet
	 * still fit the staging buffer (else readv truncates before the bug). */
	assert((size_t)OVERSIZE_PAYLOAD > cap);
	assert((size_t)OVERSIZE_PAYLOAD > tun->binding.pkt_size);
	assert((size_t)OVERSIZE_PAYLOAD <= MAX_MTU);

	/* 64 KiB staging buffer, same as main(). */
	tun->tun_buf_size = MAX_MTU;
	tun->tun_buf = malloc(tun->tun_buf_size);
	assert(tun->tun_buf);

	/* readv() source: read end of a pipe holding one framed packet. */
	rc = pipe(pipefd);
	assert(rc == 0);
	tun->tun_fd = pipefd[0];
	ctx->tun = tun;

	/* Frame = tun_pi(proto = ETH_P_MCTP) + OVERSIZE_PAYLOAD bytes. The
	 * proto must be ETH_P_MCTP or tun_read() drops it early (returns 0). */
	memset(&pi, 0, sizeof(pi));
	pi.flags = 0;
	pi.proto = htobe16(ETH_P_MCTP);

	frame_len = sizeof(pi) + OVERSIZE_PAYLOAD;
	frame = malloc(frame_len);
	assert(frame);
	memcpy(frame, &pi, sizeof(pi));
	payload = frame + sizeof(pi);
	memset(payload, 0x5a, OVERSIZE_PAYLOAD); /* recognizable fill */

	/* A pipe write of <= PIPE_BUF (4096) is atomic; ours is larger, but we
	 * are the only writer and there is room (pipe capacity is 64 KiB on
	 * Linux), and tun_read() issues a single readv that drains it. */
	wlen = write(pipefd[1], frame, frame_len);
	assert(wlen == (ssize_t)frame_len);

	/*
	 * Drive the REAL function.
	 *
	 * FIXED source  : the clamp `rlen > pkt_size` trips, tun_read() logs
	 *                 "tun frame too large" and returns -1. No memcpy, no
	 *                 overflow -> we land here and assert rc == -1.
	 *
	 * PRE-FIX source: no clamp, so mctp_pktbuf_alloc(rlen=40000) returns a
	 *                 buffer sized for only 32776 bytes at the hdr offset and
	 *                 the subsequent memcpy(..., 40000) writes 40000 bytes
	 *                 into it -> ASan aborts HERE with
	 *                 "heap-buffer-overflow ... WRITE of size ..." and the
	 *                 process exits non-zero before reaching the asserts.
	 */
	rc = tun_read(ctx);

	/* Only reached on the FIXED tree. */
	assert(rc == -1);
	printf("  tun_read() rejected oversize frame (rc=%d) - no overflow\n",
	       rc);

	free(frame);
	free(tun->tun_buf);
	close(pipefd[0]);
	close(pipefd[1]);
	__mctp_free(tun);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	printf("test: test_v24_1_tun_read_oversize_frame\n");
	test_v24_1_tun_read_oversize_frame();

	printf("V24.1 security regression test passed "
	       "(tun_read clamps oversized frames)\n");
	return EXIT_SUCCESS;
}
