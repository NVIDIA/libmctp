/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression tests for the libmctp Glasswing findings.
 *
 * Each test drives the *real* fixed code path with the exact malformed /
 * adversarial input from the finding and asserts the post-fix behaviour.
 * The tests are written to fault on the PRE-fix code: run the suite under
 * AddressSanitizer (meson setup -Db_sanitize=address) and they abort on an
 * unfixed tree (use-after-free / out-of-bounds), while passing cleanly on the
 * fixed tree. See tests/security/UNIT-TESTING-AB-REGRESSIONS.md for the
 * per-finding test rationale and reproduction instructions.
 *
 * Covered here (findings that live in libmctp.so and are drivable through the
 * public core API):
 *   - V1.1  (NVBug 6294880, CWE-416) reassembly realloc-fail use-after-free
 *
 * The remaining findings live in separate executables (ctrld / vdm-util /
 * mctp-socket / demux) or in a build-disabled module (mctp-tun) and are not
 * reachable through this libmctp unit harness; they have dedicated
 * source-compile A/B tests under tests/security/ (see
 * tests/security/UNIT-TESTING-AB-REGRESSIONS.md for the per-test AddressSanitizer
 * build/run recipes and the embedded pass/fail evidence).
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

#include <libmctp.h>
#include <libmctp-alloc.h>
#include <libmctp-log.h>

#include "test-utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* ------------------------------------------------------------------ */
/* shared minimal binding                                             */
/* ------------------------------------------------------------------ */

struct sec_binding {
	struct mctp_binding binding;
	int tx_count;
	uint8_t last_src;
	uint8_t last_dest;
};

static int sec_binding_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct sec_binding *sb = container_of(b, struct sec_binding, binding);
	struct mctp_hdr *hdr = mctp_pktbuf_hdr(pkt);

	sb->tx_count++;
	sb->last_src = hdr->src;
	sb->last_dest = hdr->dest;
	return 0;
}

static void sec_binding_init(struct sec_binding *sb, size_t body)
{
	memset(sb, 0, sizeof(*sb));
	sb->binding.name = "sec";
	sb->binding.version = 1;
	sb->binding.tx = sec_binding_tx;
	sb->binding.pkt_size = MCTP_PACKET_SIZE(body);
	sb->binding.pkt_header = 0;
	sb->binding.pkt_trailer = 0;
}

/* Inject a fully-formed packet straight into the core RX path, exactly as a
 * binding would after de-framing a wire packet. */
static void rx_frame(struct mctp_binding *b, uint8_t dest, uint8_t src,
		     uint8_t flags_seq_tag, const uint8_t *payload, size_t plen)
{
	size_t framelen = sizeof(struct mctp_hdr) + plen;
	struct mctp_pktbuf *pkt = mctp_pktbuf_alloc(b, framelen);
	struct mctp_hdr *hdr;

	assert(pkt);
	hdr = mctp_pktbuf_hdr(pkt);
	hdr->ver = 1;
	hdr->dest = dest;
	hdr->src = src;
	hdr->flags_seq_tag = flags_seq_tag;
	if (plen)
		memcpy(mctp_pktbuf_data(pkt), payload, plen);

	mctp_bus_rx(b, pkt);
}

/* ------------------------------------------------------------------ */
/* V1.1 (CWE-416): reassembly realloc-fail use-after-free             */
/* ------------------------------------------------------------------ */

/*
 * On a buffer-growth realloc failure the pre-fix code freed ctx->buf but left
 * it dangling with a stale non-zero buf_alloc_size. When the dropped slot was
 * reused by a later message, the size check skipped reallocation and the
 * fragment memcpy wrote into freed memory (and EOM delivered the freed buffer).
 *
 * We force exactly that: grow a context, fail the growth realloc, then reuse
 * the freed slot for a fresh small message. The fix nulls buf/buf_alloc_size at
 * the free site so the reuse re-enters the fresh-allocation branch. Under ASan
 * the pre-fix tree faults here (heap-use-after-free); the fixed tree delivers
 * the reused message intact.
 */

static int g_fail_growth_realloc;

static void *sec_alloc(size_t n)
{
	return malloc(n);
}

static void sec_free(void *p)
{
	free(p);
}

static void *sec_realloc(void *p, size_t n)
{
	/* Only a *growth* of an existing block (ptr != NULL) is the OOM we are
	 * simulating; the initial allocation (ptr == NULL) must still succeed so
	 * the context has a live buffer to be (mis)freed. */
	if (g_fail_growth_realloc && p != NULL)
		return NULL;
	return realloc(p, n);
}

struct uaf_rx {
	bool seen;
	size_t len;
	uint8_t first_byte;
};

static void uaf_rx_message(uint8_t eid __attribute__((unused)),
			   bool tag_owner __attribute__((unused)),
			   uint8_t msg_tag __attribute__((unused)), void *data,
			   void *msg, size_t len)
{
	struct uaf_rx *r = data;
	r->seen = true;
	r->len = len;
	r->first_byte = len ? *(uint8_t *)msg : 0;
}

static void test_v1_1_reassembly_realloc_uaf(void)
{
	struct sec_binding sb;
	struct mctp *mctp;
	struct uaf_rx rx = { 0 };
	const uint8_t eid = 9, peer = 20;
	const size_t big = 3000; /* 2*big > 4096 forces a growth realloc */
	const size_t small = 100;
	uint8_t *big_buf = malloc(big);
	uint8_t small_buf[100];

	assert(big_buf);
	memset(big_buf, 0x11, big);
	memset(small_buf, 0xAB, sizeof(small_buf));

	/* Route all libmctp allocations through our fault-injecting ops. */
	mctp_set_alloc_ops(sec_alloc, sec_free, sec_realloc);

	sec_binding_init(&sb, 4096); /* room for the 3000-byte fragments */
	mctp = mctp_init();
	assert(mctp);
	mctp_register_bus(mctp, &sb.binding, eid);
	mctp_set_rx_all(mctp, uaf_rx_message, &rx);

	/* 1. SOM (seq 0): allocates the context buffer (4096). */
	rx_frame(&sb.binding, eid, peer,
		 MCTP_HDR_FLAG_SOM | (1u << MCTP_HDR_TO_SHIFT) |
			 (0u << MCTP_HDR_SEQ_SHIFT) | 2u,
		 big_buf, big);

	/* 2. Middle (seq 1): buf_size+len exceeds the 4096 alloc -> growth
	 *    realloc, which we fail. Pre-fix this frees+dangles ctx->buf. */
	g_fail_growth_realloc = 1;
	rx_frame(&sb.binding, eid, peer,
		 (1u << MCTP_HDR_TO_SHIFT) | (1u << MCTP_HDR_SEQ_SHIFT) | 2u,
		 big_buf, big);
	g_fail_growth_realloc = 0;

	/* 3. Reuse the dropped slot with a fresh 2-fragment message. The SOM
	 *    here lands in the freed slot: fixed -> fresh alloc; pre-fix ->
	 *    memcpy into freed memory (UAF write). */
	rx_frame(&sb.binding, eid, peer,
		 MCTP_HDR_FLAG_SOM | (1u << MCTP_HDR_TO_SHIFT) |
			 (0u << MCTP_HDR_SEQ_SHIFT) | 3u,
		 small_buf, small);
	rx_frame(&sb.binding, eid, peer,
		 MCTP_HDR_FLAG_EOM | (1u << MCTP_HDR_TO_SHIFT) |
			 (1u << MCTP_HDR_SEQ_SHIFT) | 3u,
		 small_buf, small);

	/* Fixed behaviour: the reused message is reassembled and delivered
	 * intact from a freshly allocated buffer. */
	assert(rx.seen);
	assert(rx.len == 2 * small);
	assert(rx.first_byte == 0xAB);

	mctp_destroy(mctp);
	free(big_buf);
	mctp_set_alloc_ops(malloc, free, realloc); /* restore default ops */
}

/* clang-format off */
#define TEST_CASE(t) { #t, t }
static const struct {
	const char *name;
	void (*test)(void);
} security_tests[] = {
	TEST_CASE(test_v1_1_reassembly_realloc_uaf),
};
/* clang-format on */

int main(void)
{
	size_t i;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	for (i = 0; i < ARRAY_SIZE(security_tests); i++) {
		printf("test: %s\n", security_tests[i].name);
		security_tests[i].test();
	}

	printf("All %zu security regression tests passed\n",
	       ARRAY_SIZE(security_tests));
	return EXIT_SUCCESS;
}
