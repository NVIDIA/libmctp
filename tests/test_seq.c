/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compiler.h"
#include "libmctp.h"
#include "test-utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

struct test_ctx {
	struct mctp *mctp;
	struct mctp_binding_test *binding;
	int rx_count;
	uint8_t rx_data[4];
	size_t rx_len;
};

static void test_rx(uint8_t eid __unused, bool tag_owner __unused,
		    uint8_t msg_tag __unused, void *data, void *msg, size_t len)
{
	struct test_ctx *ctx = data;

	ctx->rx_count++;

	/* append incoming message data to the existing rx_data */
	assert(len <= sizeof(ctx->rx_data));
	assert(ctx->rx_len + len <= sizeof(ctx->rx_data));

	memcpy(ctx->rx_data + ctx->rx_len, msg, len);
	ctx->rx_len += len;
}

#define SEQ(x) (x << MCTP_HDR_SEQ_SHIFT)

struct test {
	int n_packets;
	uint8_t flags_seq_tags[4];
	int exp_rx_count;
	size_t exp_rx_len;
} tests[] = {
	{
		/* single packet */
		.n_packets = 1,
		.flags_seq_tags =
			{
				SEQ(1) | MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM,
			},
		.exp_rx_count = 1,
		.exp_rx_len = 1,
	},
	{
		/* two packets: one start, one end */
		.n_packets = 2,
		.flags_seq_tags =
			{
				SEQ(1) | MCTP_HDR_FLAG_SOM,
				SEQ(2) | MCTP_HDR_FLAG_EOM,
			},
		.exp_rx_count = 1,
		.exp_rx_len = 2,
	},
	{
		/* three packets: one start, one no flags, one end */
		.n_packets = 3,
		.flags_seq_tags =
			{
				SEQ(1) | MCTP_HDR_FLAG_SOM,
				SEQ(2),
				SEQ(3) | MCTP_HDR_FLAG_EOM,
			},
		.exp_rx_count = 1,
		.exp_rx_len = 3,
	},
	{
		/* two packets, wrapping sequence numbers */
		.n_packets = 2,
		.flags_seq_tags =
			{
				SEQ(3) | MCTP_HDR_FLAG_SOM,
				SEQ(0) | MCTP_HDR_FLAG_EOM,
			},
		.exp_rx_count = 1,
		.exp_rx_len = 2,
	},
	{
		/* two packets, invalid sequence number */
		.n_packets = 2,
		.flags_seq_tags =
			{
				SEQ(1) | MCTP_HDR_FLAG_SOM,
				SEQ(3) | MCTP_HDR_FLAG_EOM,
			},
		.exp_rx_count = 0,
		.exp_rx_len = 0,
	},
};

static void run_one_test(struct test_ctx *ctx, struct test *test)
{
	const mctp_eid_t local_eid = 8;
	const mctp_eid_t remote_eid = 9;
	struct {
		struct mctp_hdr hdr;
		uint8_t payload[1];
	} pktbuf;
	int i;

	ctx->rx_count = 0;
	ctx->rx_len = 0;

	mctp_test_stack_init(&ctx->mctp, &ctx->binding, local_eid);

	mctp_set_rx_all(ctx->mctp, test_rx, ctx);

	for (i = 0; i < test->n_packets; i++) {
		memset(&pktbuf, 0, sizeof(pktbuf));
		pktbuf.hdr.dest = local_eid;
		pktbuf.hdr.src = remote_eid;
		pktbuf.hdr.flags_seq_tag = test->flags_seq_tags[i];
		pktbuf.payload[0] = i;

		mctp_binding_test_rx_raw(ctx->binding, &pktbuf, sizeof(pktbuf));
	}

	assert(ctx->rx_count == test->exp_rx_count);
	assert(ctx->rx_len == test->exp_rx_len);

	/* ensure the payload data was reconstructed correctly */
	for (i = 0; i < (int)ctx->rx_len; i++)
		assert(ctx->rx_data[i] == i);

	mctp_binding_test_destroy(ctx->binding);
	mctp_destroy(ctx->mctp);
}

#define LOST_NONE (-1)
#define MSG_PKTS  6

static void count_rx(uint8_t eid __unused, bool tag_owner __unused,
		     uint8_t msg_tag __unused, void *data, void *msg __unused,
		     size_t len __unused)
{
	int *count = data;

	(*count)++;
}

static void rx_message(struct mctp_binding_test *binding, mctp_eid_t src,
		       mctp_eid_t dest, int lost)
{
	struct {
		struct mctp_hdr hdr;
		uint8_t payload[1];
	} pktbuf;
	int i;

	for (i = 0; i < MSG_PKTS; i++) {
		if (i == lost)
			continue;

		memset(&pktbuf, 0, sizeof(pktbuf));
		pktbuf.hdr.dest = dest;
		pktbuf.hdr.src = src;
		pktbuf.hdr.flags_seq_tag = SEQ(i % 4);
		if (i == 0)
			pktbuf.hdr.flags_seq_tag |= MCTP_HDR_FLAG_SOM;
		if (i == MSG_PKTS - 1)
			pktbuf.hdr.flags_seq_tag |= MCTP_HDR_FLAG_EOM;
		pktbuf.payload[0] = i;

		mctp_binding_test_rx_raw(binding, &pktbuf, sizeof(pktbuf));
	}
}

/* A lost packet must drop the whole message, also from EID 0 */
static void run_lost_packet_test(mctp_eid_t remote_eid, int lost,
				 int exp_rx_count)
{
	const mctp_eid_t local_eid = 8;
	struct mctp_binding_test *binding;
	struct mctp *mctp;
	int rx_count = 0;

	mctp_test_stack_init(&mctp, &binding, local_eid);
	mctp_set_rx_all(mctp, count_rx, &rx_count);

	rx_message(binding, remote_eid, local_eid, LOST_NONE);
	assert(rx_count == 1);

	rx_message(binding, remote_eid, local_eid, lost);
	assert(rx_count == exp_rx_count);

	rx_message(binding, remote_eid, local_eid, LOST_NONE);
	assert(rx_count == exp_rx_count + 1);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

int main(void)
{
	static const mctp_eid_t remote_eids[] = { 9, 0 };
	struct test_ctx ctx;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++)
		run_one_test(&ctx, &tests[i]);

	for (i = 0; i < ARRAY_SIZE(remote_eids); i++) {
		run_lost_packet_test(remote_eids[i], LOST_NONE, 2);
		run_lost_packet_test(remote_eids[i], 0, 1);
		run_lost_packet_test(remote_eids[i], 1, 1);
	}

	return EXIT_SUCCESS;
}
