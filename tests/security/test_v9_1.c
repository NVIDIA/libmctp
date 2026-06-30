/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding V9.1 (NVBug 6295083, CWE-191):
 * integer underflow in the USB branch of tx_pvt_message() in
 * utils/mctp-demux-daemon.c.
 *
 * Root cause (pre-fix):
 *   The USB branch validated the datagram length against
 *       min_packet_usb = MCTP_USB_EID_OFFSET + 1            (= 34)
 *   but computed the forwarded payload length as
 *       len = len - MCTP_USB_MSG_OFFSET - 1                 (= len - 35)
 *   The guard constant (34) is one less than the constant subtracted (35),
 *   so a 34-byte datagram with bind_id == MCTP_BINDING_USB passes the
 *   "len < 34" check and then underflows size_t to SIZE_MAX. That value
 *   flows as msg_len into mctp_message_pvt_bind_tx() ->
 *   mctp_message_tx_on_bus(), whose packetisation loop
 *       for (p = 0; p < msg_len; i++)
 *           memcpy(mctp_pktbuf_data(pkt), (uint8_t *)msg + p, payload_len);
 *   reads up to MCTP_BTU (64) bytes from the 34-byte client buffer on the
 *   very first iteration -- an out-of-bounds heap read -- while queuing a
 *   near-unbounded number of packets.
 *
 * Fix:
 *       min_packet_usb = MCTP_USB_MSG_OFFSET + 1            (= 35)
 *   and use "len <= min_packet_usb" (matching the SMBUS branch), so
 *   len - MCTP_USB_MSG_OFFSET - 1 is always >= 1.
 *
 * Method (A/B): this test drives the *real* static tx_pvt_message() with a
 * fabricated ctx and the exact 34-byte trigger datagram. tx_pvt_message is
 * static inside the demux daemon translation unit, so we #include that TU
 * directly (renaming its main()) and satisfy its binding-glue externs with
 * inert stubs -- none of those stubs are reached by the USB tx path.
 *
 *   - Built against the CURRENT (fixed) source under AddressSanitizer the
 *     34-byte datagram is rejected by the guard: no packet is queued, no OOB.
 *   - Built against a copy with ONLY the fix reverted (the constant + the
 *     comparison operator), the same input underflows to SIZE_MAX and the
 *     packetisation memcpy reads past the 34-byte heap buffer -- ASan aborts
 *     with heap-buffer-overflow (READ).
 *
 * See UNIT-TESTING-AB-REGRESSIONS.md for the wider per-finding test rationale
 * and manual reproduction recipes.
 */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The demux TU references binding-glue / daemon-helper symbols (the
 * bindings[] table, sd_notify, the mctp_json_* config parsers, the per-
 * binding init/poll/process entry points, etc). None of them are reached by
 * the USB tx_pvt_message() path under test, so they are satisfied at link
 * time by inert no-op stubs compiled in a *separate* translation unit
 * (tests/security/test_v9_1_stubs.c) that does not include the real binding
 * headers -- which keeps the void* stub prototypes from clashing with the
 * real declarations pulled in by the demux TU below. C resolves them by
 * symbol name only. See that file and UNIT-TESTING-AB-REGRESSIONS.md.
 */

/* ------------------------------------------------------------------ */
/* Pull in the real demux daemon TU (its main() renamed out of the    */
/* way) so we can call the static tx_pvt_message().                   */
/* ------------------------------------------------------------------ */

#define main demux_main_unused
#include "../../utils/mctp-demux-daemon.c"
#undef main

/* ------------------------------------------------------------------ */
/* Test binding: a real core binding whose tx records that a packet    */
/* was queued/sent. A genuine OOB only manifests once the underflowed  */
/* msg_len drives the packetisation memcpy, so we use a live bus.      */
/* ------------------------------------------------------------------ */

struct v9_binding {
	struct mctp_binding binding;
	int tx_count;
};

static int v9_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	/* binding is the first member of struct v9_binding, so the binding
	 * pointer is the struct pointer (avoids a container_of.h dependency). */
	struct v9_binding *vb = (struct v9_binding *)b;
	(void)pkt;
	vb->tx_count++;
	return 0;
}

/*
 * Offsets, recomputed here from the public headers so the expected values are
 * explicit and independent of the (possibly reverted) demux constants:
 *   MCTP_BIND_INFO_OFFSET                 = sizeof(uint8_t)            = 1
 *   sizeof(struct mctp_usb_pkt_private)   = 32 (packed _reserved[32])
 *   MCTP_USB_EID_OFFSET                   = 1 + 32                     = 33
 *   MCTP_USB_MSG_OFFSET                   = 33 + 1                     = 34
 * Trigger datagram length == 34:
 *   pre-fix guard  (len <  34)  -> 34 < 34  == false -> NOT rejected
 *   pre-fix length  len - 34 - 1            -> (size_t)-1 == SIZE_MAX
 *   post-fix guard (len <= 35)  -> 34 <= 35 == true  -> rejected
 */
#define USB_TRIGGER_LEN 34u

static void test_v9_1_usb_len_guard_underflow(void)
{
	struct v9_binding vb;
	struct mctp *mctp;
	const mctp_eid_t local_eid = 8;
	uint8_t *msg;

	/* Compile-time cross-check of the offsets the finding relies on. */
	assert(MCTP_USB_EID_OFFSET == 33);
	assert(MCTP_USB_MSG_OFFSET == 34);

	memset(&vb, 0, sizeof(vb));
	vb.binding.name = "v9";
	vb.binding.version = 1;
	vb.binding.tx = v9_tx;
	/* max_payload_len = MCTP_BODY_SIZE(pkt_size) must be >= MCTP_BTU(64),
	 * matching a real binding; the OOB memcpy copies up to 64 bytes. */
	vb.binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	vb.binding.pkt_header = 0;
	vb.binding.pkt_trailer = 0;

	mctp = mctp_init();
	assert(mctp);
	mctp_register_bus(mctp, &vb.binding, local_eid);
	mctp_binding_set_tx_enabled(&vb.binding, true);

	/* Minimal ctx: tx_pvt_message only touches ->mctp and ->verbose. */
	struct ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.mctp = mctp;
	ctx.verbose = false;

	/*
	 * Fabricate the exact attacker datagram a local MCTP-control client
	 * would deliver: a *34-byte* heap buffer whose first byte selects the
	 * USB binding. Allocating exactly 34 bytes puts an ASan redzone right
	 * after byte 33, so the pre-fix OOB read (which starts copying 64
	 * bytes from offset 0) trips immediately.
	 */
	msg = malloc(USB_TRIGGER_LEN);
	assert(msg);
	memset(msg, 0, USB_TRIGGER_LEN);
	msg[0] = MCTP_BINDING_USB; /* bind_id */

	/* Drive the real function with the malformed input. */
	tx_pvt_message(&ctx, msg, USB_TRIGGER_LEN);

	/*
	 * Fixed behaviour: the guard rejects the short datagram before the
	 * subtraction, so nothing is queued and no OOB read occurs.
	 *
	 * On the pre-fix (reverted) source we never reach this assertion: the
	 * underflow makes msg_len == SIZE_MAX and mctp_message_tx_on_bus()'s
	 * first memcpy reads past the 34-byte buffer -> ASan heap-buffer-
	 * overflow (READ) abort.
	 */
	assert(vb.tx_count == 0);

	free(msg);
	mctp_destroy(mctp);
}

/* ------------------------------------------------------------------ */

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	printf("test: test_v9_1_usb_len_guard_underflow\n");
	test_v9_1_usb_len_guard_underflow();

	printf("V9.1 security regression test passed\n");
	return EXIT_SUCCESS;
}
