/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for V16.1 (NVBug 6295093, CWE-125).
 *
 * ctrld/mctp-discovery.c : mctp_get_routing_table_get_response()
 *
 * A Get-Routing-Table-Entries response is received into a heap buffer whose
 * length is fully attacker-controlled (mctp_client_recv mallocs to the
 * received length, as small as 3 bytes). On a SUCCESS completion code with
 * number_of_entries >= 1, the pre-fix code performed a fixed 6-byte memcpy of
 * a struct get_routing_table_entry from offset
 * sizeof(struct mctp_ctrl_resp_get_routing_table) (== 6). For a buffer shorter
 * than 12 bytes that read runs past the end of the allocation ->
 * heap-buffer-overflow READ. A buffer shorter than the 6-byte response header
 * also over-reads completion_code / number_of_entries themselves.
 *
 * The fix adds two guards before the reads:
 *   1. resp_msg_len >= sizeof(struct mctp_ctrl_resp_get_routing_table)  (6)
 *   2. resp_msg_len >= header + sizeof(struct get_routing_table_entry)  (12)
 *
 * A/B method:
 *   - We call the REAL function with a heap buffer malloc'd to EXACTLY the
 *     short length so AddressSanitizer brackets it tightly. completion_code is
 *     SUCCESS and number_of_entries == 1 so execution reaches the entry copy.
 *   - On the CURRENT (fixed) source the call returns MCTP_RET_REQUEST_FAILED
 *     and ASan stays quiet.
 *   - Built against a copy of mctp-discovery.c with ONLY the guard(s) reverted,
 *     the same call faults with an ASan heap-buffer-overflow READ.
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

#include "libmctp-cmds.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-discovery.h"

#ifndef MCTP_CTRL_CC_SUCCESS
#define MCTP_CTRL_CC_SUCCESS 0x00
#endif
#ifndef MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES
#define MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES 0x0A
#endif
#ifndef MCTP_CTRL_HDR_MSG_TYPE
#define MCTP_CTRL_HDR_MSG_TYPE 0
#endif

/*
 * Build a minimal "success" Get-Routing-Table response of exactly `len` bytes
 * on the heap. Layout of struct mctp_ctrl_resp_get_routing_table:
 *   [0] ic_msg_type  [1] rq_dgram_inst  [2] command_code
 *   [3] completion_code  [4] next_entry_handle  [5] number_of_entries
 * Only the fields that fit within `len` are written; the rest is simply
 * absent, as in a truncated wire response. number_of_entries is forced to 1
 * (when that byte fits) so the handler attempts the 6-byte entry copy.
 */
static uint8_t *make_short_routing_resp(size_t len)
{
	uint8_t *buf = malloc(len);
	assert(buf);
	memset(buf, 0, len);

	if (len > 0)
		buf[0] = MCTP_CTRL_HDR_MSG_TYPE; /* ic_msg_type      */
	if (len > 1)
		buf[1] = 0x00; /* rq_dgram_inst    */
	if (len > 2)
		buf[2] = MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES; /* command  */
	if (len > 3)
		buf[3] = MCTP_CTRL_CC_SUCCESS; /* completion_code  */
	if (len > 4)
		buf[4] = 0xFF; /* next_entry_handle (no "next") */
	if (len > 5)
		buf[5] = 0x01; /* number_of_entries >= 1        */
	return buf;
}

static void test_v16_1_get_routing_table_short_response(void)
{
	mctp_cmdline_args_t cmdline;
	mctp_ctrl_t ctrl;
	const mctp_eid_t eid = 9;
	int ret;

	/* The handler dereferences ctrl->cmdline->ignore_eids_len and (on the
	 * no-medium path only) ctrl->bus; zero-initialise so an accidental
	 * deref is benign and ignore list is empty. */
	memset(&cmdline, 0, sizeof(cmdline));
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.cmdline = &cmdline;

	/*
	 * 3-byte buffer: shorter than the 6-byte response header. The pre-fix
	 * code reads completion_code (offset 3) and number_of_entries
	 * (offset 5) past the end before it ever looks at an entry.
	 */
	uint8_t *buf3 = make_short_routing_resp(3);
	ret = mctp_get_routing_table_get_response(&ctrl, eid, buf3, 3, false);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf3);

	/*
	 * 6-byte buffer: a complete SUCCESS header with number_of_entries == 1
	 * but no entry payload. The pre-fix code passes the decode, then does a
	 * 6-byte memcpy from offset 6 -> entirely past the 6-byte allocation
	 * (the canonical V16.1 over-read).
	 */
	uint8_t *buf6 = make_short_routing_resp(6);
	ret = mctp_get_routing_table_get_response(&ctrl, eid, buf6, 6, false);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf6);

	/*
	 * 11-byte buffer: header + 5 of the 6 entry bytes. The pre-fix 6-byte
	 * memcpy from offset 6 reads 1 byte past the end.
	 */
	uint8_t *buf11 = make_short_routing_resp(11);
	ret = mctp_get_routing_table_get_response(&ctrl, eid, buf11, 11, false);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf11);

	/*
	 * Sanity (positive control): a full-length, well-formed response
	 * (header + one complete entry == 12 bytes) is accepted by the fixed
	 * code, proving the guard is a length check and not a blanket reject.
	 * Allocated to exactly 12 bytes. starting_eid (offset 7) is left 0;
	 * the transport-binding id (offset 9) is 0 ("Unknown"), so the entry is
	 * not added to the global table, but the function still succeeds.
	 */
	size_t full = sizeof(struct mctp_ctrl_resp_get_routing_table) +
		      sizeof(struct get_routing_table_entry);
	uint8_t *bufok = make_short_routing_resp(full);
	/* Give the entry a starting_eid distinct from g_own_eid (0). */
	bufok[7] = 0x20; /* starting_eid */
	ret = mctp_get_routing_table_get_response(&ctrl, eid, bufok, full,
						  false);
	assert(ret == MCTP_RET_REQUEST_SUCCESS);
	free(bufok);

	printf("V16.1 get-routing-table short-response guard: OK\n");
}

int main(void)
{
	printf("test: test_v16_1_get_routing_table_short_response\n");
	test_v16_1_get_routing_table_short_response();
	printf("All security regression tests passed (V16.1)\n");
	return EXIT_SUCCESS;
}
