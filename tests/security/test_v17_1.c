/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for V17.1 (NVBug 6295094, CWE-125).
 *
 * ctrld/mctp-discovery.c : mctp_get_endpoint_uuid_response()
 *
 * A Get-Endpoint-UUID response is received into a heap buffer whose length is
 * fully attacker-controlled (mctp_client_recv mallocs to the received length,
 * which can be as small as 3 bytes). On a SUCCESS completion code the pre-fix
 * code cast the buffer to struct mctp_ctrl_resp_get_uuid (20 bytes) and ran a
 * fixed 16-byte memcpy of uuid.canonical, reading 16 bytes of UUID past the
 * end of a short buffer -> heap-buffer-overflow READ.
 *
 * The fix rejects any response shorter than sizeof(struct
 * mctp_ctrl_resp_get_uuid) (20 bytes) before the cast / memcpy.
 *
 * A/B method:
 *   - We call the REAL function with a heap buffer malloc'd to EXACTLY the
 *     short length, so AddressSanitizer brackets it tightly. completion_code
 *     is set to SUCCESS and command_code to GET_ENDPOINT_UUID so the decoder
 *     accepts the message and execution reaches the vulnerable copy.
 *   - On the CURRENT (fixed) source the call returns MCTP_RET_REQUEST_FAILED
 *     and ASan stays quiet.
 *   - Built against a copy of mctp-discovery.c with ONLY the length guard
 *     reverted, the same call faults with an ASan heap-buffer-overflow READ in
 *     mctp_get_endpoint_uuid_response.
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
#include "mctp-discovery.h"

/* Completion-code SUCCESS and the Get-UUID command code (see libmctp-cmds.h). */
#ifndef MCTP_CTRL_CC_SUCCESS
#define MCTP_CTRL_CC_SUCCESS 0x00
#endif
#ifndef MCTP_CTRL_CMD_GET_ENDPOINT_UUID
#define MCTP_CTRL_CMD_GET_ENDPOINT_UUID 0x03
#endif
#ifndef MCTP_CTRL_HDR_MSG_TYPE
#define MCTP_CTRL_HDR_MSG_TYPE 0
#endif

/*
 * Build a minimal "success" Get-UUID response of exactly `len` bytes on the
 * heap. The first 6 bytes (msg hdr + completion_code + 1) are a valid SUCCESS
 * response header with the matching command code; everything after that is
 * absent, exactly as a truncated wire response would be. The buffer is sized
 * to `len` so ASan flags any read past it.
 */
static uint8_t *make_short_uuid_resp(size_t len)
{
	uint8_t *buf = malloc(len);
	assert(buf);
	memset(buf, 0, len);

	/* ic_msg_type, rq_dgram_inst, command_code, completion_code:
	 * only write fields that fit within the short buffer. */
	if (len > 0)
		buf[0] = MCTP_CTRL_HDR_MSG_TYPE; /* ic_msg_type   */
	if (len > 1)
		buf[1] = 0x00; /* rq_dgram_inst */
	if (len > 2)
		buf[2] = MCTP_CTRL_CMD_GET_ENDPOINT_UUID; /* command_code  */
	if (len > 3)
		buf[3] = MCTP_CTRL_CC_SUCCESS; /* completion_code */
	return buf;
}

static void test_v17_1_get_uuid_short_response(void)
{
	const mctp_eid_t eid = 9;
	int ret;

	/*
	 * Smallest interesting length: a 3-byte buffer is the documented worst
	 * case (mctp_client_recv minimum). It carries no completion_code byte,
	 * so we also exercise the more dangerous "looks like SUCCESS" case
	 * below. Here, with only 3 bytes, the pre-fix decoder reads
	 * completion_code at offset 3 (1 byte OOB) and then the 16-byte UUID
	 * copy at offset 4 (well past the end).
	 */
	uint8_t *buf3 = make_short_uuid_resp(3);
	ret = mctp_get_endpoint_uuid_response(eid, buf3, 3);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf3);

	/*
	 * The worst case for the OOB *read*: a buffer just large enough to hold
	 * a valid SUCCESS header (6 bytes) but 14 bytes short of the 20-byte
	 * response struct. The pre-fix decoder returns true (completion_code ==
	 * SUCCESS, command_code matches), then memcpy reads 16 bytes of UUID
	 * starting at offset 4 -> 10 bytes past the 6-byte allocation.
	 */
	uint8_t *buf6 = make_short_uuid_resp(6);
	ret = mctp_get_endpoint_uuid_response(eid, buf6, 6);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf6);

	/* One byte short of the full struct still must be rejected. */
	uint8_t *buf19 = make_short_uuid_resp(19);
	ret = mctp_get_endpoint_uuid_response(eid, buf19, 19);
	assert(ret == MCTP_RET_REQUEST_FAILED);
	free(buf19);

	/*
	 * Sanity (positive control): a full-length, well-formed response is
	 * accepted by the fixed code. This proves the guard is a length check,
	 * not a blanket rejection. Allocated to the exact struct size.
	 */
	size_t full = sizeof(struct mctp_ctrl_resp_get_uuid);
	uint8_t *bufok = make_short_uuid_resp(full);
	ret = mctp_get_endpoint_uuid_response(eid, bufok, full);
	assert(ret == MCTP_RET_REQUEST_SUCCESS);
	free(bufok);

	printf("V17.1 get-uuid short-response guard: OK\n");
}

int main(void)
{
	printf("test: test_v17_1_get_uuid_short_response\n");
	test_v17_1_get_uuid_short_response();
	printf("All security regression tests passed (V17.1)\n");
	return EXIT_SUCCESS;
}
