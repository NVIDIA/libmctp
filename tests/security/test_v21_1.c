/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding V21.1
 * (NVBug 6295100, CWE-125 out-of-bounds read),
 * vdm/nvidia/mctp-vdm-commands.c : query_boot_status() / query_boot_status_json().
 *
 * Vulnerability
 * -------------
 * query_boot_status() sends a Query-Boot-Status VDM command and receives a
 * heap response whose length is fully attacker-controlled (the device picks
 * the reply size; mctp_client_recv mallocs to exactly that length, which can be
 * as small as 3 bytes). The pre-fix code checked ONLY the transport rc, then,
 * when the caller passed `more`, fed the buffer to the boot-status bit parsers
 * which index the response TAIL:
 *
 *     is_booted_OK():                       resp_msg[resp_len - 4]
 *     query_boot_status_print_bits48_to_bit57(): resp_msg[resp_len - 7]
 *                                                resp_msg[resp_len - 8]   <-- deepest
 *
 * For a 3-byte reply that is resp_msg[3 - 8] == resp_msg[-5]: a read 5 bytes
 * BELOW the start of the heap chunk (and resp_msg[-1] in is_booted_OK).
 * query_boot_status_json() has the identical pattern via the create_json_*
 * bit parsers.
 *
 * Fix (mctp-vdm-commands.c)
 * -------------------------
 *     #define MCTP_VDM_BOOT_STATUS_MIN_LEN 8
 * and, in BOTH entry points, after a successful recv:
 *     if (resp_len < MCTP_VDM_BOOT_STATUS_MIN_LEN) { free(resp); return -1; }
 * rejecting any reply too short for the tail indexing before a single tail
 * access happens.
 *
 * A/B method
 * ----------
 * This file is compiled with `#include "../../vdm/nvidia/mctp-vdm-commands.c"`
 * so it can drive the *real* query_boot_status() / query_boot_status_json().
 *
 * The entry points reach the wire only through the external symbol
 * mctp_client_send_recv() (normally in mctp-socket.c). We provide our OWN
 * definition of that symbol here and do NOT link mctp-socket.c, so the call
 * is intercepted without any live socket: the stub mallocs a response buffer
 * of EXACTLY the configured short length so AddressSanitizer brackets it
 * tightly, sets byte 0 to MCTP_VENDOR_MSG_TYPE (so the in-tree response-type
 * assertion passes), and returns MCTP_REQUESTER_SUCCESS. Everything from the
 * length guard through is_booted_OK and the print/JSON bit parsers is the real
 * code under test.
 *
 *   - FIXED tree: the MIN_LEN guard fires, the entry point returns an error
 *     and frees the buffer before any tail access -> clean under ASan.
 *   - PRE-fix tree (guard reverted): is_booted_OK reads resp[-1] and the
 *     bit-57 parser reads resp[-5] -> ASan heap-buffer-overflow READ.
 *
 * NOTE ON JSON-C: mctp-vdm-commands.c #includes <json-c/json.h> and emits JSON
 * in query_boot_status_json(). On a normal build json-c is a real dependency
 * (see vdm/nvidia/meson.build). On a host that lacks the json-c *dev headers*
 * (only the runtime lib installed), point -I at a directory holding a small
 * compile/link shim json-c/json.h + json_shim.c that declares/defines exactly
 * the 8 json_object_* symbols this file uses. The exercised paths
 * (query_boot_status / query_boot_status_json with a short reply) return before
 * any json_object_* call, so the shim never executes -- it only satisfies the
 * compiler/linker. (The shim's json funcs are kept out-of-line so the optimizer
 * cannot dead-code-eliminate the OOB response-byte loads under test.)
 *
 * Build (sandbox, dedicated source compile -- mctp-vdm-commands.c is #included
 * here so it must NOT also appear on the command line; mctp-socket.c is omitted
 * so our stub provides mctp_client_send_recv). mctp_prlog() lives in log.c,
 * which needs -lsystemd (sd-journal):
 *
 *   printf '#ifndef _CONFIG_H\n#define _CONFIG_H\n#endif\n' > .sec-v21_1/config.h
 *   # .sec-v21_1/json-c/json.h + .sec-v21_1/json_shim.c : json-c compile/link
 *   #   shim, only needed where the json-c dev headers are absent.
 *   gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer \
 *       -I./.sec-v21_1 -I. -Itests -Ivdm/nvidia \
 *       tests/security/test_v21_1.c vdm/nvidia/mctp-vdm-encode.c log.c \
 *       .sec-v21_1/json_shim.c -lsystemd -o ./.sec-v21_1/t
 *   ASAN_OPTIONS=detect_leaks=0 ./.sec-v21_1/t
 *
 * Pre-fix reproduction (A/B): copy mctp-vdm-commands.c to scratch, delete only
 * the two `resp_len < MCTP_VDM_BOOT_STATUS_MIN_LEN` guard blocks, repoint the
 * #include below at that copy, rebuild and run -> ASan heap-buffer-overflow READ
 * in is_booted_OK (resp[resp_len-4]) reached from query_boot_status.
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

/*
 * Intercept the wire call. query_boot_status() -> mctp_vdm_client_send_recv()
 * (static, pulled in by the #include below) -> mctp_client_send_recv(). By
 * defining the latter here and not linking mctp-socket.c, we control the exact
 * response buffer with no socket. The signature must match mctp-socket.h.
 *
 * g_resp_len is the length of the buffer the next call hands back; it is
 * malloc'd to EXACTLY that size so ASan flags any below/above access.
 */
static size_t g_resp_len;
static int g_send_recv_calls;

/* Forward decls of the types the stub signature needs, before the source is
 * pulled in. mctp_eid_t and mctp_requester_rc_t come from the headers the
 * included source itself includes; declare the stub after that include to use
 * them. We therefore split: declare a marker and define the stub *after* the
 * source include (see bottom of file is not possible -- definition must be
 * visible to the linker, which it is regardless of order in one TU). */

/* The real source. It includes <json-c/json.h> (satisfied by the scratch
 * shim), libmctp headers, ctrld/mctp-ctrl.h (mctp_requester_rc_t), and
 * mctp-socket.h (mctp_client_send_recv prototype). Bringing it in here exposes
 * query_boot_status(), query_boot_status_json() and the static helpers. */
#include "../../vdm/nvidia/mctp-vdm-commands.c"

/*
 * Our definition of the external wire entry point. Matches the prototype in
 * mctp-socket.h exactly. Returns a heap buffer of exactly g_resp_len bytes.
 */
mctp_requester_rc_t mctp_client_send_recv(mctp_eid_t eid, int fd,
					  uint8_t msgtype,
					  const uint8_t *req_msg, size_t req_len,
					  uint8_t **resp_msg, size_t *resp_len)
{
	(void)eid;
	(void)fd;
	(void)msgtype;
	(void)req_msg;
	(void)req_len;

	g_send_recv_calls++;

	uint8_t *buf = malloc(g_resp_len); /* EXACT size -> tight ASan bracket */
	assert(buf || g_resp_len == 0);
	if (g_resp_len)
		memset(buf, 0, g_resp_len);
	/* Byte 0 must be the VDM message type: mctp_vdm_client_send_recv()
	 * asserts resp_msg[0] == MCTP_VENDOR_MSG_TYPE on success. */
	if (g_resp_len > 0)
		buf[0] = MCTP_VENDOR_MSG_TYPE;

	*resp_msg = buf;
	*resp_len = g_resp_len;
	return MCTP_REQUESTER_SUCCESS;
}

/* Drive query_boot_status() with a device reply of `len` bytes. `more` selects
 * whether the boot-status bit parsers run (they are the OOB-reading code). */
static int drive_query_boot_status(size_t len, uint8_t more)
{
	g_resp_len = len;
	/* fd/tid are unused by our stub; verbose=0 so print_hex/vdm_resp_output
	 * early-return and never walk the short buffer themselves. */
	return query_boot_status(/*fd*/ -1, /*tid*/ 9, /*verbose*/ 0, more);
}

static void test_v21_1_query_boot_status_short_response(void)
{
	int rc;

	/*
	 * Worst case from the finding: a 3-byte success reply. With `more`
	 * set, the pre-fix code calls is_booted_OK (reads resp[3-4]=resp[-1])
	 * and query_boot_status_print_bits48_to_bit57 (reads resp[3-8]=resp[-5]),
	 * both below the 3-byte heap chunk. The fix rejects it first.
	 */
	rc = drive_query_boot_status(3, /*more*/ true);
	assert(rc == -1);

	/* One byte short of the 8-byte minimum must still be rejected, with the
	 * bit parsers requested. resp[7-8] == resp[-1] pre-fix. */
	rc = drive_query_boot_status(7, /*more*/ true);
	assert(rc == -1);

	/*
	 * The guard must fire even when `more` is not set: a short reply is
	 * invalid regardless, and the fix rejects it up front. (Pre-fix this
	 * particular call did not index the tail, so it is purely a behavioural
	 * assertion on the fixed tree.)
	 */
	rc = drive_query_boot_status(3, /*more*/ false);
	assert(rc == -1);

	/*
	 * Positive control: a full 8-byte reply (the documented minimum) is
	 * accepted and parsed by the fixed code. Allocated to exactly 8 bytes,
	 * so resp[8-8]=resp[0] is the lowest access and stays in bounds; this
	 * proves the guard is a length check, not a blanket rejection, and that
	 * the boundary value itself is safe.
	 */
	rc = drive_query_boot_status(8, /*more*/ true);
	assert(rc == 0);

	assert(g_send_recv_calls == 4);

	printf("V21.1 query_boot_status short-response guard: OK\n");
}

static void test_v21_1_query_boot_status_json_short_response(void)
{
	int prev_calls = g_send_recv_calls;
	int rc;

	/*
	 * query_boot_status_json() shares the defect: on the pre-fix tree the
	 * create_json_query_boot_status_bits48_to_bit57 parser reads
	 * resp[resp_len-7]/resp[resp_len-8]. With a 3-byte reply that is
	 * resp[-5]. The fix rejects resp_len < 8 before any json_object_* call,
	 * so the json-c shim stubs are never reached here.
	 */
	g_resp_len = 3;
	rc = query_boot_status_json(/*fd*/ -1, /*tid*/ 9);
	assert(rc == -1);

	/* Boundary: one byte short still rejected. */
	g_resp_len = 7;
	rc = query_boot_status_json(/*fd*/ -1, /*tid*/ 9);
	assert(rc == -1);

	assert(g_send_recv_calls == prev_calls + 2);

	printf("V21.1 query_boot_status_json short-response guard: OK\n");
}

int main(void)
{
	printf("test: test_v21_1_query_boot_status_short_response\n");
	test_v21_1_query_boot_status_short_response();

	printf("test: test_v21_1_query_boot_status_json_short_response\n");
	test_v21_1_query_boot_status_json_short_response();

	printf("All security regression tests passed (V21.1)\n");
	return EXIT_SUCCESS;
}
