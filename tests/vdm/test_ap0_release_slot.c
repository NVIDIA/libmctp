/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Tests for the AP0_RELEASE_SLOT decode in query_boot_status (text and JSON).
 *
 * AP0_RELEASE_SLOT of 1 and 2 are reported as is. 0 is ambiguous, so it is
 * resolved from the other status bits:
 *
 *   FATAL_ERROR_CODE (bits 28-31) != 0                    -> fatal error
 *   PRIMARY/SECONDARY auth status (bits 8-11 / 12-15)
 *     == AUTHENTICATE_IN_PROGRESS (15)                    -> in progress
 *   neither                                               -> not-reported
 *
 * The source under test is #included so the real static decoders run; the
 * wire call is replaced by a stub, so no socket is needed.
 *
 * Standalone build (json-c dev headers may be replaced by a declarations-only
 * shim; the runtime library is still linked):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
 *       -I. -Itests -Ivdm/nvidia \
 *       tests/vdm/test_ap0_release_slot.c vdm/nvidia/mctp-vdm-encode.c log.c \
 *       -lsystemd -ljson-c -o ./scratch/t
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

#include "../../vdm/nvidia/mctp-vdm-commands.c"

#define RESP_LEN 32

static uint8_t g_resp[RESP_LEN];

mctp_requester_rc_t mctp_client_send_recv(mctp_eid_t eid, int fd,
					  uint8_t msgtype,
					  const uint8_t *req_msg,
					  size_t req_len, uint8_t **resp_msg,
					  size_t *resp_len)
{
	(void)eid;
	(void)fd;
	(void)msgtype;
	(void)req_msg;
	(void)req_len;

	uint8_t *buf = malloc(RESP_LEN);
	assert(buf);
	memcpy(buf, g_resp, RESP_LEN);
	buf[0] = MCTP_VENDOR_MSG_TYPE;
	*resp_msg = buf;
	*resp_len = RESP_LEN;
	return MCTP_REQUESTER_SUCCESS;
}

/* Build a reply with the given status fields. Everything else is zero. */
static void set_resp(uint8_t release_slot, uint8_t primary, uint8_t secondary,
		     uint8_t fatal)
{
	memset(g_resp, 0, sizeof(g_resp));
	g_resp[RESP_LEN - 7] = release_slot & 0x3;
	g_resp[RESP_LEN - 2] = (primary & 0xF) | ((secondary & 0xF) << 4);
	g_resp[RESP_LEN - 4] = (fatal & 0xF) << 4;
}

/* Run fn with stdout captured, return what it printed. */
static char *capture(int (*fn)(void))
{
	static char out[16384];
	char tmpfnam[] = "/tmp/mctp-vdm-test-XXXXXX";
	int saved, rc;

	int tmpfd = mkstemp(tmpfnam);
	assert(tmpfd > 0);
	assert(unlink(tmpfnam) == 0);
	assert(fflush(stdout) == 0);
	saved = dup(STDOUT_FILENO);
	assert(saved >= 0);
	assert(dup2(tmpfd, STDOUT_FILENO) >= 0);
	rc = fn();
	assert(fflush(stdout) == 0);
	assert(fsync(tmpfd) == 0);
	assert(dup2(saved, STDOUT_FILENO) >= 0);
	close(saved);
	assert(rc == 0);

	off_t end = lseek(tmpfd, 0, SEEK_END);
	assert(end >= 0);
	size_t sz = (size_t)end;
	assert(sz < sizeof(out));
	assert(lseek(tmpfd, 0, SEEK_SET) == 0);
	ssize_t n = read(tmpfd, out, sz);
	assert(n != -1);
	assert((size_t)n == sz);
	out[n] = '\0';
	close(tmpfd);
	return out;
}

static int run_text(void)
{
	return query_boot_status(-1, 9, 0, true);
}

static int run_json(void)
{
	return query_boot_status_json(-1, 9);
}

struct tc {
	const char *name;
	uint8_t slot, primary, secondary, fatal;
	const char *want; /* text after the value, e.g. "0 (not-reported)" */
};

static const struct tc cases[] = {
	/* Slots 1 and 2 are reported as is, whatever the other bits say. */
	{ "slot0", 1, 1, 0, 0, "1 (slot0)" },
	{ "slot1", 2, 1, 0, 0, "2 (slot1)" },
	{ "slot0 with fatal bits", 1, 1, 0, 3, "1 (slot0)" },
	{ "slot1 with in-progress", 2, 15, 15, 0, "2 (slot1)" },
	{ "slot 3 undefined", 3, 1, 0, 0, "Undefined value" },

	/* 0: nothing wrong -> not-reported (the GPU case: auth OK, no error) */
	{ "primary ok", 0, 1, 0, 0, "0 (not-reported)" },
	{ "both ok", 0, 1, 1, 0, "0 (not-reported)" },
	{ "all zero", 0, 0, 0, 0, "0 (not-reported)" },
	/* An auth *error* is not "in progress"; FATAL_ERROR_CODE decides. */
	{ "auth error, no fatal", 0, 6, 0, 0, "0 (not-reported)" },

	/* 0: authentication in progress, in either field */
	{ "primary in progress", 0, 15, 0, 0,
	  "0 (authentication in progress)" },
	{ "secondary in progress", 0, 1, 15, 0,
	  "0 (authentication in progress)" },
	{ "both in progress", 0, 15, 15, 0, "0 (authentication in progress)" },

	/* 0: fatal error, any non-zero code (1..9 defined, 15 undefined) */
	{ "fatal 1", 0, 1, 0, 1, "0 (fatal error happened)" },
	{ "fatal 9", 0, 1, 0, 9, "0 (fatal error happened)" },
	{ "fatal 15", 0, 0, 0, 15, "0 (fatal error happened)" },
	/* Fatal outranks in progress. */
	{ "fatal and in progress", 0, 15, 0, 5, "0 (fatal error happened)" },
};

static void test_helper_directly(void)
{
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct tc *c = &cases[i];

		if (c->slot != 0)
			continue;
		set_resp(c->slot, c->primary, c->secondary, c->fatal);
		const char *got = ap0_release_slot_zero_text(g_resp, RESP_LEN);
		if (strcmp(got, c->want) != 0) {
			fprintf(stderr, "helper %s: got '%s' want '%s'\n",
				c->name, got, c->want);
			abort();
		}
	}
	printf("0-value decode truth table: OK\n");
}

static void test_text_and_json(void)
{
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct tc *c = &cases[i];
		char want[128];
		char *out;

		set_resp(c->slot, c->primary, c->secondary, c->fatal);

		out = capture(run_text);
		snprintf(want, sizeof(want), "AP0_RELEASE_SLOT");
		char *line = strstr(out, want);
		assert(line);
		if (!strstr(line, c->want) ||
		    strstr(line, c->want) > strchr(line, '\n')) {
			fprintf(stderr, "text %s: line not '%s':\n%s\n",
				c->name, c->want, line);
			abort();
		}

		out = capture(run_json);
		snprintf(want, sizeof(want), "\"AP0_RELEASE_SLOT\":\"%s\"",
			 c->want);
		if (!strstr(out, want)) {
			fprintf(stderr, "json %s: missing %s in:\n%s\n",
				c->name, want, out);
			abort();
		}
	}
	printf("text and JSON output: OK\n");
}

int main(void)
{
	test_helper_directly();
	test_text_and_json();
	printf("All AP0_RELEASE_SLOT tests passed\n");
	return 0;
}
