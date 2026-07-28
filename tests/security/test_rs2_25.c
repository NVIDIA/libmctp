/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/*
 * Security regression test for finding RS2-25
 *   NVBug 6519382, CWE-787 (Out-of-bounds Write), mctp-socket.c
 *   ::mctp_usr_socket_init()
 *
 * THE BUG
 * -------
 * mctp_usr_socket_init() derives the socket-name length from the caller-supplied
 * `path` (an abstract AF_UNIX name: path[0]=='\0' followed by the name), then
 * memcpy()s that many bytes straight into the fixed addr.sun_path with no bound:
 *
 *     len = strlen(&path[1]) + 1;
 *     memcpy(addr.sun_path, path, len);      // len unbounded
 *
 * sun_path is 108 bytes; a name longer than that overflows the stack
 * sockaddr_un.  (The demux daemon's bind path in utils/mctp-demux-daemon.c has
 * the identical unbounded copy and the identical guard; this test exercises the
 * mctp-socket.c site.)
 *
 * THE FIX (mctp-socket.c, just before the copy)
 *     if (len > (int)sizeof(addr.sun_path)) {
 *         MCTP_ERR(...); return MCTP_REQUESTER_OPEN_FAIL;
 *     }
 * A name too long to fit sun_path is rejected before the copy.
 *
 * A/B METHOD
 * ----------
 * This test drives the REAL mctp_usr_socket_init() by #include'ing the
 * translation unit (mctp-socket.c). Build WITHOUT -DMCTP_IN_KERNEL so the
 * userspace-socket entry point is compiled.
 *
 *   - Fixed source under ASan: the overlong name is rejected with
 *     MCTP_REQUESTER_OPEN_FAIL before the copy; the test PASSES (no overflow).
 *   - A scratch copy with ONLY the length guard reverted: the memcpy writes
 *     ~200 bytes into the 108-byte sun_path and ASan aborts with
 *     "stack-buffer-overflow ... WRITE".
 *
 * Build (from repo root sources/libmctp; see UNIT-TESTING-AB-REGRESSIONS.md):
 *   printf '#ifndef _CONFIG_H\n#define _CONFIG_H\n#endif\n' > config.h
 *   gcc -g -O1 -fsanitize=address -I. -Itests tests/security/test_rs2_25.c \
 *       log.c -lsystemd -o /tmp/t_rs2_25
 *   ASAN_OPTIONS=detect_leaks=0 /tmp/t_rs2_25
 */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Pull in the real translation unit to reach mctp_usr_socket_init(). */
#include "../../mctp-socket.c"

/* An abstract socket name far longer than sun_path (108). */
#define OVERLONG_NAME 200

static void test_rs2_25_overlong_socket_name(void)
{
	char path[1 + OVERLONG_NAME + 1];
	int fd = -1;
	mctp_requester_rc_t rc;

	/* Make the precondition explicit: name length exceeds sun_path. */
	assert((size_t)(OVERLONG_NAME + 1) > sizeof(((struct sockaddr_un *)0)->sun_path));
	printf("  name bytes=%d sun_path=%zu\n", OVERLONG_NAME + 1,
	       sizeof(((struct sockaddr_un *)0)->sun_path));

	/* Abstract name: leading NUL, then OVERLONG_NAME non-NUL bytes. */
	path[0] = '\0';
	memset(&path[1], 'a', OVERLONG_NAME);
	path[1 + OVERLONG_NAME] = '\0';

	/*
	 * Drive the REAL function.
	 *
	 * FIXED source  : len (== 201) > sizeof(sun_path) (== 108), so the guard
	 *                 returns MCTP_REQUESTER_OPEN_FAIL before the copy.
	 * PRE-FIX source: memcpy(addr.sun_path, path, 201) overflows the 108-byte
	 *                 stack sun_path -> ASan aborts HERE with
	 *                 "stack-buffer-overflow ... WRITE".
	 */
	rc = mctp_usr_socket_init(&fd, path, MCTP_MESSAGE_TYPE_VDIANA, 1,
				  false);

	/* Only reached on the FIXED tree. */
	assert(rc == MCTP_REQUESTER_OPEN_FAIL);
	printf("  mctp_usr_socket_init() rejected overlong socket name (rc=%d) - no overflow\n",
	       rc);

	if (fd >= 0)
		close(fd);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	printf("test: test_rs2_25_overlong_socket_name\n");
	test_rs2_25_overlong_socket_name();

	printf("RS2-25 security regression test passed "
	       "(mctp_usr_socket_init rejects overlong socket names)\n");
	return EXIT_SUCCESS;
}
