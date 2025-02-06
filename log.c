/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <systemd/sd-journal.h>

#include "libmctp.h"
#include "libmctp-log.h"

#include <syslog.h>

enum {
	MCTP_LOG_NONE,
	MCTP_LOG_STDIO,
	MCTP_LOG_SYSLOG,
	MCTP_LOG_CUSTOM,
} log_type = MCTP_LOG_NONE;

static int log_stdio_level;
static void (*log_custom_fn)(int, const char *, va_list);

#define MAX_TRACE_BYTES	  5120
#define TRACE_FORMAT	  "%02X "
#define TRACE_FORMAT_SIZE 3
#define FORMATTED_MSG_SIZE 4096

static bool trace_enable;

void mctp_prlog(int level, const char *fmt, ...)
{
	static const char *syslog_identifier = NULL;
	if (syslog_identifier == NULL) {
		syslog_identifier = getenv("SYSLOG_IDENTIFIER");
		if (!syslog_identifier) {
			syslog_identifier = "mctp-demux"; // Default value.
		}
	}
	va_list ap;
	va_start(ap, fmt);

	int syslog_level = LOG_INFO;
	switch (level) {
	case MCTP_LOG_ERR:
		syslog_level = LOG_ERR;
		break;
	case MCTP_LOG_WARNING:
		syslog_level = LOG_WARNING;
		break;
	case MCTP_LOG_NOTICE:
		syslog_level = LOG_NOTICE;
		break;
	case MCTP_LOG_INFO:
		syslog_level = LOG_INFO;
		break;
	case MCTP_LOG_DEBUG:
		syslog_level = LOG_DEBUG;
		break;
	default:
		syslog_level = LOG_INFO;
		break;
	}
	switch (log_type) {
	case MCTP_LOG_NONE:
		break;
	case MCTP_LOG_STDIO:
#ifdef MCTP_LOG_TO_JOURNAL
	{
		if (level <= log_stdio_level) {
			char formatted_message[FORMATTED_MSG_SIZE];
			vsnprintf(formatted_message, sizeof(formatted_message),
				  fmt, ap);
			sd_journal_send("PRIORITY=%d", syslog_level,
					"SYSLOG_IDENTIFIER=%s",
					syslog_identifier, "MESSAGE=%s",
					formatted_message, NULL);
		}
	}
#else
	{
		if (level <= log_stdio_level) {
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			fprintf(stderr, "%llu-%llu ",
				(unsigned long long)ts.tv_sec,
				ts.tv_nsec / 1000000ULL);

			vfprintf(stderr, fmt, ap);
			fputs("\n", stderr);
			fflush(stderr);
		}
	}
#endif
	break;
	case MCTP_LOG_SYSLOG:
		vsyslog(syslog_level, fmt, ap);
		break;
	case MCTP_LOG_CUSTOM:
		log_custom_fn(level, fmt, ap);
		break;
	}
	va_end(ap);
}

void mctp_set_log_stdio(int level)
{
	log_type = MCTP_LOG_STDIO;
	log_stdio_level = level;
}

void mctp_set_log_syslog(void)
{
	log_type = MCTP_LOG_SYSLOG;
}

void mctp_set_log_custom(void (*fn)(int, const char *, va_list))
{
	log_type = MCTP_LOG_CUSTOM;
	log_custom_fn = fn;
}

void mctp_set_tracing_enabled(bool enable)
{
	trace_enable = enable;
}

void mctp_trace_common(const char *tag, const void *const payload,
		       const size_t len)
{
	char tracebuf[MAX_TRACE_BYTES * TRACE_FORMAT_SIZE + sizeof('\0')];
	/* if len is bigger than ::MAX_TRACE_BYTES, loop will leave place for '..'
	 * at the end to indicate that whole payload didn't fit
	 */
	const size_t limit = len > MAX_TRACE_BYTES ? MAX_TRACE_BYTES - 1 : len;
	char *ptr = tracebuf;
	unsigned int i;

	if (!trace_enable || len == 0)
		return;

	for (i = 0; i < limit; i++)
		ptr += sprintf(ptr, TRACE_FORMAT, ((uint8_t *)payload)[i]);

	/* buffer saturated, probably need to increase the size */
	if (limit < len)
		sprintf(ptr, "..");

	mctp_prdebug("%s %s", tag, tracebuf);
}
