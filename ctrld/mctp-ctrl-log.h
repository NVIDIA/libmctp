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
/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_CTRL_LOG_H__
#define __MCTP_CTRL_LOG_H__

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <systemd/sd-journal.h>

static inline void mctp_ctrl_prlog(int level, const char *fmt, ...)
{
	va_list ap;

	(void)level;
	va_start(ap, fmt);
#ifdef MCTP_LOG_TO_JOURNAL
	int syslog_level;
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
	const char *syslog_identifier = getenv("SYSLOG_IDENTIFIER");
	if (!syslog_identifier) {
		syslog_identifier = "mctp-ctrl"; // Default value.
	}
	char formatted_message[4096];
	vsnprintf(formatted_message, sizeof(formatted_message), fmt, ap);
	sd_journal_send("PRIORITY=%d", syslog_level, "SYSLOG_IDENTIFIER=%s",
			syslog_identifier, "MESSAGE=%s", formatted_message,
			NULL);
#else
	vfprintf(stderr, fmt, ap);
	fflush(stderr);
#endif
	va_end(ap);
}

extern uint8_t g_verbose_level;

/* libmctp-internal logging */

void mctp_ctrl_prlog(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

enum { MCTP_CTRL_LOG_NONE = 0, MCTP_CTRL_LOG_VERBOSE, MCTP_CTRL_LOG_DEBUG };

#ifndef pr_fmt
#define pr_fmt(x) x
#endif

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_LOG_ERR	 3
#define MCTP_LOG_WARNING 4
#define MCTP_LOG_NOTICE	 5
#define MCTP_LOG_INFO	 6
#define MCTP_LOG_DEBUG	 7

#define MCTP_CTRL_ERR(fmt, ...)                                                \
	mctp_ctrl_prlog(MCTP_LOG_ERR, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_CTRL_WARN(fmt, ...)                                               \
	mctp_ctrl_prlog(MCTP_LOG_WARNING, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_CTRL_INFO(fmt, ...)                                               \
	mctp_ctrl_prlog(MCTP_LOG_INFO, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_CTRL_DEBUG(f_, ...)                                               \
	do {                                                                   \
		if (g_verbose_level >= MCTP_CTRL_LOG_VERBOSE) {                \
			mctp_ctrl_prlog(MCTP_LOG_INFO, f_, ##__VA_ARGS__);     \
		}                                                              \
	} while (0)

#define MCTP_CTRL_TRACE(f_, ...)                                               \
	do {                                                                   \
		if (g_verbose_level == MCTP_CTRL_LOG_VERBOSE) {                \
			mctp_ctrl_prlog(MCTP_LOG_INFO, f_, ##__VA_ARGS__);     \
		}                                                              \
	} while (0)

#endif /* __MCTP_CTRL_LOG_H__ */
