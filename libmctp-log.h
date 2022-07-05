/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_LOG_H
#define _LIBMCTP_LOG_H

#include <stddef.h>
#include <stdlib.h>

/* libmctp-internal logging */

void mctp_prlog(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

void mctp_trace_common(const char *tag, const void *const payload,
		       const size_t len);

#ifndef pr_fmt
#define pr_fmt(x) x
#endif

#define mctp_prerr(fmt, ...)                                                   \
	mctp_prlog(MCTP_LOG_ERR, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prwarn(fmt, ...)                                                  \
	mctp_prlog(MCTP_LOG_WARNING, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prinfo(fmt, ...)                                                  \
	mctp_prlog(MCTP_LOG_INFO, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prdebug(fmt, ...)                                                 \
	mctp_prlog(MCTP_LOG_DEBUG, pr_fmt(fmt), ##__VA_ARGS__)

#define MCTP_ASSERT(cond, fmt, ...) do {					\
	if (!(cond)) {								\
		mctp_prerr("at %s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
		abort();							\
	}									\
} while(0)

#define MCTP_ASSERT_RET(cond, ret, fmt, ...) do {				\
	if (!(cond)) {								\
		mctp_prerr("at %s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
		return (ret);							\
	}									\
} while(0)

#define mctp_trace_rx(payload, len)                                            \
	mctp_trace_common(pr_fmt("<RX<"), (payload), (len))
#define mctp_trace_tx(payload, len)                                            \
	mctp_trace_common(pr_fmt(">TX>"), (payload), (len))

#endif /* _LIBMCTP_LOG_H */
