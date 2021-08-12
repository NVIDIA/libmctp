/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_CTRL_LOG_H__
#define __MCTP_CTRL_LOG_H__

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>


static inline void mctp_ctrl_prlog(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);
}


/* libmctp-internal logging */

void mctp_ctrl_prlog(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#ifndef pr_fmt
#define pr_fmt(x) x
#endif

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_LOG_ERR        3
#define MCTP_LOG_WARNING    4
#define MCTP_LOG_NOTICE     5
#define MCTP_LOG_INFO       6
#define MCTP_LOG_DEBUG      7


#define MCTP_CTRL_ERR(fmt, ...)                                                   \
    mctp_ctrl_prlog(MCTP_LOG_ERR, pr_fmt(fmt), ##__VA_ARGS__)
#define MCTP_CTRL_WARN(fmt, ...)                                                  \
    mctp_ctrl_prlog(MCTP_LOG_WARNING, pr_fmt(fmt), ##__VA_ARGS__)
#define MCTP_CTRL_INFO(fmt, ...)                                                  \
    mctp_ctrl_prlog(MCTP_LOG_INFO, pr_fmt(fmt), ##__VA_ARGS__)
#define MCTP_CTRL_DEBUG(fmt, ...)                                                 \
    mctp_ctrl_prlog(MCTP_LOG_DEBUG, pr_fmt(fmt), ##__VA_ARGS__)

#endif /* __MCTP_CTRL_LOG_H__ */
