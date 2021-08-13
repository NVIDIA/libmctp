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
    va_end(ap);
}

extern uint8_t g_verbose_level;

/* libmctp-internal logging */

void mctp_ctrl_prlog(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static enum {
   MCTP_CTRL_LOG_NONE = 0,
   MCTP_CTRL_LOG_VERBOSE,
   MCTP_CTRL_LOG_DEBUG
} mctp_ctrl_verbosity_t;

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

#define MCTP_CTRL_DEBUG(f_, ...) do { if (g_verbose_level >= MCTP_CTRL_LOG_VERBOSE) \
                { mctp_ctrl_prlog(MCTP_LOG_INFO, f_, ##__VA_ARGS__); } } while(0)

#define MCTP_CTRL_TRACE(f_, ...) do { if (g_verbose_level == MCTP_CTRL_LOG_VERBOSE)  \
                { mctp_ctrl_prlog(MCTP_LOG_INFO, f_, ##__VA_ARGS__); } } while(0)


#endif /* __MCTP_CTRL_LOG_H__ */

