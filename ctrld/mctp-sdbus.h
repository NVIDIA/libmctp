/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_SDBUS_H__
#define __MCTP_SDBUS_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCTP_GET_UUID_MAPPINGS "GetUUIDMap"
#define MCTP_GET_ROITUNG_INFO "GetRoutingInfo"

#define MCTP_CTRL_DBUS_NAME "xyz.openbmc_project.MCTP.Control"
#define MCTP_CTRL_OBJ_NAME "/xyz/openbmc_project/mctp"

#define MCTP_CTRL_NW_OBJ_PATH "/xyz/openbmc_project/mctp/0/"
#define MCTP_CTRL_DBUS_EP_INTERFACE "xyz.openbmc_project.MCTP.Endpoint"
#define MCTP_CTRL_DBUS_UUID_INTERFACE "xyz.openbmc_project.Common.UUID"
#define MCTP_CTRL_DBUS_SOCK_INTERFACE "xyz.openbmc_project.Common.UnixSocket"
#define MCTP_CTRL_DBUS_BINDING_INTERFACE "xyz.openbmc_project.MCTP.Binding"

#define MCTP_CTRL_SDBUS_OBJ_PATH_SIZE 1024
#define MCTP_CTRL_SDBUS_NMAE_SIZE 255
#define MCTP_CTRL_SDBUS_NETWORK_ID 0

#define MCTP_CTRL_SD_BUS_FD 0
#define MCTP_CTRL_SIGNAL_FD 1
#define MCTP_CTRL_TOTAL_FDS 2

#define MCTP_CTRL_POLL_TIMEOUT 1000
#define MCTP_CTRL_SDBUS_MAX_MSG_SIZE 256

#define DATA_PROPERTY "data"
#define DATA_SIGNATURE "(i)"

#define MCTP_CTRL_MAX_BUS_TYPES 4

/* MCTP ctrl D-Bus poll struct */
typedef struct mctp_sdbus_context {
	struct pollfd fds[MCTP_CTRL_TOTAL_FDS];
	struct sd_bus *bus;
} mctp_sdbus_context_t;

enum { SDBUS_POLLING_TIMEOUT = 1, SDBUS_PROCESS_EVENT };

/**
 * @brief initialize D-Bus objects for mctp ctrl servies and hanlde D-Bus requests
 *
 * @param[in] bus - destination MCTP eid
 * @param[in] signalfd - the signal fd to terminate threads,
 * @param[in] cmdline - the command line structure
 *
 * @return int (errno may be set). failure is returned.
 */
int mctp_ctrl_sdbus_init(sd_bus *bus, int signalfd,
			 const mctp_cmdline_args_t *cmdline);

/**
 * @brief stop serving the D-Bus requests
 *
 * @return N/A
 */
void mctp_ctrl_sdbus_stop(void);

/**
 * @brief D-Bus requests handling routine
 *
 * @param[in] context - mctp D-Bus context
 *
 * @return int (errno may be set). failure is returned.
 */
int mctp_ctrl_sdbus_dispatch(mctp_sdbus_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SDBUS_H__ */
