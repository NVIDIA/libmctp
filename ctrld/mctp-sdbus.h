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
#define MCTP_CTRL_DBUS_DECORATOR_INTERFACE                                     \
	"xyz.openbmc_project.Inventory.Decorator.I2CDevice"
#define MCTP_CTRL_DBUS_ENABLE_INTERFACE "xyz.openbmc_project.Object.Enable"

#define MCTP_CTRL_SDBUS_OBJ_PATH_SIZE 1024
#define MCTP_CTRL_SDBUS_NMAE_SIZE 255
#define MCTP_CTRL_SDBUS_NETWORK_ID 0

#define MCTP_CTRL_SD_BUS_FD 0
#define MCTP_CTRL_SIGNAL_FD 1
#define MCTP_CTRL_SOCKET_FD 2
#define MCTP_CTRL_TIMER_FD  3
#define MCTP_CTRL_TOTAL_FDS 4
#ifdef MOCKUP_ENDPOINT
#define MCTP_CTRL_SD_MON_FD 5
#endif

#define MCTP_CTRL_POLL_TIMEOUT 1000
#define MCTP_CTRL_SDBUS_MAX_MSG_SIZE 256

#define DATA_PROPERTY "data"
#define DATA_SIGNATURE "(i)"

#define MCTP_CTRL_MAX_BUS_TYPES 4

#ifdef MOCKUP_ENDPOINT
/* MCTP sdbus extra watch */
typedef struct mctp_sdbus_fd_watch {
	int (*fd_event)(void *);
	void *ctx;
	int fd_mon;
} mctp_sdbus_fd_watch_t;
#endif

/* MCTP ctrl D-Bus poll struct */
typedef struct mctp_sdbus_context {
	struct pollfd fds[MCTP_CTRL_TOTAL_FDS];
	struct sd_bus *bus;
	const mctp_cmdline_args_t *cmdline;
#ifdef MOCKUP_ENDPOINT
	struct mctp_sdbus_fd_watch monitor;
#endif
} mctp_sdbus_context_t;

enum { SDBUS_POLLING_TIMEOUT = 1, SDBUS_PROCESS_EVENT };

/**
 * @brief initialize D-Bus objects for mctp ctrl servies and hanlde D-Bus requests
 *
 * @param[in] mctp_ctrl - the MCTP control main structure.
 * @param[in] signalfd - the signal fd to terminate threads,
 * @param[in] cmdline - the command line structure
 *
 * @return int (errno may be set). failure is returned.
 */
#ifdef MOCKUP_ENDPOINT
int mctp_ctrl_sdbus_init(mctp_ctrl_t *mctp_ctrl, int signalfd,
			 const mctp_cmdline_args_t *cmdline,
			 const mctp_sdbus_fd_watch_t *monfd);
#else
int mctp_ctrl_sdbus_init(mctp_ctrl_t *mctp_ctrl, int signalfd,
			 const mctp_cmdline_args_t *cmdline);
#endif

/**
 * @brief stop serving the D-Bus requests
 *
 * @return N/A
 */
void mctp_ctrl_sdbus_stop(void);

/**
 * @brief D-Bus requests handling routine
 *
 * @param[in] mctp_ctrl - The mctp ctrl object.
 * @param[in] context - mctp D-Bus context
 *
 * @return int (errno may be set). failure is returned.
 */
int mctp_ctrl_sdbus_dispatch(mctp_ctrl_t *mctp_ctrl,
			     mctp_sdbus_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SDBUS_H__ */
