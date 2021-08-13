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

#define MCTP_GET_UUID_MAPPINGS          "GetUUIDMap"
#define MCTP_GET_ROITUNG_INFO           "GetRoutingInfo"

#define MCTP_CTRL_DBUS_NAME             "xyz.openbmc_project.MCTP.Control"
#define MCTP_CTRL_OBJ_NAME              "/xyz/openbmc_project/mctp"

#define MCTP_CTRL_NW_OBJ_PATH           "/xyz/openbmc_project/mctp/0/"
#define MCTP_CTRL_DBUS_EP_INTERFACE     "xyz.openbmc_project.MCTP.Endpoint"
#define MCTP_CTRL_DBUS_UUID_INTERFACE   "xyz.openbmc_project.Common.UUID"

#define MCTP_CTRL_SDBUS_OBJ_PATH_SIZE   1024
#define MCTP_CTRL_SDBUS_NETWORK_ID      0

#define MCTP_CTRL_SD_BUS_FD             0
#define MCTP_CTRL_TOTAL_FDS             1

#define MCTP_CTRL_POLL_TIMEOUT          1000
#define MCTP_CTRL_SDBUS_MAX_MSG_SIZE    256

#define DATA_PROPERTY                   "data"
#define DATA_SIGNATURE                  "(i)"

/* MCTP ctrl sdbus poll struct */
typedef struct mctp_sdbus_context {
    struct pollfd fds[MCTP_CTRL_TOTAL_FDS];
    struct sd_bus *bus;
} mctp_sdbus_context_t;

/* MCTP ctrl supported bus types */
typedef enum {
    MCTP_CTRL_PCIE_BUS_TYPE,
    MCTP_CTRL_SPI_BUS_TYPE,
    MCTP_CTRL_I2C_BUS_TYPE,
    MCTP_CTRL_MAX_BUS_TYPES
} mctp_ctrl_max_supported_types_t;

int mctp_ctrl_sdbus_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SDBUS_H__ */
