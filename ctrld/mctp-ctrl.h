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

#ifndef __MCTP_CTRL_H__
#define __MCTP_CTRL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include <systemd/sd-bus.h>

#include "mctp-ctrl-cmdline.h"
#include "../config.h"

/* Default socket path */
#define MCTP_SOCK_PATH_PCIE "\0mctp-pcie-mux"
#define MCTP_SOCK_PATH_SPI  "\0mctp-spi-mux"
#define MCTP_SOCK_PATH_I2C  "\0mctp-i2c-mux"
#define MCTP_SOCK_PATH_USB  "\0mctp-usb-mux"

/* Define Max buffer size */
#define MCTP_RX_BUFFER_MAX_SIZE 64

/* Default destination eid table size */
#define MCTP_DEST_EID_TABLE_MAX 256

/* Runtime debug configuration files */
#define MCTP_CTRL_EMU_CFG_DIR	    "/tmp"
#define MCTP_CTRL_EMU_CFG_FILE	    "mctp-ctrl-emu.json"
#define MCTP_CTRL_EMU_CFG_JSON_ROOT "mctp_demux_pcie_emu"

typedef uint8_t mctp_eid_t;

typedef struct {
	uint8_t eid;
	size_t resp_msg_len;
	int sock;
	uint8_t type;
	const char *message;
	uint8_t rx_buffer[MCTP_RX_BUFFER_MAX_SIZE];
	void *pvt_binding_data;
	unsigned int pvt_binding_len;
	struct pollfd *pollfds;
	mctp_cmdline_args_t *cmdline;

	/* used for log and D-Bus requests */
	sd_bus *bus;

	/* Used only by MCTP SPI ctrl. */
	pthread_cond_t worker_cv;
	pthread_mutex_t worker_mtx;
	bool worker_is_ready;
	bool perform_rediscovery;
} mctp_ctrl_t;

/* MCTP ctrl requester return codes */
typedef enum mctp_requester_error_codes {
	MCTP_REQUESTER_SUCCESS = 0,
	MCTP_REQUESTER_OPEN_FAIL = -1,
	MCTP_REQUESTER_NOT_MCTP_MSG = -2,
	MCTP_REQUESTER_NOT_RESP_MSG = -3,
	MCTP_REQUESTER_NOT_REQ_MSG = -4,
	MCTP_REQUESTER_RESP_MSG_TOO_SMALL = -5,
	MCTP_REQUESTER_INSTANCE_ID_MISMATCH = -6,
	MCTP_REQUESTER_SEND_FAIL = -7,
	MCTP_REQUESTER_RECV_FAIL = -8,
	MCTP_REQUESTER_INVALID_RECV_LEN = -9,
	MCTP_REQUESTER_TIMEOUT = -10,
} mctp_requester_rc_t;

/* MCTP ctrl return codes */
typedef enum {
	MCTP_CMD_SUCCESS,
	MCTP_CMD_FAILED,
	MCTP_RET_ENCODE_SUCCESS,
	MCTP_RET_DECODE_SUCCESS,
	MCTP_RET_REQUEST_SUCCESS,
	MCTP_RET_DISCOVERY_SUCCESS,
	MCTP_RET_ROUTING_TABLE_FOUND,
	MCTP_RET_ENCODE_FAILED,
	MCTP_RET_DECODE_FAILED,
	MCTP_RET_REQUEST_FAILED,
	MCTP_RET_DISCOVERY_FAILED,
	MCTP_RET_DEVICE_NOT_READY,
} mctp_ret_codes_t;

/* Function prototypes */
int mctp_event_monitor(mctp_ctrl_t *mctp_evt);

mctp_requester_rc_t mctp_client_send(mctp_eid_t dest_eid, int mctp_fd,
				     uint8_t msgtype,
				     const uint8_t *mctp_req_msg,
				     size_t req_msg_len);

mctp_requester_rc_t
mctp_client_with_binding_send(mctp_eid_t dest_eid, int mctp_fd,
			      const uint8_t *mctp_req_msg, size_t req_msg_len,
			      const mctp_binding_ids_t *bind_id,
			      void *mctp_binding_info, size_t mctp_binding_len);

uint16_t mctp_ctrl_get_target_bdf(const mctp_cmdline_args_t *cmd);

mctp_requester_rc_t mctp_client_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **mctp_resp_msg,
				     size_t *resp_msg_len);

int main_ctrl(int argc, char *const *argv);

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_CTRL_H__ */
