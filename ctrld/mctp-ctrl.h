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

/* Default socket path */
#define MCTP_SOCK_PATH_PCIE "\0mctp-pcie-mux"
#define MCTP_SOCK_PATH_SPI "\0mctp-spi-mux"
#define MCTP_SOCK_PATH_I2C "\0mctp-i2c-mux"
#define MCTP_SOCK_PATH_USB "\0mctp-usb-mux"


/* Define Max buffer size */
#define MCTP_RX_BUFFER_MAX_SIZE 64

/* Default destination eid table size */
#define MCTP_DEST_EID_TABLE_MAX	256

typedef uint8_t mctp_eid_t;

typedef enum {
	MCTP_CTRL_FD_SOCKET = 0,
	MCTP_CTRL_FD_NR,
} mctp_ctrl_poll_t;

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

	/* used for log and D-Bus requests */
	sd_bus *bus;

	/* Used only by MCTP SPI ctrl. */
	pthread_cond_t worker_cv;
	pthread_mutex_t worker_mtx;
	bool worker_is_ready;
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
void mctp_ctrl_print_buffer(const char *str, const uint8_t *buffer, int size);

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

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_CTRL_H__ */
