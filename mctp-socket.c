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
#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#define pr_fmt(x) "mctp-socket: " x

#include "libmctp.h"
#include "libmctp-log.h"
#include "libmctp-cmds.h"
#include "libmctp-externals.h"

#include "ctrld/mctp-ctrl-log.h"
#include "ctrld/mctp-ctrl-cmds.h"
#include "ctrld/mctp-ctrl.h"

#include "mctp-socket.h"

#include "vdm/nvidia/libmctp-vdm-cmds.h"

/* Set MCTP message Type */
const uint8_t MCTP_CTRL_MSG_TYPE = 0;
const uint8_t MCTP_MSG_TYPE_HDR = 0;

/* MCTP Tx/Rx timeouts */
#define MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS 0

/* MCTP TX/RX retry threshold */
#define MCTP_CMD_THRESHOLD 2

mctp_requester_rc_t mctp_usr_socket_init(int *fd, const char *path,
					 uint8_t msgtype, time_t time_out)
{
	int rc = -1;
	int len;
	struct sockaddr_un addr;
	struct timeval timeout;

	/* Set timeout as 5 seconds */
	timeout.tv_sec = time_out;
	timeout.tv_usec = MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS;

	/* Create a socket connection */
	*fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);

	MCTP_ASSERT_RET(*fd != -1, MCTP_REQUESTER_OPEN_FAIL,
			"open socket failed, errno=%d\n", errno);

	/* Register socket operations timeouts */
	if (setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
		       sizeof(timeout)) < 0) {
		MCTP_ERR("socket[%d] setsockopt failed\n", *fd);
	}

	addr.sun_family = AF_UNIX;

	/* skip the fist null terminated and plus one to the length */
	len = strlen(&path[1]) + 1;

	memcpy(addr.sun_path, path, len);

	/* Send a connect request to ther server */
	rc = connect(*fd, (struct sockaddr *)&addr,
		     sizeof(addr.sun_family) + len);
	if (-1 == rc) {
		close(*fd);
		if (path[0] == 0) {
			MCTP_ERR(
				"connect socket[%d] failed, error = %d, path = \\0%s\n",
				*fd, errno, &(path[1]));
		} else {
			MCTP_ERR(
				"connect socket[%d] failed, error = %d, path = %s\n",
				*fd, errno, path);
		}
		return MCTP_REQUESTER_OPEN_FAIL;
	}

	/* Register the type of the server */
	rc = write(*fd, &msgtype, sizeof(msgtype));
	if (-1 == rc) {
		MCTP_ERR("register to socket[%d] failed\n", *fd);
		close(*fd);
		return MCTP_REQUESTER_OPEN_FAIL;
	}

	return MCTP_REQUESTER_SUCCESS;
}

static mctp_requester_rc_t mctp_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **mctp_resp_msg,
				     size_t *resp_msg_len, mctp_eid_t *resp_eid)
{
	uint8_t tag = 0;
	size_t mctp_prefix_len = sizeof(tag) + sizeof(eid);
	uint8_t mctp_prefix[mctp_prefix_len];
	struct iovec iov[2];
	size_t mctp_len;
	size_t min_len = sizeof(tag) + sizeof(eid) + sizeof(MCTP_MSG_TYPE_HDR) +
			 sizeof(struct mctp_ctrl_cmd_msg_hdr);
	ssize_t length;

	length = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

	if (length < 0 && errno == EAGAIN) {
		mctp_prinfo("%s: Recv failed: due to timedout\n", __func__);
		return MCTP_REQUESTER_TIMEOUT;
	}

	if ((length <= 0) || (length > MCTP_MAX_MESSAGE_SIZE)) {
		mctp_prinfo(
			"%s: Recv failed: Invalid length: %zi or timedout\n",
			__func__, length);
		return MCTP_REQUESTER_RECV_FAIL;
	} else if (length < (ssize_t)min_len - 1) {
		/* read and discard */
		uint8_t buf[length];

		length = recv(mctp_fd, buf, length, 0);
		mctp_trace_common("mctp_recv_msg_invalid_len >", buf, length);
		return MCTP_REQUESTER_INVALID_RECV_LEN;
	} else {
		mctp_len = length - mctp_prefix_len;

		iov[0].iov_len = mctp_prefix_len;
		iov[0].iov_base = mctp_prefix;

		*mctp_resp_msg = malloc(mctp_len);

		MCTP_ASSERT_RET(*mctp_resp_msg != NULL,
				MCTP_REQUESTER_RECV_FAIL,
				"fail to allocate %zu bytes memory\n",
				mctp_len);

		iov[1].iov_len = mctp_len;
		iov[1].iov_base = *mctp_resp_msg;

		struct msghdr msg = { 0 };
		msg.msg_iov = iov;
		msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
		int bytes = recvmsg(mctp_fd, &msg, 0);

		mctp_trace_common("mctp_prefix_msg >", mctp_prefix,
				  mctp_prefix_len);
		mctp_trace_common("mctp_resp_msg >", *mctp_resp_msg, mctp_len);

		if (length != bytes) {
			MCTP_ERR(
				"free mctp_resp_msg MCTP_REQUESTER_INVALID_RECV_LEN\n");
			free(*mctp_resp_msg);
			return MCTP_REQUESTER_INVALID_RECV_LEN;
		}
		*resp_eid = mctp_prefix[1];

		/* Update the response length */
		*resp_msg_len = mctp_len;

		mctp_prdebug("%s: resp_msg_len: %zu, mctp_len: %zu\n", __func__,
			     *resp_msg_len, mctp_len);
		return MCTP_REQUESTER_SUCCESS;
	}

	return MCTP_REQUESTER_SUCCESS;
}

/* The function won't do eid checking mainly for mctp control messages,
 * especailly mctp discovery messages.
 * */
mctp_requester_rc_t mctp_client_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **mctp_resp_msg,
				     size_t *resp_msg_len)
{
	mctp_eid_t resp_eid[1] = { 0 };
	return mctp_recv(eid, mctp_fd, mctp_resp_msg, resp_msg_len, resp_eid);
}

/* The function will check EID and ignore the incomming response and receive
 * the response again if EID mismatches.
 * */
static mctp_requester_rc_t
mctp_client_recv_from_eid(mctp_eid_t eid, int mctp_fd, uint8_t cmd_code,
			  uint8_t **mctp_resp_msg, size_t *resp_msg_len)
{
	mctp_eid_t resp_eid[1] = { 0 };
	mctp_requester_rc_t rc;
	struct mctp_vendor_msg_hdr *resp;
	struct timespec now = { 0 };
	struct timespec prev = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &prev);
	do {
		rc = mctp_recv(eid, mctp_fd, mctp_resp_msg, resp_msg_len,
			       resp_eid);

		if (rc != MCTP_REQUESTER_SUCCESS) {
			return rc;
		}

		/* Skip msg type */
		resp = (struct mctp_vendor_msg_hdr *)(*mctp_resp_msg + 1);
		/* Mctp demux will forard the response to all mctp client
		 * registered with the same message type.
		 * We may receive the unexpected data and need to read it again
		 */
		if (eid == resp_eid[0] && cmd_code == resp->command_code) {
			break;
		}

		/* Remember command code before freeing the message */
		uint8_t resp_command_code = resp->command_code;

		/* free the msg and will read it again */
		free(*mctp_resp_msg);
		*mctp_resp_msg = NULL;

		/* set up the timer in case the response is missing and we will hit
		 * ifinite loop
		 */
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - prev.tv_sec) >
		    MCTP_CTRL_TXRX_TIMEOUT_16SECS) {
			fprintf(stderr,
				"recv timeout due to missing response.\n");
			return MCTP_REQUESTER_TIMEOUT;
		}

		if (eid != resp_eid[0]) {
			mctp_prdebug(
				"%s: I'm not the requester - %d, EID: %d\n",
				__func__, eid, resp_eid[0]);
		}

		if (cmd_code != resp_command_code) {
			mctp_prdebug(
				"%s: Command code 0x%02x is not requested command code 0x%02x\n",
				__func__, resp->command_code, cmd_code);
		}

	} while (1);

	return rc;
}

mctp_requester_rc_t mctp_client_send(mctp_eid_t dest_eid, int mctp_fd,
				     uint8_t msgtype,
				     const uint8_t *mctp_req_msg,
				     size_t req_msg_len)
{
	uint8_t hdr[3] = { LIBMCTP_TAG_OWNER_MASK |
				   ((msgtype == MCTP_MESSAGE_TYPE_VDIANA) ?
					    MCTP_TAG_VDM :
					    0),
			   dest_eid, msgtype };

	struct iovec iov[2];
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = (uint8_t *)mctp_req_msg;
	iov[1].iov_len = req_msg_len;

	struct msghdr msg = { 0 };
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	mctp_trace_common("mctp_req_msg >", mctp_req_msg, req_msg_len);
	ssize_t rc = sendmsg(mctp_fd, &msg, 0);

	MCTP_ASSERT_RET(rc != -1, MCTP_REQUESTER_SEND_FAIL,
			"failed to sendmsg\n");

	return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t mctp_client_send_recv(mctp_eid_t eid, int fd,
					  uint8_t msgtype,
					  const uint8_t *req_msg,
					  size_t req_len, uint8_t **resp_msg,
					  size_t *resp_len)
{
	mctp_requester_rc_t rc = -1;
	int retry_count = 0;
	uint8_t cmd_code;
	struct mctp_vendor_msg_hdr *req = NULL;

	while (1) {
		rc = mctp_client_send(eid, fd, msgtype, req_msg, req_len);

		MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, rc,
				"fail to send [rc: %d] request\n", rc);

		req = (struct mctp_vendor_msg_hdr *)req_msg;
		cmd_code = req->command_code;
		/* Receive the data again if EID mismatch */
		rc = mctp_client_recv_from_eid(eid, fd, cmd_code, resp_msg,
					       resp_len);

		if (rc == MCTP_REQUESTER_SUCCESS) {
			break;
		}
		/* Check if it's timedout or not */
		if (rc == MCTP_REQUESTER_TIMEOUT) {
			/* Increment the retry count */
			retry_count++;

			fprintf(stderr,
				"%s: MCTP Rx Command Timed out, retrying[%d]\n",
				__func__, retry_count);

			/* Increment retry count and check for Threshold */
			MCTP_ASSERT_RET(
				retry_count < MCTP_CMD_THRESHOLD,
				MCTP_REQUESTER_RECV_FAIL,
				"fail to recv [rc: %d], Reached threshold[%d]\n",
				rc, MCTP_CMD_THRESHOLD);

		} else {
			fprintf(stderr, "%s: MCTP Rx Invalid data [rc: %d]\n",
				__func__, rc);
			/* Report the failure in output file */
			return rc;
		}
	}

	return rc;
}
