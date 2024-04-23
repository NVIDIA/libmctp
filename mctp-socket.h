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
#ifndef __MCTP_SOCKET_H__
#define __MCTP_SOCKET_H__

/* MCTP default Tx/Rx timeouts */
#define MCTP_CTRL_TXRX_TIMEOUT_5SECS 5
#define MCTP_CTRL_TXRX_TIMEOUT_16SECS 16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open the MCTp-VDM socket interface, return success only if
 *        Socket is opened and Register with the message type.
 *
 * @param[in] *intf - Socket interface name
 * @param[in] *path - Unix socket name
 * @param[in] msgtype - MCTP Message type
 * @param[in] timeout - MCTP Rx/Tx timeout
 *
 * @returns socket fd on successfull, errno on failure.
 */
mctp_requester_rc_t mctp_usr_socket_init(int *intf, const char *path,
					 uint8_t msgtype, time_t timeout);

/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a MCTP message.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[out] mctp_resp_msg - *mctp_resp_msg will point to MCTP msg,
 *             this function allocates memory, caller to free(*mctp_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the MCTP msg.
 *
 * @return int (errno may be set). failure is returned even
 *         when data was read, but wasn't a MCTP response message
 */
mctp_requester_rc_t mctp_client_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **mctp_resp_msg,
				     size_t *resp_msg_len);

/**
 * @brief Write MCTP socket. If the data is sent out, return success.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] mctp_req_msg - the request message will be sent out.
 * @param[in] req_msg_len - the length of the request message.
 *
 * @return int (errno may be set). failure is returned.
 */
mctp_requester_rc_t mctp_client_send(mctp_eid_t dest_eid, int mctp_fd,
				     uint8_t msgtype,
				     const uint8_t *mctp_req_msg,
				     size_t req_msg_len);

/**
 * @brief Write MCTP socket and then read  MCTP socket. If the read timeout incurs,
 *  there will be retry happening.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] mctp_req_msg - the request message will be sent to the enpoint.
 * @param[in] req_msg_len - the length of the request message.
 * @param[out] mctp_resp_msg - *mctp_resp_msg will point to MCTP msg,
 *             this function allocates memory, caller to free(*mctp_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the MCTP msg.
 *
 * @return int (errno may be set). failure is returned when either read or write
 *		socket failed.
 */
mctp_requester_rc_t mctp_client_send_recv(mctp_eid_t eid, int fd,
					  uint8_t msgtype,
					  const uint8_t *req_msg,
					  size_t req_len, uint8_t **resp_msg,
					  size_t *resp_len);
#ifdef __cplusplus
}
#endif

#endif /* __MCTP_SOCKET_H__ */
