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
#ifndef _LIBMCTP_VDM_CMDS_H
#define _LIBMCTP_VDM_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

#define MCTP_CTRL_HDR_MSG_TYPE	       0
#define MCTP_CTRL_HDR_FLAG_REQUEST     (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM       (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F
#define MCTP_VENDOR_MSG_TYPE	       0x7f

/* MCTP VDM Command codes */
#define MCTP_VENDOR_CMD_SET_ENDPOINT_UUID   0x01
#define MCTP_VENDOR_CMD_BOOTCOMPLETE	    0x02
#define MCTP_VENDOR_CMD_HEARTBEAT	    0x03
#define MCTP_VENDOR_CMD_ENABLE_HEARTBEAT    0x04
#define MCTP_VENDOR_CMD_QUERYBOOTSTATUS	    0x05
#define MCTP_VENDOR_CMD_DOWNLOAD_LOG	    0x06
#define MCTP_VENDOR_CMD_IN_BAND		    0x07
#define MCTP_VENDOR_CMD_SELFTEST	    0x08
#define MCTP_VENDOR_CMD_BG_COPY		    0x09
#define MCTP_VENDOR_CMD_RESTART		    0x0A
#define MCTP_VENDOR_CMD_DBG_TOKEN_INST	    0xB
#define MCTP_VENDOR_CMD_DBG_TOKEN_ERASE	    0xC
#define MCTP_VENDOR_CMD_CERTIFICATE_INSTALL 0xD
#define MCTP_VENDOR_CMD_DBG_TOKEN_QUERY	    0xF
#define MCTP_VENDOR_CMD_SET_QUERY_BOOT_MODE 0x11
#define MCTP_VENDOR_CMD_BOOT_AP		    0x12
#define MCTP_VENDOR_CMD_CAK_INSTALL	    0x14
#define MCTP_VENDOR_CMD_CAK_LOCK	    0x15
#define MCTP_VENDOR_CMD_CAK_TEST	    0x16
#define MCTP_VENDOR_CMD_DOT_DISABLE	    0x17
#define MCTP_VENDOR_CMD_DOT_TOKEN_INST	    0x18
#define MCTP_VENDOR_CMD_FORCE_GRANT_REVOKED 0x19
#define MCTP_VENDOR_CMD_RESET_EROT	    0x1A
#define MCTP_VENDOR_CMD_REVOKE_AP_OTP	    0x1B

/* Download log buffer length */
#define MCTP_VDM_DOWNLOAD_LOG_BUFFER_SIZE 52

/* currently, we have three certificates. each one has 1k bytes at the wrose
 * case
 * 2(version)+2(size)+3K(certificate chain)+96(signature) = 3172 bytes
 * */
#define MCTP_CERTIFICATE_CHAIN_SIZE 3172

/* ECDSA P 384 DOT key length */
#define MCTP_ECDSA_P_384_DOT_ENABLE_KEY 96

#define MCTP_CAK_COMMAND_PAYLOAD_LEN (MCTP_ECDSA_P_384_DOT_ENABLE_KEY + 99)

/* Maximum debug token size */
#define MCTP_DEBUG_TOKEN_SIZE 4096

/* Maximum DOT token size */
#define MCTP_DOT_TOKEN_SIZE 256

struct mctp_vendor_msg_hdr {
	uint32_t iana;
	uint8_t rq_dgram_inst;
	uint8_t vendor_msg_type;
	uint8_t command_code;
	uint8_t msg_version;
} __attribute__((__packed__));

struct mctp_vendor_cmd_selftest {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t payload[4];
} __attribute__((__packed__));

struct mctp_vendor_cmd_bootcmplt {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_bootcomplete_v2 {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t slot : 2;
	uint8_t valid : 6;
	uint8_t rvsd1;
	uint8_t rvsd2;
} __attribute__((__packed__));

struct mctp_vendor_cmd_hbenvent {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_hbenable {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t enable;
} __attribute__((__packed__));

struct mctp_vendor_cmd_background_copy {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t code;
} __attribute__((__packed__));

struct mctp_vendor_cmd_bootstatus {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_downloadlog {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t session_id;
} __attribute__((__packed__));

/* MCTP-VDM Download log response structure */
struct mctp_vendor_cmd_downloadlog_resp {
	uint8_t msg_type;
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t cc;
	uint8_t session;
	uint8_t length;
	uint8_t data[MCTP_VDM_DOWNLOAD_LOG_BUFFER_SIZE];
} __attribute__((__packed__));

struct mctp_vendor_cmd_in_band {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t code;
} __attribute__((__packed__));

struct mctp_vendor_cmd_restartnoti {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_dbg_token_inst {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_DEBUG_TOKEN_SIZE];
} __attribute__((__packed__));

struct mctp_vendor_cmd_dbg_token_erase {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_dbg_token_query {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_certificate_install {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_CERTIFICATE_CHAIN_SIZE];
} __attribute__((__packed__));

struct mctp_vendor_cmd_boot_ap {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_set_query_boot_mode {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t code;
} __attribute__((__packed__));

struct mctp_vendor_cmd_cak_install {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_ECDSA_P_384_DOT_ENABLE_KEY];
	uint8_t cak_disable;
	uint8_t ap_fw_metadata_signature[96];
	uint8_t ap_fw_metadata_rbp[2];
} __attribute__((__packed__));

struct mctp_vendor_cmd_cak_lock {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_ECDSA_P_384_DOT_ENABLE_KEY];
} __attribute__((__packed__));

struct mctp_vendor_cmd_cak_test {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_dot_disable {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_ECDSA_P_384_DOT_ENABLE_KEY];
} __attribute__((__packed__));

struct mctp_vendor_cmd_dot_token_inst {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	unsigned char payload[MCTP_DOT_TOKEN_SIZE];
} __attribute__((__packed__));

struct mctp_vendor_cmd_force_grant_revoked {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t code;
} __attribute__((__packed__));

struct mctp_vendor_cmd_reset_erot {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));

struct mctp_vendor_cmd_revoke_ap_otp {
	struct mctp_vendor_msg_hdr vdr_msg_hdr;
	uint8_t code;
} __attribute__((__packed__));

/* MCTP-VDM encoder API's */
bool mctp_encode_vendor_cmd_selftest(struct mctp_vendor_cmd_selftest *cmd);
bool mctp_encode_vendor_cmd_bootcmplt(struct mctp_vendor_cmd_bootcmplt *cmd);
bool mctp_encode_vendor_cmd_bootcmplt_v2(
	struct mctp_vendor_cmd_bootcomplete_v2 *cmd);
bool mctp_encode_vendor_cmd_hbenable(struct mctp_vendor_cmd_hbenable *cmd);
bool mctp_encode_vendor_cmd_hbenvent(struct mctp_vendor_cmd_hbenvent *cmd);
bool mctp_encode_vendor_cmd_restartnoti(struct mctp_vendor_cmd_restartnoti *cmd);
bool mctp_encode_vendor_cmd_bootstatus(struct mctp_vendor_cmd_bootstatus *cmd);
bool mctp_encode_vendor_cmd_downloadlog(struct mctp_vendor_cmd_downloadlog *cmd,
					uint8_t session);
bool mctp_encode_vendor_cmd_background_copy(
	struct mctp_vendor_cmd_background_copy *cmd);
bool mctp_encode_vendor_cmd_dbg_token_inst(
	struct mctp_vendor_cmd_dbg_token_inst *cmd);
bool mctp_encode_vendor_cmd_dbg_token_erase(
	struct mctp_vendor_cmd_dbg_token_erase *cmd);
bool mctp_encode_vendor_cmd_dbg_token_query(
	struct mctp_vendor_cmd_dbg_token_query *cmd);
bool mctp_encode_vendor_cmd_dbg_token_query_v2(
	struct mctp_vendor_cmd_dbg_token_query *cmd);
bool mctp_encode_vendor_cmd_certificate_install(
	struct mctp_vendor_cmd_certificate_install *cmd);
bool mctp_encode_vendor_cmd_in_band(struct mctp_vendor_cmd_in_band *cmd);
bool mctp_encode_vendor_cmd_boot_ap(struct mctp_vendor_cmd_boot_ap *cmd);
bool mctp_encode_vendor_cmd_set_query_boot_mode(
	struct mctp_vendor_cmd_set_query_boot_mode *cmd);
bool mctp_encode_vendor_cmd_cak_install(struct mctp_vendor_cmd_cak_install *cmd);
bool mctp_encode_vendor_cmd_cak_lock(struct mctp_vendor_cmd_cak_lock *cmd);
bool mctp_encode_vendor_cmd_cak_test(struct mctp_vendor_cmd_cak_test *cmd);
bool mctp_encode_vendor_cmd_dot_disable(struct mctp_vendor_cmd_dot_disable *cmd);
bool mctp_encode_vendor_cmd_dot_token_inst(
	struct mctp_vendor_cmd_dot_token_inst *cmd);
bool mctp_encode_vendor_cmd_force_grant_revoked(
	struct mctp_vendor_cmd_force_grant_revoked *cmd);
bool mctp_encode_vendor_cmd_reset_erot(struct mctp_vendor_cmd_reset_erot *cmd);
bool mctp_encode_vendor_cmd_revoke_ap_otp(
	struct mctp_vendor_cmd_revoke_ap_otp *cmd);
#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_VDM_CMDS_H */
