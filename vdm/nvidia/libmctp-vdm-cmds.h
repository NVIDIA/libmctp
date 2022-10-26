/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_VDM_CMDS_H
#define _LIBMCTP_VDM_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

#define MCTP_CTRL_HDR_MSG_TYPE 0
#define MCTP_CTRL_HDR_FLAG_REQUEST (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F
#define MCTP_VENDOR_MSG_TYPE 0x7f

/* MCTP VDM Command codes */
#define MCTP_VENDOR_CMD_SET_ENDPOINT_UUID 0x01
#define MCTP_VENDOR_CMD_BOOTCOMPLETE 0x02
#define MCTP_VENDOR_CMD_HEARTBEAT 0x03
#define MCTP_VENDOR_CMD_ENABLE_HEARTBEAT 0x04
#define MCTP_VENDOR_CMD_QUERYBOOTSTATUS 0x05
#define MCTP_VENDOR_CMD_DOWNLOAD_LOG 0x06
#define MCTP_VENDOR_CMD_IN_BAND 0x07
#define MCTP_VENDOR_CMD_SELFTEST 0x08
#define MCTP_VENDOR_CMD_BG_COPY 0x09
#define MCTP_VENDOR_CMD_RESTART 0x0A
#define MCTP_VENDOR_CMD_DBG_TOKEN_INST 0xB
#define MCTP_VENDOR_CMD_DBG_TOKEN_ERASE 0xC
#define MCTP_VENDOR_CMD_CERTIFICATE_INSTALL 0xD
#define MCTP_VENDOR_CMD_DBG_TOKEN_QUERY 0xF

/* Download log buffer length */
#define MCTP_VDM_DOWNLOAD_LOG_BUFFER_SIZE 52

/* currently, we have three certificates. each one has 1k bytes at the wrose
 * case
 * 2(version)+2(size)+3K(certificate chain)+96(signature) = 3172 bytes
 * */
#define MCTP_CERTIFICATE_CHAIN_SIZE  3172

/* Maximum debug token size */
#define MCTP_DEBUG_TOKEN_SIZE 256

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
bool mctp_encode_vendor_cmd_dgb_token_query(
	struct mctp_vendor_cmd_dbg_token_query *cmd);
bool mctp_encode_vendor_cmd_certificate_install(
	struct mctp_vendor_cmd_certificate_install *cmd);
bool mctp_encode_vendor_cmd_in_band(
        struct mctp_vendor_cmd_in_band *cmd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_VDM_CMDS_H */
