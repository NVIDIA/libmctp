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
#define MCTP_VENDOR_CMD_SET_ENDPOINT_UUID   0x01
#define MCTP_VENDOR_CMD_BOOTCOMPLETE        0x02
#define MCTP_VENDOR_CMD_HEARTBEAT           0x03
#define MCTP_VENDOR_CMD_ENABLE_HEARTBEAT    0x04
#define MCTP_VENDOR_CMD_QUERYBOOTSTATUS     0x05
#define MCTP_VENDOR_CMD_DOWNLOAD_LOG        0x06
#define MCTP_VENDOR_CMD_ENABLE_IB_UPDATE    0x07
#define MCTP_VENDOR_CMD_SELFTEST            0x08
#define MCTP_VENDOR_CMD_BG_COPY             0x09
#define MCTP_VENDOR_CMD_RESTART             0x0A


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
        uint8_t slot  : 2;
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

struct mctp_vendor_cmd_enable_ib_update {
        struct mctp_vendor_msg_hdr vdr_msg_hdr;
        uint8_t enable;
} __attribute__((__packed__));

struct mctp_vendor_cmd_restartnoti {
        struct mctp_vendor_msg_hdr vdr_msg_hdr;
} __attribute__((__packed__));


/* MCTP-VDM encoder API's */
bool mctp_encode_vendor_cmd_selftest(struct mctp_vendor_cmd_selftest *cmd);
bool mctp_encode_vendor_cmd_bootcmplt(struct mctp_vendor_cmd_bootcmplt *cmd);
bool mctp_encode_vendor_cmd_bootcmplt_v2(struct mctp_vendor_cmd_bootcomplete_v2 *cmd);
bool mctp_encode_vendor_cmd_hbenable(struct mctp_vendor_cmd_hbenable *cmd);
bool mctp_encode_vendor_cmd_hbenvent(struct mctp_vendor_cmd_hbenvent *cmd);
bool mctp_encode_vendor_cmd_restartnoti(struct mctp_vendor_cmd_restartnoti *cmd);
bool mctp_encode_vendor_cmd_bootstatus(struct mctp_vendor_cmd_bootstatus *cmd);
bool mctp_encode_vendor_cmd_downloadlog(struct mctp_vendor_cmd_downloadlog *cmd, uint8_t session);
bool mctp_encode_vendor_cmd_background_copy(struct mctp_vendor_cmd_background_copy *cmd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_VDM_CMDS_H */
