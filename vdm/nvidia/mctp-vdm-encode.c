/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "mctp-vdm-nvda.h"

/* Default instance ID macro */
#define MCTP_VDM_INSTANCE_ID_DEFAULT 0x00

/* VDM Header macros */
#define MCTP_VDM_HDR_IANA	     0x1647
#define MCTP_VDM_HDR_VENDOR_MSG_TYPE 0x01
#define MCTP_VDM_HDR_MSG_VER_1	     0x01
#define MCTP_VDM_HDR_MSG_VER_2	     0x02

#define ENCODE_VMD_CMD_FUNC(_name)                                             \
	do {                                                                   \
		MCTP_ASSERT_RET(cmd != NULL, false, "cmd is NULL\n");          \
		encode_vendor_cmd_header(&cmd->vdr_msg_hdr, getRqDgramInst(),  \
					 MCTP_VENDOR_CMD_##_name);             \
		return true;                                                   \
	} while (0)

static uint8_t createInstanceId()
{
	static uint8_t instanceId = MCTP_VDM_INSTANCE_ID_DEFAULT;

	instanceId = (instanceId)&MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	return instanceId;
}

static uint8_t getRqDgramInst()
{
	uint8_t instanceID = createInstanceId();
	uint8_t rqDgramInst = instanceID | MCTP_CTRL_HDR_FLAG_REQUEST;
	return rqDgramInst;
}

static void encode_vendor_cmd_header(struct mctp_vendor_msg_hdr *mctp_vdr_hdr,
				     uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_vdr_hdr->iana = MCTP_VDM_HDR_IANA;
	mctp_vdr_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_vdr_hdr->vendor_msg_type = MCTP_VDM_HDR_VENDOR_MSG_TYPE;
	mctp_vdr_hdr->command_code = cmd_code;
	mctp_vdr_hdr->msg_version = MCTP_VDM_HDR_MSG_VER_1;
}

bool mctp_encode_vendor_cmd_dbg_token_inst(
	struct mctp_vendor_cmd_dbg_token_inst *cmd)
{
	ENCODE_VMD_CMD_FUNC(DBG_TOKEN_INST);
}

bool mctp_encode_vendor_cmd_dbg_token_erase(
	struct mctp_vendor_cmd_dbg_token_erase *cmd)
{
	ENCODE_VMD_CMD_FUNC(DBG_TOKEN_ERASE);
}

bool mctp_encode_vendor_cmd_dbg_token_query(
	struct mctp_vendor_cmd_dbg_token_query *cmd)
{
	ENCODE_VMD_CMD_FUNC(DBG_TOKEN_QUERY);
}

bool mctp_encode_vendor_cmd_cak_install(struct mctp_vendor_cmd_cak_install *cmd)
{
	ENCODE_VMD_CMD_FUNC(CAK_INSTALL);
}

bool mctp_encode_vendor_cmd_cak_lock(struct mctp_vendor_cmd_cak_lock *cmd)
{
	ENCODE_VMD_CMD_FUNC(CAK_LOCK);
}

bool mctp_encode_vendor_cmd_cak_test(struct mctp_vendor_cmd_cak_test *cmd)
{
	ENCODE_VMD_CMD_FUNC(CAK_TEST);
}

bool mctp_encode_vendor_cmd_dot_disable(struct mctp_vendor_cmd_dot_disable *cmd)
{
	ENCODE_VMD_CMD_FUNC(DOT_DISABLE);
}

bool mctp_encode_vendor_cmd_dot_token_inst(
	struct mctp_vendor_cmd_dot_token_inst *cmd)
{
	ENCODE_VMD_CMD_FUNC(DOT_TOKEN_INST);
}

bool mctp_encode_vendor_cmd_selftest(struct mctp_vendor_cmd_selftest *cmd)
{
	MCTP_ASSERT_RET(cmd != NULL, false, "cmd is NULL\n");

	encode_vendor_cmd_header(&cmd->vdr_msg_hdr, getRqDgramInst(),
				 MCTP_VENDOR_CMD_SELFTEST);

	return true;
}

bool mctp_encode_vendor_cmd_downloadlog(struct mctp_vendor_cmd_downloadlog *cmd,
					uint8_t session)
{
	MCTP_ASSERT_RET(cmd != NULL, false, "cmd is NULL\n");

	encode_vendor_cmd_header(&cmd->vdr_msg_hdr, getRqDgramInst(),
				 MCTP_VENDOR_CMD_DOWNLOAD_LOG);
	cmd->session_id = session;
	return true;
}

bool mctp_encode_vendor_cmd_bootcmplt(struct mctp_vendor_cmd_bootcmplt *cmd)
{
	ENCODE_VMD_CMD_FUNC(BOOTCOMPLETE);
}

bool mctp_encode_vendor_cmd_bootcmplt_v2(
	struct mctp_vendor_cmd_bootcomplete_v2 *cmd)
{
	MCTP_ASSERT_RET(cmd != NULL, false, "cmd is NULL\n");

	encode_vendor_cmd_header(&cmd->vdr_msg_hdr, getRqDgramInst(),
				 MCTP_VENDOR_CMD_BOOTCOMPLETE);
	cmd->vdr_msg_hdr.msg_version = MCTP_VDM_HDR_MSG_VER_2;

	return true;
}

bool mctp_encode_vendor_cmd_hbenable(struct mctp_vendor_cmd_hbenable *cmd)
{
	ENCODE_VMD_CMD_FUNC(ENABLE_HEARTBEAT);
}

bool mctp_encode_vendor_cmd_background_copy(
	struct mctp_vendor_cmd_background_copy *cmd)
{
	ENCODE_VMD_CMD_FUNC(BG_COPY);
}

bool mctp_encode_vendor_cmd_hbenvent(struct mctp_vendor_cmd_hbenvent *cmd)
{
	ENCODE_VMD_CMD_FUNC(HEARTBEAT);
}

bool mctp_encode_vendor_cmd_restartnoti(struct mctp_vendor_cmd_restartnoti *cmd)
{
	ENCODE_VMD_CMD_FUNC(RESTART);
}

bool mctp_encode_vendor_cmd_bootstatus(struct mctp_vendor_cmd_bootstatus *cmd)
{
	ENCODE_VMD_CMD_FUNC(QUERYBOOTSTATUS);
}

bool mctp_encode_vendor_cmd_certificate_install(
	struct mctp_vendor_cmd_certificate_install *cmd)
{
	ENCODE_VMD_CMD_FUNC(CERTIFICATE_INSTALL);
}

bool mctp_encode_vendor_cmd_in_band(struct mctp_vendor_cmd_in_band *cmd)
{
	if (!cmd) {
		return false;
	}

	encode_vendor_cmd_header(&cmd->vdr_msg_hdr, getRqDgramInst(),
				 MCTP_VENDOR_CMD_IN_BAND);

	return true;
}

bool mctp_encode_vendor_cmd_boot_ap(struct mctp_vendor_cmd_boot_ap *cmd)
{
	ENCODE_VMD_CMD_FUNC(BOOT_AP);
}

bool mctp_encode_vendor_cmd_set_query_boot_mode(
	struct mctp_vendor_cmd_set_query_boot_mode *cmd)
{
	ENCODE_VMD_CMD_FUNC(SET_QUERY_BOOT_MODE);
}
