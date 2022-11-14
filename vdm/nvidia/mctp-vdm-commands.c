/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "mctp-vdm-nvda.h"
#include "mctp-vdm-commands.h"

#include "ctrld/mctp-ctrl.h"

#include "mctp-socket.h"

/* MCTP-VDM response binary file */
#define MCTP_VDM_RESP_OUTPUT_FILE "/var/mctp-vdm-output.bin"

/* MCTP-VDM IANA size */
#define MCTP_VDM_IANA_SIZE 4
/* MCTP-VDM Instance ID size */
#define MCTP_VDM_INST_ID_SIZE 1
/*
 * MCTP-VDM Nvidia message type offset
 * NOTE: The msg buffer contains data as below format
 * [IANA]-[Inst ID]-[Nvidia Msg Type]-[Nvidia Msg Command code]-[Nvidia Msg version]-[Nvidia Msg Payload]
 * So adding (IANA + InstID) to get NVDA message type offset.
*/
#define MCTP_VDM_NVDA_MSG_TYPE_OFFSET                                          \
	(MCTP_VDM_IANA_SIZE + MCTP_VDM_INST_ID_SIZE)

/* MCTP-VDM response output in byte format */
#define MCTP_VDM_RESP_OP_BYTE_FORMAT 1

/* MCTP-VDM Download log max size 365KB */
#define MCTP_VDM_DOWNLOAD_LOG_MAX_SIZE (365 * 1024)

/* MCTP-VDM Response output macros */
const uint8_t mctp_vdm_op_success = MCTP_VDM_CMD_OP_SUCCESS;

/*
 * Print the output to console and also redirect the output
 * to log file
 */
static void print_hex(char *msg, uint8_t *data, int len, uint8_t output)
{
	if (output == VERBOSE_DISABLE) {
		return;
	}

	printf("%s: ", msg);

	if (data) {
		for (int i = 0; i < len; ++i) {
			printf("%02X ", data[i]);
		}
	}

	printf("\n");
}

/*
 * Move the MCTP-VDM response to a binary file in below format:
 * The first parameter is the response byte:
 *   0x01 means no response/unsuccessful
 *   0xff is successful response
 * The remaining data can be extracted based on the vdm command.
 */
static int vdm_resp_output(char *msg, int len, uint8_t result, uint8_t enable)
{
	FILE *fptr = NULL;
	size_t wlen = 0;

	/* Return if the enable option is false */
	if (enable == VERBOSE_DISABLE)
		return -1;

	/* Open the Output file */
	fptr = fopen(MCTP_VDM_RESP_OUTPUT_FILE, "w+");

	MCTP_ASSERT_RET(fptr != NULL, errno, "[err: %d] Unable to open %s\n",
			errno, MCTP_VDM_RESP_OUTPUT_FILE);

	/* Update the results */
	if (result != 0) {
		wlen = fwrite(&result, MCTP_VDM_RESP_OP_BYTE_FORMAT,
			      sizeof(uint8_t), fptr);

		/* Close the Output fptr */
		fclose(fptr);
		MCTP_ASSERT_RET(wlen == 1, errno,
				"[err: %d] Unable to write %s\n", errno,
				MCTP_VDM_RESP_OUTPUT_FILE);

		return 0;
	}
	wlen = fwrite(&mctp_vdm_op_success, MCTP_VDM_RESP_OP_BYTE_FORMAT,
		      sizeof(uint8_t), fptr);

	if (wlen != 1) {
		/* Close the Output fptr */
		fclose(fptr);
		MCTP_ERR("[err: %d] Unable to write %s\n",
				 errno, MCTP_VDM_RESP_OUTPUT_FILE);
		return (errno);
	}

	/* Update the Message */
	if ((msg) && (len > MCTP_VDM_NVDA_MSG_TYPE_OFFSET)) {
		wlen = fwrite(&msg[MCTP_VDM_NVDA_MSG_TYPE_OFFSET],
			      MCTP_VDM_RESP_OP_BYTE_FORMAT,
			      (len - MCTP_VDM_NVDA_MSG_TYPE_OFFSET), fptr);
		if (wlen != (len - MCTP_VDM_NVDA_MSG_TYPE_OFFSET)) {
			/* Close the Output fptr */
			fclose(fptr);
			MCTP_ERR("[err: %d] Unable to write %s\n",
					 errno, MCTP_VDM_RESP_OUTPUT_FILE);
			return (errno);
		}
	}

	/* Close the Output fptr */
	fclose(fptr);

	return 0;
}

/* MCTP-VDM Client send and receive function */
static mctp_requester_rc_t
mctp_vdm_client_send_recv(mctp_eid_t eid, int fd, const uint8_t *req_msg,
			  size_t req_len, uint8_t **resp_msg, size_t *resp_len,
			  uint8_t verbose)
{
	mctp_requester_rc_t rc;
	uint8_t *resp;

	print_hex("TX", req_msg, req_len, verbose);

	rc = mctp_client_send_recv(eid, fd, MCTP_VENDOR_MSG_TYPE, req_msg,
				   req_len, resp_msg, resp_len);

	if (rc == MCTP_REQUESTER_SUCCESS) {
		/* Print out the data to the console */
		print_hex("RX", *resp_msg + 1, *resp_len - 1, verbose);

		/* Report the result in output file */
		vdm_resp_output(*resp_msg + 1, *resp_len - 1, 0, verbose);

		MCTP_ASSERT_RET(*resp_msg[0] == MCTP_VENDOR_MSG_TYPE,
				MCTP_REQUESTER_NOT_RESP_MSG,
				"VMD message type is not correct - %x\n",
				*resp_msg[0]);
	} else {
		vdm_resp_output(NULL, 0, errno, verbose);
	}

	return rc;
}

/*
 * Self test command:
 * To run a health check inside Glacier
 */
int selftest(int fd, uint8_t tid, uint8_t *payload, int length, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_selftest cmd;

	MCTP_ASSERT_RET(length <= 4, -1, "the length is out of the spec.\n");
	memset(&cmd, 0, sizeof(cmd));

	/* Encode the VDM headers for selftest */
	mctp_encode_vendor_cmd_selftest(&cmd);
	memcpy(&cmd.payload, payload, length);

	length += sizeof(struct mctp_vendor_msg_hdr);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, length,
				       (uint8_t **)&resp, &resp_len, verbose);
	free(resp);
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Boot Complete v1:
 * The Boot Complete command shall be sent by AP after boot to some stable state.
 */
int boot_complete_v1(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_bootcmplt cmd = { 0 };

	/* Encode the VDM headers for Boot complete v1 */
	mctp_encode_vendor_cmd_bootcmplt(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Boot Complete v2:
 * The v2 command of Boot Complete is used the same way
 * as Boot Complete v1. The main difference is that byte 9 of the MCTP
 * message (NVIDIA message version) shall be set to 0x2 and the Request
 * data has additional bytes
 */
int boot_complete_v2(int fd, uint8_t tid, uint8_t valid, uint8_t slot,
		     uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_bootcomplete_v2 cmd = { 0 };

	/* Encode the VDM headers for Boot complete v2 */
	mctp_encode_vendor_cmd_bootcmplt_v2(&cmd);

	/* Update valid ID and the slot number fields */
	cmd.valid = valid;
	cmd.slot = slot;

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Set Heartbeat Enable/Disable:
 * Sometimes AP firmware might not be able to do heartbeat reporting,
 * and in this case, AP firmware can send this message to disable
 * heartbeat reporting, and enable it later.
 */
int set_heartbeat_enable(int fd, uint8_t tid, int enable, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_hbenable cmd = { 0 };

	/* Encode the VDM headers for Heartbeat enable/disable */
	mctp_encode_vendor_cmd_hbenable(&cmd);

	/* Update enable field */
	cmd.enable = enable;

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

/*
 * Heartbeat event:
 * If an AP supports heartbeat reporting, the AP firmware should send this
 * command to Glacier EC_FW every 1 min, and if Glacier cannot receive this
 * heartbeat message, it considers the AP firmware is not working fine,
 * and it switches to the other firmware slot to boot.
 * If the other firmware still has a heartbeat timeout for 3 times,
 * it keeps the AP firmware booting in that slot, records the information,
 * and disables the heartbeat watchdog.
 * NOTE: Heartbeat notification is valid only after boot complete is received
 */
int heartbeat(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_hbenvent cmd = { 0 };

	/* Encode the VDM headers for Heartbeat event */
	mctp_encode_vendor_cmd_hbenvent(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Query boot status:
 * Query Boot Status command can be called by AP firmware to know Glacier
 * and AP status. The returned boot status code is a 64-bit data.
 */
int query_boot_status(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_bootstatus cmd = { 0 };

	/* Encode the VDM headers for Query boot status */
	mctp_encode_vendor_cmd_bootstatus(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Background Copy v1:
 * The command is mainly used to manage interaction between Global #WP
 * and background copy.
 * This command should only be supported on the OOB path and not on
 * the In Band path.
 */
int background_copy(int fd, uint8_t tid, uint8_t code, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_background_copy cmd = { 0 };

	/* Encode the VDM headers for Background copy */
	mctp_encode_vendor_cmd_background_copy(&cmd);

	/* Update the code field */
	cmd.code = code;

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

/*
 * Download log:
 * The log data is saved into the internal SPI with fixed size.
 * This command is used to download the whole log data by pages.
 * NV can use the offline tool to parse the log data.
 */
int download_log(int fd, uint8_t eid, char *dl_path, uint8_t verbose)
{
	uint8_t session = MCTP_VDM_DOWNLOAD_LOG_SESSION_ID_START;
	int length = 0xFF;
	mctp_requester_rc_t rc = 0;
	int bytes_count = 0;
	size_t resp_len = 0;
	FILE *fptr = fopen(dl_path, "w+");
	struct mctp_vendor_cmd_downloadlog req = { 0 };
	struct mctp_vendor_cmd_downloadlog_resp *resp = NULL;

	MCTP_ASSERT_RET(fptr != NULL, -1, "failed to open file- %s -%d\n",
			dl_path, rc);

	while (length != 0) {
		/* Encode the VDM headers for Download log */
		mctp_encode_vendor_cmd_downloadlog(&req, session);
		print_hex("Request for DownloadLog", (uint8_t *)&req,
			  sizeof(req), verbose);

		/* Send and Receive the MCTP-VDM command */
		rc = mctp_client_send_recv(eid, fd, MCTP_VENDOR_MSG_TYPE,
					   (uint8_t *)&req, sizeof(req),
					   (uint8_t **)&resp, &resp_len);

		if (rc != MCTP_REQUESTER_SUCCESS) {
			fprintf(stderr, "%s: fail to recv [rc: %d] response\n",
				__func__, rc);
			free(resp);
			fclose(fptr);
			return -1;
		}

		/* The verbose option can be enabled if user want to see each packet transfers */
		if (verbose) {
			printf("resp_len: %zu\n", resp_len);
			print_hex("Response for DownloadLog", (uint8_t *)resp,
				  resp_len, verbose);
			printf("DL: cc is %d, session is %d, length is %d\n",
			       resp->cc, resp->session, resp->length);
		}

		/* Return failure if the response cc is zero */
		if (resp->cc != 0) {
			fprintf(stderr, "%s: Invalid cc[%d] DownloadLog fail\n",
				__func__, resp->cc);
			free(resp);
			fclose(fptr);
			return -1;
		}

		/* Increment bytes count */
		bytes_count += resp->length;
		if (bytes_count > MCTP_VDM_DOWNLOAD_LOG_MAX_SIZE) {
			fprintf(stderr,
				"%s: Bytes received [%d] is more than expected log size\n",
				__func__, bytes_count);
			free(resp);
			fclose(fptr);
			return -1;
		}

		/* Update the session Id and the length */
		session = resp->session;
		length = resp->length;

		/* Write the response data to the file */
		fwrite(resp->data, 1, length, fptr);

		/* Free the response data */
		free(resp);

		/* Set the resp pointer to NULL */
		resp = NULL;
	}

	/* Close the download log file */
	fclose(fptr);

	return 0;
}

/*
 * Restart Notification:
 * Restart notification shall be delivered to Glacier when an AP is about
 * to go through a restart that is not indicated via any physical
 * pins(such as software restart).
 */
int restart_notification(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_restartnoti cmd = { 0 };

	/* Encode the VDM headers for Restart notification */
	mctp_encode_vendor_cmd_restartnoti(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}
/*
 * */
int debug_token_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_dbg_token_inst cmd = { 0 };

	MCTP_ASSERT_RET(length == 256, -1, "the length is out of the spec.\n");

	/* Encode the VDM headers for debug token install */
	mctp_encode_vendor_cmd_dbg_token_inst(&cmd);

	memcpy(&cmd.payload, payload, length);
	length += sizeof(struct mctp_vendor_msg_hdr);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, length,
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

/*
 * */
int debug_token_erase(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_dbg_token_erase cmd = { 0 };

	/* Encode the VDM headers for debug token erase */
	mctp_encode_vendor_cmd_dbg_token_erase(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

/*
 * */
int debug_token_query(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_dbg_token_query cmd = { 0 };

	/* Encode the VDM headers for debug token query*/
	mctp_encode_vendor_cmd_dbg_token_query(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

int certificate_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
			uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_certificate_install cmd = { 0 };

	MCTP_ASSERT_RET(length <= MCTP_CERTIFICATE_CHAIN_SIZE, -1,
			"the length is out of the spec.\n");

	/* Encode the VDM headers for debug token query*/
	mctp_encode_vendor_cmd_certificate_install(&cmd);

	memcpy(&cmd.payload, payload, length);
	length += sizeof(struct mctp_vendor_msg_hdr);
	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, length,
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Enable IB Update v1:
 * By default firmware update is supported through both In-band and OOB paths, 
 * but for some CSP, they do not want to allow IB update for security reasons.
 * For parameter "code" equals 0, the command disables "in-band".
 * For parameter "code" equals 1, the command enables "in-band".
 * For parameter "code" equals 2, the command returns status of "in-band"
 *  returns 0, for disabled "in-band"
 *  returns 1, for enabled "in-band" 
 */
int in_band(int fd, uint8_t tid, uint8_t code, uint8_t verbose)
{
    uint8_t                                 *resp = NULL;
    size_t                                  resp_len = 0;
    mctp_requester_rc_t                     rc = -1;
    struct mctp_vendor_cmd_in_band cmd = {0};

    /* Encode the VDM headers for Enable IB Update */
    mctp_encode_vendor_cmd_in_band(&cmd);

    /* Update the code field */
    cmd.code = code;

    /* Send and Receive the MCTP-VDM command */
    rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

    /* free memory */
    free(resp);
	
	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	
    return 0;
}
