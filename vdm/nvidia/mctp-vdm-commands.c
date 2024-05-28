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
#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "libmctp-vdm-cmds.h"
#include "libmctp.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include "mctp-vdm-nvda.h"
#include "mctp-vdm-commands.h"

#include "ctrld/mctp-ctrl.h"

#include "mctp-socket.h"

#define MCTP_CTRL_CC_UNKNOWN 0xFF
#define MCTP_CC_POSITION     9

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

/* Boot Status Code Bits */
#define EC_TAG0_AUTH_ERROR	     0
#define EC_TAG1_COPY_ERROR	     1
#define EC_OTP_MISMATCH_ERROR	     2
#define EC_SET_KEY_REVOKE	     3
#define EC_SET_ROLLBACK_PROTECTION   4
#define EC_RECEIVE_AP0_BOOT_COMPLETE 5
#define EC_STRAP_MISMATCH	     6

#define AP0_PRIMARY_FW_AUTHENTICATION_STATUS   8
#define AP0_SECONDARY_FW_AUTHENTICATION_STATUS 12
#define AP0_RECOVERY_FW_AUTHENTICATION_STATUS  16

#define AP0_ACTIVE_SLOT			20
#define AP0_SPI_READ_FAILURE		21
#define AP0_POWER_GOOD			22
#define AP0_RESET_ON_HOLD		23
#define AP0_SPI_ACCESS_VIOLATION_OPCODE 24
#define AP0_SPI_ACCESS_VIOLATION_RANGE	25
#define AP0_HEARTBEAT_TIMEOUT		26
#define AP0_BOOTCOMPLETE_TIMEOUT	27

#define FATAL_ERROR_CODE 28

#define PRIMARY_PUF_AC_VALID  32
#define FALLBACK_PUF_AC_VALID 33
#define PUF0_ENGINE_STARTED   34
#define PUF0_AK_GEN	      35
#define AK_SRC_IS_PUF	      36
#define PUF1_ENGINE_STARTED   37
#define PUF1_UDS_GEN	      38
#define PUF1_IK_GEN	      39
#define IK_SRC_IS_PUF	      40
#define AP0_RELEASE_SLOT      48
#define REGION_COPY_FAILED    50
#define STAGE_DL_FAILED	      54

#define NO_FATAL_ERROR			      0 /* SUCCESS */
#define FATAL_ERR_AUTH_AP_FW		      1
#define FATAL_ERR_INIT_RESET_EVENT_FAIL	      2
#define FATAL_ERR_SETUP_SPIMON_FAIL	      3
#define FATAL_ERR_GRANT_AP_SPI_ACCESS_FAIL    4
#define FATAL_ERR_TIMEOUT_WAIT_AP_PGOOD	      5
#define FATAL_ERR_TRY_RELEASE_ON_INVALID_SLOT 6
#define FATAL_ERR_BC_ON_INVALID_SLOT	      7
#define FATAL_ERR_BC_TIMEOUT_MAX_ATTEMPT      8
#define FATAL_ERR_SET_TIMER		      9

#define AUTHENTICATE_SUCCESS		1
#define VALIDATE_PUBLIC_KEY_ERROR	2
#define KEY_REVOKE_CHECK_ERROR		3
#define ROLLBACK_PROTECTION_CHECK_ERROR 4
#define AUTHENTICATE_ERROR		6
#define SPI_READ_ERROR			7
#define AUTHENTICATE_IN_PROGRESS	15

/* Background Copy */
#define MCTP_VDM_BACKGROUND_COPY_BYTE_1_POSITION 10
#define MCTP_VDM_BACKGROUND_COPY_BYTE_2_POSITION 11

enum MCTP_VDM_COMPLETION_CODE {
	SUCCESS = MCTP_CTRL_CC_SUCCESS,
	ERROR = MCTP_CTRL_CC_ERROR,
	ERROR_INVALID_DATA = MCTP_CTRL_CC_ERROR_INVALID_DATA,
	ERROR_INVALID_LENGTH = MCTP_CTRL_CC_ERROR_INVALID_LENGTH,
	ERROR_NOT_READY = MCTP_CTRL_CC_ERROR_NOT_READY,
	ERROR_UNSUPPORTED_CMD = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD,
	UNKNOWN = MCTP_CTRL_CC_UNKNOWN
};

#define print_boot_flag(flag, val, offset)                                     \
	do {                                                                   \
		printf("%-40s:\t %s \n", #flag,                                \
		       (val) & (uint8_t)(0x01) << ((flag) - (offset)) ?        \
			       "true" :                                        \
			       "false");                                       \
	} while (0)

#define print_boot_flag_rep_name(flag_name, flag_val, val, offset)             \
	do {                                                                   \
		printf("%-40s:\t %s \n", (flag_name),                          \
		       (val) & (uint8_t)(0x01) << ((flag) - (offset)) ?        \
			       "true" :                                        \
			       "false");                                       \
	} while (0)

#define print_boot_value(flag, val)                                            \
	do {                                                                   \
		printf("%-40s:\t %s \n", #flag,                                \
		       ((val) == (flag)) ? "true" : "false");                  \
	} while (0)

#define print_boot_num_value(flag, val)                                        \
	do {                                                                   \
		printf("%-40s:\t %u \n", #flag, (val));                        \
	} while (0)

#define create_json_element_flag(json_obj, flag, val, offset)                  \
	do {                                                                   \
		json_object_object_add(                                        \
			(json_obj), #flag,                                     \
			json_object_new_boolean(                               \
				(val) & (uint8_t)(0x01)                        \
						<< ((flag) - (offset))));      \
	} while (0)

#define create_json_element_boolean_value(json_obj, flag, val)                 \
	do {                                                                   \
		json_object_object_add((json_obj), #flag,                      \
				       json_object_new_boolean((val) ==        \
							       (flag)));       \
	} while (0)

#define create_json_element_number_value(json_obj, flag, val)                  \
	do {                                                                   \
		json_object_object_add((json_obj), #flag,                      \
				       json_object_new_int(val));              \
	} while (0)

#define create_json_element_equals_flag_name(json_obj, element_name, flag)     \
	do {                                                                   \
		json_object_object_add((json_obj), (element_name),             \
				       json_object_new_string(#flag));         \
	} while (0)

/* short messages for command 'query_boot_status' whether boot succeeded or failed */
#define MSG_BOOT_OK	"AP boot success"
#define MSG_BOOT_FAILED "AP boot failed"

/*
 * This function extracts the completion code from the response of an MCTP command
 * and generates corresponding JSON data to represent it.
 */
void create_json_with_completion_code(const uint8_t *resp_msg,
				      struct json_object *json_obj)
{
	uint8_t resp_byte_completion_code = resp_msg[MCTP_CC_POSITION];

	switch (resp_byte_completion_code) {
	case SUCCESS:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", SUCCESS);
		break;
	case ERROR:
		create_json_element_equals_flag_name(json_obj,
						     "COMPLETION_CODE", ERROR);
		break;
	case ERROR_INVALID_DATA:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", ERROR_INVALID_DATA);
		break;
	case ERROR_INVALID_LENGTH:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", ERROR_INVALID_LENGTH);
		break;
	case ERROR_NOT_READY:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", ERROR_NOT_READY);
		break;
	case ERROR_UNSUPPORTED_CMD:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", ERROR_UNSUPPORTED_CMD);
		break;
	default:
		create_json_element_equals_flag_name(
			json_obj, "COMPLETION_CODE", UNKNOWN);
		break;
	}
}

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
		MCTP_ERR("[err: %d] Unable to write %s\n", errno,
			 MCTP_VDM_RESP_OUTPUT_FILE);
		return (errno);
	}

	/* Update the Message */
	if ((msg) && (len > MCTP_VDM_NVDA_MSG_TYPE_OFFSET)) {
		wlen = fwrite(&msg[MCTP_VDM_NVDA_MSG_TYPE_OFFSET],
			      MCTP_VDM_RESP_OP_BYTE_FORMAT,
			      (len - MCTP_VDM_NVDA_MSG_TYPE_OFFSET), fptr);
		if (wlen != (size_t)(len - MCTP_VDM_NVDA_MSG_TYPE_OFFSET)) {
			/* Close the Output fptr */
			fclose(fptr);
			MCTP_ERR("[err: %d] Unable to write %s\n", errno,
				 MCTP_VDM_RESP_OUTPUT_FILE);
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

	print_hex("TX", (uint8_t *)req_msg, req_len, verbose);

	rc = mctp_client_send_recv(eid, fd, MCTP_VENDOR_MSG_TYPE, req_msg,
				   req_len, resp_msg, resp_len);

	if (rc == MCTP_REQUESTER_SUCCESS) {
		/* Print out the data to the console */
		print_hex("RX", *resp_msg + 1, *resp_len - 1, verbose);

		/* Report the result in output file */
		vdm_resp_output(*(char **)resp_msg + 1, *resp_len - 1, 0,
				verbose);

		MCTP_ASSERT_RET(*resp_msg[0] == MCTP_VENDOR_MSG_TYPE,
				MCTP_REQUESTER_NOT_RESP_MSG,
				"VMD message type is not correct - %x\n",
				*resp_msg[0]);
	} else {
		vdm_resp_output(NULL, 1, errno, verbose);
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
 * The function reads bits from 0 to 7 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits0_to_bit7(const uint8_t *resp_msg,
						  const int resp_len)
{
	uint8_t resp_byte_8 = resp_msg[resp_len - 1];
	int offset = 0;

	print_boot_flag(EC_TAG0_AUTH_ERROR, resp_byte_8, offset);
	print_boot_flag(EC_TAG1_COPY_ERROR, resp_byte_8, offset);
	print_boot_flag(EC_OTP_MISMATCH_ERROR, resp_byte_8, offset);
	print_boot_flag(EC_SET_KEY_REVOKE, resp_byte_8, offset);
	print_boot_flag(EC_SET_ROLLBACK_PROTECTION, resp_byte_8, offset);
	print_boot_flag(EC_RECEIVE_AP0_BOOT_COMPLETE, resp_byte_8, offset);
	print_boot_flag(EC_STRAP_MISMATCH, resp_byte_8, offset);
	printf("\n");
}

/*
 * The function reads byte storing Authentication status code and
 * displays it in readable form 
 */
static void
query_boot_status_print_authentication_status(const uint8_t resp_byte)
{
	print_boot_value(AUTHENTICATE_SUCCESS, (resp_byte & 0xF));
	print_boot_value(VALIDATE_PUBLIC_KEY_ERROR, (resp_byte & 0xF));
	print_boot_value(KEY_REVOKE_CHECK_ERROR, (resp_byte & 0xF));
	print_boot_value(ROLLBACK_PROTECTION_CHECK_ERROR, (resp_byte & 0xF));
	print_boot_value(AUTHENTICATE_ERROR, (resp_byte & 0xF));
	print_boot_value(SPI_READ_ERROR, (resp_byte & 0xF));
	print_boot_value(AUTHENTICATE_IN_PROGRESS, (resp_byte & 0xF));
}

/*
 * The function reads bits from 8 to 15 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits8_to_bit15(const uint8_t *resp_msg,
						   const int resp_len)
{
	uint8_t resp_byte_7 = resp_msg[resp_len - 2];

	printf("AP0_PRIMARY_FW_AUTHENTICATION_STATUS\n");
	query_boot_status_print_authentication_status(resp_byte_7);

	printf("\n");

	printf("AP0_SECONDARY_FW_AUTHENTICATION_STATUS\n");
	query_boot_status_print_authentication_status(resp_byte_7 >> 4);

	printf("\n");
}

/*
 * The function reads bits from 16 to 23 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits16_to_bit23(const uint8_t *resp_msg,
						    const int resp_len)
{
	uint8_t resp_byte_6 = resp_msg[resp_len - 3];
	int offset = AP0_ACTIVE_SLOT;

	printf("AP0_RECOVERY_FW_AUTHENTICATION_STATUS\n");
	query_boot_status_print_authentication_status(resp_byte_6);
	printf("\n");
	print_boot_num_value(AP0_ACTIVE_SLOT, (resp_byte_6 >> 4) & 0x01);
	print_boot_flag(AP0_SPI_READ_FAILURE, (resp_byte_6 >> 4), offset);
	print_boot_flag(AP0_POWER_GOOD, (resp_byte_6 >> 4), offset);
	print_boot_flag(AP0_RESET_ON_HOLD, (resp_byte_6 >> 4), offset);
	printf("\n");
}

/*
 * The function reads bits from 24 to 31 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits24_to_bit31(const uint8_t *resp_msg,
						    const int resp_len)
{
	uint8_t resp_byte_5 = resp_msg[resp_len - 4];
	int offset = AP0_SPI_ACCESS_VIOLATION_OPCODE;

	print_boot_flag(AP0_SPI_ACCESS_VIOLATION_OPCODE, resp_byte_5, offset);
	print_boot_flag(AP0_SPI_ACCESS_VIOLATION_RANGE, resp_byte_5, offset);
	print_boot_flag(AP0_HEARTBEAT_TIMEOUT, resp_byte_5, offset);
	print_boot_flag(AP0_BOOTCOMPLETE_TIMEOUT, resp_byte_5, offset);

	if (NO_FATAL_ERROR != (resp_byte_5 >> 4)) {
		printf("\n");
		printf("FATAL_ERROR_CODE\n");
		print_boot_value(FATAL_ERR_AUTH_AP_FW, (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_INIT_RESET_EVENT_FAIL,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_SETUP_SPIMON_FAIL,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_GRANT_AP_SPI_ACCESS_FAIL,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_TIMEOUT_WAIT_AP_PGOOD,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_TRY_RELEASE_ON_INVALID_SLOT,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_BC_ON_INVALID_SLOT,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_BC_TIMEOUT_MAX_ATTEMPT,
				 (resp_byte_5 >> 4));
		print_boot_value(FATAL_ERR_SET_TIMER, (resp_byte_5 >> 4));
	}
	printf("\n");
}

/*
 * The function reads bits from 32 to 39 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits32_to_bit39(const uint8_t *resp_msg,
						    const int resp_len)
{
	uint8_t resp_byte_4 = resp_msg[resp_len - 5];
	int offset = PRIMARY_PUF_AC_VALID;

	print_boot_flag(PRIMARY_PUF_AC_VALID, resp_byte_4, offset);
	print_boot_flag(FALLBACK_PUF_AC_VALID, resp_byte_4, offset);
	print_boot_flag(PUF0_ENGINE_STARTED, resp_byte_4, offset);
	print_boot_flag(PUF0_AK_GEN, resp_byte_4, offset);
	print_boot_flag(AK_SRC_IS_PUF, resp_byte_4, offset);
	print_boot_flag(PUF1_ENGINE_STARTED, resp_byte_4, offset);
	print_boot_flag(PUF1_UDS_GEN, resp_byte_4, offset);
	print_boot_flag(PUF1_IK_GEN, resp_byte_4, offset);
	printf("\n");
}

/*
 * The function reads bits from 40 to 47 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits40_to_bit47(const uint8_t *resp_msg,
						    const int resp_len)
{
	uint8_t resp_byte_3 = resp_msg[resp_len - 6];
	int offset = IK_SRC_IS_PUF;

	print_boot_flag(IK_SRC_IS_PUF, resp_byte_3, offset);
	printf("\n");
}

/*
 * The function reads bits from 48 to 57 from response from command 'query_boot_status' and 
 * displays it in readable form  
 */
static void query_boot_status_print_bits48_to_bit57(const uint8_t *resp_msg,
						    const int resp_len)
{
	uint8_t resp_byte_2 = resp_msg[resp_len - 7];
	uint8_t resp_byte_1 = resp_msg[resp_len - 8];
	int offset = AP0_RELEASE_SLOT;
	uint16_t resp_byte_2_and_1 = resp_byte_2 | (resp_byte_1 << 8);

	uint8_t ap0_release_slot_value =
		(resp_byte_2_and_1 >> (AP0_RELEASE_SLOT - offset)) & 0x03;

	printf("%-40s:\t ", "AP0_RELEASE_SLOT");
	switch (ap0_release_slot_value) {
	case 0:
		printf("0 (fatal error happened)");
		break;
	case 1:
		printf("1 (slot0)");
		break;
	case 2:
		printf("2 (slot1)");
		break;
	default:
		printf("Undefined value");
		break;
	}
	printf("\n");

	printf("%-40s:\t ", "REGION_COPY_FAILED");
	uint8_t region_copy_failed_value =
		(resp_byte_2_and_1 >> (REGION_COPY_FAILED - offset)) & 0x0F;

	switch (region_copy_failed_value) {
	case 0:
		printf("REGION_CP_SUCCESS");
		break;
	case 1:
		printf("REGION_CP_FAIL_STRAP_SETTING");
		break;
	case 2:
		printf("REGION_CP_FAIL_NO_BOOT_COMPLETE_SLOT");
		break;
	case 3:
		printf("REGION_CP_FAIL_TIMEOUT");
		break;
	case 4:
		printf("REGION_CP_FAIL");
		break;
	default:
		printf("Undefined value");
		break;
	}
	printf("\n");

	printf("%-40s:\t ", "STAGE_DL_FAILED");
	uint8_t stage_dl_failed_value =
		(resp_byte_2_and_1 >> (STAGE_DL_FAILED - offset)) & 0x0F;

	switch (stage_dl_failed_value) {
	case 0:
		printf("Not started");
		break;
	case 1:
		printf("BG copy in progress");
		break;
	case 2:
		printf("Background copy to gold failed");
		break;
	case 3:
		printf("Background copy to inactive failed");
		break;
	case 4:
		printf("Success");
		break;
	default:
		printf("Undefined value");
		break;
	}
	printf("\n");
}

/*
 * This function parses bits from 0 to 7 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits0_to_bit7(const uint8_t *resp_msg,
					    const int resp_len,
					    struct json_object *json_obj)
{
	uint8_t resp_byte_8 = resp_msg[resp_len - 1];
	int offset = 0;

	create_json_element_flag(json_obj, EC_TAG0_AUTH_ERROR, resp_byte_8,
				 offset);
	create_json_element_flag(json_obj, EC_TAG1_COPY_ERROR, resp_byte_8,
				 offset);
	create_json_element_flag(json_obj, EC_OTP_MISMATCH_ERROR, resp_byte_8,
				 offset);
	create_json_element_flag(json_obj, EC_SET_KEY_REVOKE, resp_byte_8,
				 offset);
	create_json_element_flag(json_obj, EC_SET_ROLLBACK_PROTECTION,
				 resp_byte_8, offset);
	create_json_element_flag(json_obj, EC_RECEIVE_AP0_BOOT_COMPLETE,
				 resp_byte_8, offset);
	create_json_element_flag(json_obj, EC_STRAP_MISMATCH, resp_byte_8,
				 offset);
}

/*
 * This function reads a byte storing the Authentication status code
 * and creates corresponding JSON boolean values for each status.
 * These values are then added to the provided JSON object.
 */
static void create_json_query_boot_status_authentication_status(
	const uint8_t resp_byte, struct json_object *fw_auth_status)
{
	create_json_element_boolean_value(fw_auth_status, AUTHENTICATE_SUCCESS,
					  (resp_byte & 0xF));
	create_json_element_boolean_value(
		fw_auth_status, VALIDATE_PUBLIC_KEY_ERROR, (resp_byte & 0xF));
	create_json_element_boolean_value(
		fw_auth_status, KEY_REVOKE_CHECK_ERROR, (resp_byte & 0xF));
	create_json_element_boolean_value(fw_auth_status,
					  ROLLBACK_PROTECTION_CHECK_ERROR,
					  (resp_byte & 0xF));
	create_json_element_boolean_value(fw_auth_status, AUTHENTICATE_ERROR,
					  (resp_byte & 0xF));
	create_json_element_boolean_value(fw_auth_status, SPI_READ_ERROR,
					  (resp_byte & 0xF));
	create_json_element_boolean_value(
		fw_auth_status, AUTHENTICATE_IN_PROGRESS, (resp_byte & 0xF));
}

/*
 * This function parses bits from 8 to 15 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits8_to_bit15(const uint8_t *resp_msg,
					     const int resp_len,
					     struct json_object *json_obj)
{
	uint8_t resp_byte_7 = resp_msg[resp_len - 2];

	struct json_object *primary_fw_auth_status = json_object_new_object();
	create_json_query_boot_status_authentication_status(
		resp_byte_7, primary_fw_auth_status);
	json_object_object_add(json_obj, "AP0_PRIMARY_FW_AUTHENTICATION_STATUS",
			       primary_fw_auth_status);

	struct json_object *secondary_fw_auth_status = json_object_new_object();
	create_json_query_boot_status_authentication_status(
		resp_byte_7 >> 4, secondary_fw_auth_status);
	json_object_object_add(json_obj,
			       "AP0_SECONDARY_FW_AUTHENTICATION_STATUS",
			       secondary_fw_auth_status);
}

/*
 * This function parses bits from 16 to 23 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits16_to_bit23(const uint8_t *resp_msg,
					      const int resp_len,
					      struct json_object *json_obj)
{
	uint8_t resp_byte_6 = resp_msg[resp_len - 3];
	int offset = AP0_ACTIVE_SLOT;

	struct json_object *recovery_fw_auth_status = json_object_new_object();
	create_json_query_boot_status_authentication_status(
		resp_byte_6, recovery_fw_auth_status);
	json_object_object_add(json_obj,
			       "AP0_RECOVERY_FW_AUTHENTICATION_STATUS",
			       recovery_fw_auth_status);

	create_json_element_number_value(json_obj, AP0_ACTIVE_SLOT,
					 (resp_byte_6 >> 4) & 0x01);
	create_json_element_flag(json_obj, AP0_SPI_READ_FAILURE,
				 (resp_byte_6 >> 4), offset);
	create_json_element_flag(json_obj, AP0_POWER_GOOD, (resp_byte_6 >> 4),
				 offset);
	create_json_element_flag(json_obj, AP0_RESET_ON_HOLD,
				 (resp_byte_6 >> 4), offset);
}

/*
 * This function parses bits from 24 to 31 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits24_to_bit31(const uint8_t *resp_msg,
					      const int resp_len,
					      struct json_object *json_obj)
{
	uint8_t resp_byte_5 = resp_msg[resp_len - 4];
	int offset = AP0_SPI_ACCESS_VIOLATION_OPCODE;

	create_json_element_flag(json_obj, AP0_SPI_ACCESS_VIOLATION_OPCODE,
				 resp_byte_5, offset);
	create_json_element_flag(json_obj, AP0_SPI_ACCESS_VIOLATION_RANGE,
				 resp_byte_5, offset);
	create_json_element_flag(json_obj, AP0_HEARTBEAT_TIMEOUT, resp_byte_5,
				 offset);
	create_json_element_flag(json_obj, AP0_BOOTCOMPLETE_TIMEOUT,
				 resp_byte_5, offset);

	if (NO_FATAL_ERROR != (resp_byte_5 >> 4)) {
		struct json_object *fatal_error_codes =
			json_object_new_object();

		create_json_element_boolean_value(fatal_error_codes,
						  FATAL_ERR_AUTH_AP_FW,
						  (resp_byte_5 >> 4));
		create_json_element_boolean_value(
			fatal_error_codes, FATAL_ERR_INIT_RESET_EVENT_FAIL,
			(resp_byte_5 >> 4));
		create_json_element_boolean_value(fatal_error_codes,
						  FATAL_ERR_SETUP_SPIMON_FAIL,
						  (resp_byte_5 >> 4));
		create_json_element_boolean_value(
			fatal_error_codes, FATAL_ERR_GRANT_AP_SPI_ACCESS_FAIL,
			(resp_byte_5 >> 4));
		create_json_element_boolean_value(
			fatal_error_codes, FATAL_ERR_TIMEOUT_WAIT_AP_PGOOD,
			(resp_byte_5 >> 4));
		create_json_element_boolean_value(
			fatal_error_codes,
			FATAL_ERR_TRY_RELEASE_ON_INVALID_SLOT,
			(resp_byte_5 >> 4));
		create_json_element_boolean_value(fatal_error_codes,
						  FATAL_ERR_BC_ON_INVALID_SLOT,
						  (resp_byte_5 >> 4));
		create_json_element_boolean_value(
			fatal_error_codes, FATAL_ERR_BC_TIMEOUT_MAX_ATTEMPT,
			(resp_byte_5 >> 4));
		create_json_element_boolean_value(fatal_error_codes,
						  FATAL_ERR_SET_TIMER,
						  (resp_byte_5 >> 4));

		json_object_object_add(json_obj, "FATAL_ERROR_CODE",
				       fatal_error_codes);
	}
}

/*
 * This function parses bits from 32 to 39 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits32_to_bit39(const uint8_t *resp_msg,
					      const int resp_len,
					      struct json_object *json_obj)
{
	uint8_t resp_byte_4 = resp_msg[resp_len - 5];
	int offset = PRIMARY_PUF_AC_VALID;

	create_json_element_flag(json_obj, PRIMARY_PUF_AC_VALID, resp_byte_4,
				 offset);
	create_json_element_flag(json_obj, FALLBACK_PUF_AC_VALID, resp_byte_4,
				 offset);
	create_json_element_flag(json_obj, PUF0_ENGINE_STARTED, resp_byte_4,
				 offset);
	create_json_element_flag(json_obj, PUF0_AK_GEN, resp_byte_4, offset);
	create_json_element_flag(json_obj, AK_SRC_IS_PUF, resp_byte_4, offset);
	create_json_element_flag(json_obj, PUF1_ENGINE_STARTED, resp_byte_4,
				 offset);
	create_json_element_flag(json_obj, PUF1_UDS_GEN, resp_byte_4, offset);
	create_json_element_flag(json_obj, PUF1_IK_GEN, resp_byte_4, offset);
}

/*
 * This function parses bits from 40 to 47 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits40_to_bit47(const uint8_t *resp_msg,
					      const int resp_len,
					      struct json_object *json_obj)
{
	uint8_t resp_byte_3 = resp_msg[resp_len - 6];
	int offset = IK_SRC_IS_PUF;

	create_json_element_flag(json_obj, IK_SRC_IS_PUF, resp_byte_3, offset);
}

/*
 * This function parses bits from 48 to 57 from the response of the 'query_boot_status' command
 * and creates corresponding JSON flags for each boot status.
 * The flags are then added to the provided JSON object.
 */
static void
create_json_query_boot_status_bits48_to_bit57(const uint8_t *resp_msg,
					      const int resp_len,
					      struct json_object *json_obj)
{
	uint8_t resp_byte_2 = resp_msg[resp_len - 7];
	uint8_t resp_byte_1 = resp_msg[resp_len - 8];
	int offset = AP0_RELEASE_SLOT;
	uint16_t resp_byte_2_and_1 = resp_byte_2 | (resp_byte_1 << 8);

	uint8_t ap0_release_slot_value =
		(resp_byte_2_and_1 >> (AP0_RELEASE_SLOT - offset)) & 0x03;

	char *ap0_release_slot_value_txt;
	switch (ap0_release_slot_value) {
	case 0:
		ap0_release_slot_value_txt = "0 (fatal error happened)";
		break;
	case 1:
		ap0_release_slot_value_txt = "1 (slot0)";
		break;
	case 2:
		ap0_release_slot_value_txt = "2 (slot1)";
		break;
	default:
		ap0_release_slot_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(
		json_obj, "AP0_RELEASE_SLOT",
		json_object_new_string(ap0_release_slot_value_txt));

	uint8_t region_copy_failed_value =
		(resp_byte_2_and_1 >> (REGION_COPY_FAILED - offset)) & 0x0F;

	char *region_copy_failed_value_txt;

	switch (region_copy_failed_value) {
	case 0:
		region_copy_failed_value_txt = "REGION_CP_SUCCESS";
		break;
	case 1:
		region_copy_failed_value_txt = "REGION_CP_FAIL_STRAP_SETTING";
		break;
	case 2:
		region_copy_failed_value_txt =
			"REGION_CP_FAIL_NO_BOOT_COMPLETE_SLOT";
		break;
	case 3:
		region_copy_failed_value_txt = "REGION_CP_FAIL_TIMEOUT";
		break;
	case 4:
		region_copy_failed_value_txt = "REGION_CP_FAIL";
		break;
	default:
		region_copy_failed_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(
		json_obj, "REGION_COPY_FAILED",
		json_object_new_string(region_copy_failed_value_txt));

	uint8_t stage_dl_failed_value =
		(resp_byte_2_and_1 >> (STAGE_DL_FAILED - offset)) & 0x0F;
	char *stage_dl_failed_value_txt;

	switch (stage_dl_failed_value) {
	case 0:
		stage_dl_failed_value_txt = "Not started";
		break;
	case 1:
		stage_dl_failed_value_txt = "BG copy in progress";
		break;
	case 2:
		stage_dl_failed_value_txt = "Background copy to gold failed";
		break;
	case 3:
		stage_dl_failed_value_txt =
			"Background copy to inactive failed";
		break;
	case 4:
		stage_dl_failed_value_txt = "Success";
		break;
	default:
		stage_dl_failed_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(
		json_obj, "STAGE_DL_FAILED",
		json_object_new_string(stage_dl_failed_value_txt));
}

/*
 * Check Boot Status Codes to verify whether AP booted successfully or not.
 * The list of bits used in the function is presented below:
 *
 *	AP0_HEARTBEAT_TIMEOUT
 *	AP0_BOOTCOMPLETE_TIMEOUT
 *	FATAL_ERR_AUTH_AP_FW
 *	FATAL_ERR_INIT_RESET_EVENT_FAIL,
 *	FATAL_ERR_SETUP_SPIMON_FAIL,
 *	FATAL_ERR_GRANT_AP_SPI_ACCESS_FAIL,
 *	FATAL_ERR_TRY_RELEASE_ON_INVALID_SLOT,
 *	FATAL_ERR_BC_ON_INVALID_SLOT,
 *	FATAL_ERR_BC_TIMEOUT_MAX_ATTEMPT
 *	FATAL_ERR_SET_TIMER
 *
 * If all these bits are set to 0 then the function returns true.
 */
bool is_booted_OK(const uint8_t *resp_msg, const int resp_len)
{
	uint8_t respByte5 = resp_msg[resp_len - 4];

	int offset = AP0_SPI_ACCESS_VIOLATION_OPCODE;

	bool hasTimeout =
		respByte5 & (uint8_t)(0x01)
				    << (AP0_HEARTBEAT_TIMEOUT - offset) ||
		respByte5 & (uint8_t)(0x01)
				    << (AP0_BOOTCOMPLETE_TIMEOUT - offset);

	if (hasTimeout == true) {
		return false;
	}

	bool hasFatalError =
		((respByte5 >> 4) == FATAL_ERR_AUTH_AP_FW) ||
		((respByte5 >> 4) == FATAL_ERR_INIT_RESET_EVENT_FAIL) ||
		((respByte5 >> 4) == FATAL_ERR_SETUP_SPIMON_FAIL) ||
		((respByte5 >> 4) == FATAL_ERR_GRANT_AP_SPI_ACCESS_FAIL) ||
		((respByte5 >> 4) == FATAL_ERR_TIMEOUT_WAIT_AP_PGOOD) ||
		((respByte5 >> 4) == FATAL_ERR_TRY_RELEASE_ON_INVALID_SLOT) ||
		((respByte5 >> 4) == FATAL_ERR_BC_ON_INVALID_SLOT) ||
		((respByte5 >> 4) == FATAL_ERR_BC_TIMEOUT_MAX_ATTEMPT) ||
		((respByte5 >> 4) == FATAL_ERR_SET_TIMER);

	if (hasFatalError == true) {
		return false;
	}

	return true;
}

/*
 * Query boot status:
 * Query Boot Status command can be called by AP firmware to know Glacier
 * and AP status. The returned boot status code is a 64-bit data.
 */
int query_boot_status(int fd, uint8_t tid, uint8_t verbose, uint8_t more)
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

	/* Show boot status codes when flag 'more' is set */
	if (more == true) {
		printf("\n");
		if (is_booted_OK(resp, resp_len) == true) {
			printf(MSG_BOOT_OK);
		} else {
			printf(MSG_BOOT_FAILED);
		}
		printf("\n");
		printf("\n");
		printf("Boot Status Codes\n");
		printf("\n");

		query_boot_status_print_bits0_to_bit7(resp, resp_len);
		query_boot_status_print_bits8_to_bit15(resp, resp_len);
		query_boot_status_print_bits16_to_bit23(resp, resp_len);
		query_boot_status_print_bits24_to_bit31(resp, resp_len);
		query_boot_status_print_bits32_to_bit39(resp, resp_len);
		query_boot_status_print_bits40_to_bit47(resp, resp_len);
		query_boot_status_print_bits48_to_bit57(resp, resp_len);
	}

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * Query boot status:
 * Query Boot Status command can be called by AP firmware to know Glacier
 * and AP status. The returned boot status codes are formatted in JSON.
 */
int query_boot_status_json(int fd, uint8_t tid)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_bootstatus cmd = { 0 };

	/* Encode the VDM headers for Query boot status */
	mctp_encode_vendor_cmd_bootstatus(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, false);

	struct json_object *json_obj = json_object_new_object();
	struct json_object *query_boot_status_response =
		json_object_new_object();
	struct json_object *boot_status_flags = json_object_new_object();

	create_json_with_completion_code(resp, query_boot_status_response);

	char *msg_boot;

	if (is_booted_OK(resp, resp_len) == true) {
		msg_boot = MSG_BOOT_OK;
	} else {
		msg_boot = MSG_BOOT_FAILED;
	}

	json_object_object_add(query_boot_status_response, "MSG_BOOT",
			       json_object_new_string(msg_boot));

	create_json_query_boot_status_bits0_to_bit7(resp, resp_len,
						    boot_status_flags);
	create_json_query_boot_status_bits8_to_bit15(resp, resp_len,
						     boot_status_flags);
	create_json_query_boot_status_bits16_to_bit23(resp, resp_len,
						      boot_status_flags);
	create_json_query_boot_status_bits24_to_bit31(resp, resp_len,
						      boot_status_flags);
	create_json_query_boot_status_bits32_to_bit39(resp, resp_len,
						      boot_status_flags);
	create_json_query_boot_status_bits40_to_bit47(resp, resp_len,
						      boot_status_flags);
	create_json_query_boot_status_bits48_to_bit57(resp, resp_len,
						      boot_status_flags);

	json_object_object_add(query_boot_status_response, "BOOT_STATUS_FLAGS",
			       boot_status_flags);

	json_object_object_add(json_obj, "RESPONSE",
			       query_boot_status_response);

	// Printing JSON object
	printf("%s\n", json_object_to_json_string_ext(json_obj,
						      JSON_C_TO_STRING_PRETTY));

	json_object_put(json_obj);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);

	return 0;
}

/*
 * This function parses the first byte from the response of 
 * the 'background_copy_query' command and generates corresponding JSON 
 * data representing the status of the background copy operation.
 * The status indicates whether background copy is enabled or disabled, 
 * and the behavior across power cycles.
 *
 * Possible statuses:
 * 0x0: Background Copy Disabled.
 *      This state persists across power cycles.
 * 0x1: Background Copy Enabled.
 *      This is the default behavior in ERoT unless 0x0, 0x2, 
 *      or 0x3 have been explicitly set.
 *      This state persists across power cycles.
 * 0x2: Background Copy Disabled for this boot cycle.
 *      No change is made to the non-volatile state.
 *      On the next boot, the non-volatile state is used 
 *      to determine if background copy is disabled or enabled.
 * 0x3: Background Copy Enabled for this boot cycle.
 *      No change is made to the non-volatile state.
 *      On the next boot, the non-volatile state is used 
 *      to determine if background copy is disabled or enabled.
 *
 */
void create_json_background_copy_query_status_byte_1(
	const uint8_t *resp_msg, struct json_object *json_obj)
{
	uint8_t resp_byte_1 =
		resp_msg[MCTP_VDM_BACKGROUND_COPY_BYTE_1_POSITION];

	char *query_status_value_txt;

	switch (resp_byte_1) {
	case 0x0:
		query_status_value_txt = "Disabled";
		break;
	case 0x1:
		query_status_value_txt = "Enabled";
		break;
	case 0x2:
		query_status_value_txt = "Disabled for this boot cycle";
		break;
	case 0x3:
		query_status_value_txt = "Enabled for this boot cycle";
		break;
	default:
		query_status_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(json_obj, "STATUS",
			       json_object_new_string(query_status_value_txt));
}

/*
 * This function parses the first byte from the response of 
 * the 'background_copy_progress' command and generates corresponding JSON 
 * data representing the status of the background copy progress.
 * The status indicates whether background copy is in progress or not.
 * 
 * Possible statuses:
 * 0x1: No background copy in progress or background copy complete.
 * 0x2: Background copy in progress.
 * 
 */
void create_json_background_copy_progress_byte_1(const uint8_t *resp_msg,
						 struct json_object *json_obj)
{
	uint8_t resp_byte_1 =
		resp_msg[MCTP_VDM_BACKGROUND_COPY_BYTE_1_POSITION];

	char *progress_value_txt;

	switch (resp_byte_1) {
	case 0x1:
		progress_value_txt =
			"No background copy in progress or background copy complete";
		break;
	case 0x2:
		progress_value_txt = "Background copy in progress";
		break;
	default:
		progress_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(json_obj, "STATUS",
			       json_object_new_string(progress_value_txt));
}

/*
 * This function parses the second byte from the response of 
 * the 'background_copy_progress' command and generates corresponding JSON 
 * data representing the progress of background copy operation.
 * 
 */
void create_json_background_copy_progress_byte_2(const uint8_t *resp_msg,
						 struct json_object *json_obj)
{
	uint8_t resp_byte_2 =
		resp_msg[MCTP_VDM_BACKGROUND_COPY_BYTE_2_POSITION];

	char progress_str[10];
	sprintf(progress_str, "%u%%", resp_byte_2);

	json_object_object_add(json_obj, "PROGRESS",
			       json_object_new_string(progress_str));
}

/*
 * This function parses the first byte from the response of 
 * the 'background_copy_pending' command and generates corresponding JSON 
 * data representing the status of the background copy pending.
 * The status indicates whether background copy is pending or not.
 * 
 * Possible statuses:
 * 0x1: No background copy pending.
 * 0x2: Background copy pending.
 * 
 */
void create_json_background_copy_pending_byte_1(const uint8_t *resp_msg,
						struct json_object *json_obj)
{
	uint8_t resp_byte_1 =
		resp_msg[MCTP_VDM_BACKGROUND_COPY_BYTE_1_POSITION];

	char *pending_value_txt;

	switch (resp_byte_1) {
	case 0x1:
		pending_value_txt = "No background copy pending";
		break;
	case 0x2:
		pending_value_txt = "Background copy pending";
		break;
	default:
		pending_value_txt = "Undefined value";
		break;
	}

	json_object_object_add(json_obj, "STATUS",
			       json_object_new_string(pending_value_txt));
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
 * Background Copy v1:
 * The command is mainly used to manage interaction between Global #WP
 * and background copy.
 * This command should only be supported on the OOB path and not on
 * the In Band path. The returned boot status codes are formatted in JSON.
 */
int background_copy_json(int fd, uint8_t tid, uint8_t code)
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
				       (uint8_t **)&resp, &resp_len, false);

	struct json_object *json_obj = json_object_new_object();
	struct json_object *background_copy_response = json_object_new_object();

	create_json_with_completion_code(resp, background_copy_response);

	switch (code) {
	case MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS:
		create_json_background_copy_query_status_byte_1(
			resp, background_copy_response);
		break;
	case MCTP_VDM_BACKGROUND_COPY_PROGRESS:
		create_json_background_copy_progress_byte_1(
			resp, background_copy_response);
		create_json_background_copy_progress_byte_2(
			resp, background_copy_response);
		break;
	case MCTP_VDM_BACKGROUND_COPY_PENDING:
		create_json_background_copy_pending_byte_1(
			resp, background_copy_response);
		break;
	}

	json_object_object_add(json_obj, "RESPONSE", background_copy_response);

	/* Printing JSON object */
	printf("%s\n", json_object_to_json_string_ext(json_obj,
						      JSON_C_TO_STRING_PRETTY));

	json_object_put(json_obj);

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

/*
 * */
int debug_token_query_v2(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_dbg_token_query cmd = { 0 };

	/* Encode the VDM headers for debug token query*/
	mctp_encode_vendor_cmd_dbg_token_query_v2(&cmd);

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
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_in_band cmd = { 0 };

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

/*
 *This command will allow an AP held in reset because the manual boot mode is
 *on.  The AP will be released from reset and allowed to boot as long as the
 *secure boot authentication passes.  If the AP is not being held in reset,
 *the command will essentially be a no-op.
 */
int boot_ap(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_boot_ap cmd = { 0 };

	/* Encode the VDM headers for Restart notification */
	mctp_encode_vendor_cmd_boot_ap(&cmd);

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
 * This command/query is for the manual boot mode, whereupon ERoT reset, if the
 * mode is on, the AP will be held in reset until the Boot AP command is
 * given.  This mode is applied only once per ERoT reset.  After the AP has
 * been booted, any firmware upgrade and AP reset will result in the AP booting
 * without intervention as long as the secure boot checks on the AP firmware
 * passes.
 */
int set_query_boot_mode(int fd, uint8_t tid, uint8_t code, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_set_query_boot_mode cmd = { 0 };

	/* Encode the VDM headers for Restart notification */
	mctp_encode_vendor_cmd_set_query_boot_mode(&cmd);

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

/* The command is used to install CAK */
int cak_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
		uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_cak_install cmd = { 0 };

	MCTP_ASSERT_RET(length <= (sizeof(cmd) - sizeof(cmd.vdr_msg_hdr)), -1,
			"the length is out of the spec.\n");

	/* Encode the VDM headers for CAK install */
	mctp_encode_vendor_cmd_cak_install(&cmd);

	memcpy((unsigned char *)&cmd.payload, payload, length);
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
This command is used to lock/move CAK from SRAM to Glacier internal flash
*/
int cak_lock(int fd, uint8_t tid, uint8_t *payload, size_t length,
	     uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_cak_lock cmd = { 0 };

	MCTP_ASSERT_RET(length <= MCTP_ECDSA_P_384_DOT_ENABLE_KEY, -1,
			"the length is out of the spec.\n");

	/* Encode the VDM headers for CAK lock */
	mctp_encode_vendor_cmd_cak_lock(&cmd);

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
 * Command to confirm if the current AP_FW Metadata can be successfully
 * authenticated using the current DOT CAK.
 */
int cak_test(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_cak_test cmd = { 0 };

	/* Encode the VDM headers for CAK test */
	mctp_encode_vendor_cmd_cak_test(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

/* Command to disable DOT Functionality */
int dot_disable(int fd, uint8_t tid, uint8_t *payload, size_t length,
		uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;

	struct mctp_vendor_cmd_dot_disable cmd = { 0 };

	MCTP_ASSERT_RET(length <= MCTP_ECDSA_P_384_DOT_ENABLE_KEY, -1,
			"the length is out of the spec.\n");

	/* Encode the VDM headers for DOT disable */
	mctp_encode_vendor_cmd_dot_disable(&cmd);

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
 * This command is used to install/flash DOT token onto Glacier internal SPI
 * Flash. Upon receipt, ECFW will authenticate the token and after successful
 * authentication, it shall perform DOT authorized commands like Unlock,
 * Enable, Signing Test, or Override depending upon the 'type' field in DOT
 * token structure. Processing error, if any, will be handled gracefully by
 * ECFW and the error code will be reported back as response.
 */
int dot_token_install(int fd, uint8_t tid, uint8_t *payload, size_t length,
		      uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_dot_token_inst cmd = { 0 };

	MCTP_ASSERT_RET(length == 256, -1, "the length is out of the spec.\n");

	/* Encode the VDM headers for debug token install */
	mctp_encode_vendor_cmd_dot_token_inst(&cmd);

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

int force_grant_revoke(int fd, uint8_t tid, uint8_t code, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_force_grant_revoked cmd = { 0 };

	/* Encode the VDM headers for force grant revoked command */
	mctp_encode_vendor_cmd_force_grant_revoked(&cmd);

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

int reset_erot(int fd, uint8_t tid, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_reset_erot cmd = { 0 };

	/* Encode the VDM headers for reset_erot command */
	mctp_encode_vendor_cmd_reset_erot(&cmd);

	/* Send and Receive the MCTP-VDM command */
	rc = mctp_vdm_client_send_recv(tid, fd, (uint8_t *)&cmd, sizeof(cmd),
				       (uint8_t **)&resp, &resp_len, verbose);

	/* free memory */
	free(resp);

	MCTP_ASSERT_RET(rc == MCTP_REQUESTER_SUCCESS, -1,
			"%s: fail to recv [rc: %d] response\n", __func__, rc);
	return 0;
}

int revoke_ap_otp(int fd, uint8_t tid, uint8_t code, uint8_t verbose)
{
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	mctp_requester_rc_t rc = -1;
	struct mctp_vendor_cmd_revoke_ap_otp cmd = { 0 };

	/* Encode the VDM headers for revoke AP otp command */
	mctp_encode_vendor_cmd_revoke_ap_otp(&cmd);

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
