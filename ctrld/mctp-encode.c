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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "libmctp-cmds.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-ctrl-log.h"
#include "mctp-encode.h"

static uint8_t createInstanceId()
{
	static uint8_t instanceId = 0x00;

	//instanceId = (instanceId + 1) & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	instanceId = (instanceId)&MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	return instanceId;
}

static uint8_t getRqDgramInst()
{
	uint8_t instanceID = createInstanceId();
	uint8_t rqDgramInst = instanceID | MCTP_CTRL_HDR_FLAG_REQUEST;
	return rqDgramInst;
}

/* TODO: Will be revisiting the instance id management is done by upper
 * layer or the control command by itself.
 */

static void encode_ctrl_cmd_header(struct mctp_ctrl_cmd_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

/* Prepare endpoint discovery request */
bool mctp_encode_ctrl_cmd_prepare_ep_discovery(
	struct mctp_ctrl_cmd_prepare_ep_discovery *prep_ep_discovery)
{
	if (!prep_ep_discovery)
		return false;

	encode_ctrl_cmd_header(&prep_ep_discovery->ctrl_msg_hdr,
			       getRqDgramInst(),
			       MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY);
	return true;
}

/* Prepare endpoint discovery response */
bool mctp_decode_resp_prepare_ep_discovery(
	struct mctp_ctrl_resp_prepare_discovery *prep_ep_discovery)
{
	if (!prep_ep_discovery)
		return false;

	if (prep_ep_discovery->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	return true;
}

/* Endpoint discovery request */
bool mctp_encode_ctrl_cmd_ep_discovery(
	struct mctp_ctrl_cmd_ep_discovery *ep_discovery)
{
	if (!ep_discovery)
		return false;

	encode_ctrl_cmd_header(&ep_discovery->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_ENDPOINT_DISCOVERY);
	return true;
}

/*
 * Endpoint discovery response (only if the EPs undiscoveed), otherwise
 * don't expect response from EPs [as per DSP0238: Figure 2]
 */
bool mctp_decode_resp_ep_discovery(
	struct mctp_ctrl_resp_endpoint_discovery *ep_discovery)
{
	if (!ep_discovery)
		return false;

	if (ep_discovery->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	return true;
}

/* Set Endpoint ID request */
bool mctp_encode_ctrl_cmd_set_eid(struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
				  mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
	if (!set_eid_cmd)
		return false;

	encode_ctrl_cmd_header(&set_eid_cmd->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	set_eid_cmd->operation = op;
	set_eid_cmd->eid = eid;
	return true;
}

/*
 * Set Endpoint ID response
 * NOTE: Here the response should indicate whether the endpoint supports
 * an EID pool. the bus owner can then issue the Allocate Endpoint IDs
 * command (based on pool size in the response) to supply the pool of EIDs
 * to the device.
 * Refer DSP0236 (Section 12.10) for more details
 */

bool mctp_decode_resp_set_eid(struct mctp_ctrl_resp_set_eid *set_eid)
{
	if (!set_eid)
		return false;

	if (set_eid->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	MCTP_CTRL_DEBUG("%s: eid_set: 0x%x, eid_pool_size: 0x%x\n", __func__,
			set_eid->eid_set, set_eid->eid_pool_size);
	return true;
}

/* Allocate Endpoint ID request */
bool mctp_encode_ctrl_cmd_alloc_eid(
	struct mctp_ctrl_cmd_alloc_eid *alloc_eid_cmd,
	mctp_ctrl_cmd_alloc_eid_op op, uint8_t pool_size, uint8_t start)
{
	if (!alloc_eid_cmd)
		return false;

	/* Update allocate EID operation flag */
	alloc_eid_cmd->operation = op;

	/* Update the EIDs pool start and the pool size */
	alloc_eid_cmd->eid_pool_size = pool_size;
	alloc_eid_cmd->eid_start = start;

	encode_ctrl_cmd_header(&alloc_eid_cmd->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);

	return true;
}

/* Allocate Endpoint ID response */
bool mctp_decode_resp_alloc_eid(struct mctp_ctrl_resp_alloc_eid *alloc_eid)
{
	if (!alloc_eid)
		return false;

	if (alloc_eid->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	MCTP_CTRL_DEBUG("%s: eid_start: 0x%x, eid_pool_size: 0x%x\n", __func__,
			alloc_eid->eid_start, alloc_eid->eid_pool_size);

	return true;
}

/* Get Routing table request */
bool mctp_encode_ctrl_cmd_get_routing_table(
	struct mctp_ctrl_cmd_get_routing_table *get_routing_table_cmd,
	uint8_t entry_handle)
{
	if (!get_routing_table_cmd)
		return false;

	encode_ctrl_cmd_header(&get_routing_table_cmd->ctrl_msg_hdr,
			       getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	get_routing_table_cmd->entry_handle = entry_handle;
	return true;
}

bool mctp_decode_resp_get_routing_table(
	struct mctp_ctrl_resp_get_routing_table *routing_table)
{
	if (!routing_table)
		return false;

	if (routing_table->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	MCTP_CTRL_DEBUG("%s: next_entry_handle: %d, number_of_entries: %d\n",
			__func__, routing_table->next_entry_handle,
			routing_table->number_of_entries);

	return true;
}

bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd)
{
	if (!get_eid_cmd)
		return false;

	encode_ctrl_cmd_header(&get_eid_cmd->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	return true;
}

bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd)
{
	if (!get_uuid_cmd)
		return false;

	encode_ctrl_cmd_header(&get_uuid_cmd->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	return true;
}

bool mctp_decode_resp_get_uuid(struct mctp_ctrl_resp_get_uuid *get_uuid_resp)
{
	if (!get_uuid_resp)
		return false;

	if (get_uuid_resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	MCTP_CTRL_DEBUG("%s: sizeof uuid: %zu\n", __func__,
			sizeof(get_uuid_resp->uuid.raw));

	return true;
}

bool mctp_encode_ctrl_cmd_get_ver_support(
	struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
	uint8_t msg_type_number)
{
	if (!mctp_ver_support_cmd)
		return false;

	encode_ctrl_cmd_header(&mctp_ver_support_cmd->ctrl_msg_hdr,
			       getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	mctp_ver_support_cmd->msg_type_number = msg_type_number;
	return true;
}

bool mctp_decode_resp_get_ver_support(
	struct mctp_ctrl_resp_get_mctp_ver_support *mctp_ver_support_resp)
{
	if (!mctp_ver_support_resp)
		return false;

	if (mctp_ver_support_resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	MCTP_CTRL_DEBUG("%s: number of entries: %zu\n", __func__,
			sizeof(mctp_ver_support_resp->number_of_entries));

	return true;
}

bool mctp_encode_ctrl_cmd_get_msg_type_support(
	struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd)
{
	if (!msg_type_support_cmd)
		return false;

	encode_ctrl_cmd_header(&msg_type_support_cmd->ctrl_msg_hdr,
			       getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	return true;
}

bool mctp_decode_ctrl_cmd_get_msg_type_support(
	struct mctp_ctrl_resp_get_msg_type_support *msg_type_support_cmd)
{
	if (!msg_type_support_cmd)
		return false;

	if (msg_type_support_cmd->completion_code != MCTP_CTRL_CC_SUCCESS)
		return false;

	return true;
}

bool mctp_encode_ctrl_cmd_get_vdm_support(
	struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd,
	uint8_t v_id_set_selector)
{
	if (!vdm_support_cmd)
		return false;

	encode_ctrl_cmd_header(&vdm_support_cmd->ctrl_msg_hdr, getRqDgramInst(),
			       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	vdm_support_cmd->vendor_id_set_selector = v_id_set_selector;
	return true;
}

bool mctp_encode_ctrl_cmd_discovery_notify(
	struct mctp_ctrl_cmd_discovery_notify *discovery_notify_cmd)
{
	if (!discovery_notify_cmd)
		return false;

	encode_ctrl_cmd_header(&discovery_notify_cmd->ctrl_msg_hdr,
			       getRqDgramInst(),
			       MCTP_CTRL_CMD_DISCOVERY_NOTIFY);
	return true;
}
