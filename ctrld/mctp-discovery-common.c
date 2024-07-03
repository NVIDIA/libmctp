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
#include <stdlib.h>
#include <string.h>

#include "mctp-discovery-common.h"
#include "libmctp-cmds.h"
#include "mctp-ctrl-log.h"

/* Global pointer for Routing table and its length */
mctp_routing_table_t *g_routing_table_entries = NULL;
int g_routing_table_length = 0;

/* Global pointer for UUID and its length */
mctp_uuid_table_t *g_uuid_entries = NULL;
int g_uuid_table_len = 0;

/* Global pointer for Message types and its length */
mctp_msg_type_table_t *g_msg_type_entries = NULL;
int g_msg_type_table_len = 0;

/* Global EID pool size and start position */
uint8_t g_eid_pool_size = 0;
uint8_t g_eid_pool_start = 0;

/* Start point of Routing entry */
const uint8_t MCTP_ROUTING_ENTRY_START = 0;

/* Map for Tracing ID and the message */
mctp_discovery_message_table_t msg_tbl[] = {
	{ MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST,
	  "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST" },
	{ MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE,
	  "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE" },
	{ MCTP_EP_DISCOVERY_REQUEST, "MCTP_EP_DISCOVERY_REQUEST" },
	{ MCTP_EP_DISCOVERY_RESPONSE, "MCTP_EP_DISCOVERY_RESPONSE" },
	{ MCTP_SET_EP_REQUEST, "MCTP_SET_EP_REQUEST" },
	{ MCTP_SET_EP_RESPONSE, "MCTP_SET_EP_RESPONSE" },
	{ MCTP_ALLOCATE_EP_ID_REQUEST, "MCTP_ALLOCATE_EP_ID_REQUEST" },
	{ MCTP_ALLOCATE_EP_ID_RESPONSE, "MCTP_ALLOCATE_EP_ID_RESPONSE" },
	{ MCTP_GET_MSG_TYPE_REQUEST, "MCTP_GET_MSG_TYPE_REQUEST" },
	{ MCTP_GET_MSG_TYPE_RESPONSE, "MCTP_GET_MSG_TYPE_RESPONSE" },
};

/* Helper function to print respons messages */
void mctp_print_resp_msg(struct mctp_ctrl_resp *ep_discovery_resp,
			 const char *msg, int msg_len)
{
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");

	/* Print only if message exist */
	if (msg) {
		MCTP_CTRL_TRACE("   %s\n", msg);
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");
	}

	MCTP_CTRL_TRACE("MCTP-RESP-HDR >> \n");
	MCTP_CTRL_TRACE("\tmsg_type \t: 0x%x\n",
			ep_discovery_resp->hdr.ic_msg_type);
	MCTP_CTRL_TRACE("\trq_dgram_inst \t: 0x%x\n",
			ep_discovery_resp->hdr.rq_dgram_inst);
	MCTP_CTRL_TRACE("\tcommand_code \t: 0x%x\n",
			ep_discovery_resp->hdr.command_code);

	/* Print the compeltion code */
	if (msg_len >= 1)
		MCTP_CTRL_TRACE("\tcomp_code \t: 0x%x (%s)\n",
				ep_discovery_resp->completion_code,
				(ep_discovery_resp->completion_code ==
				 MCTP_CTRL_CC_SUCCESS) ?
					"SUCCESS" :
					"FAILURE");

	/* Decrement the length by one */
	msg_len--;

	MCTP_CTRL_TRACE("MCTP-RESP-DATA >> \n");

	/* Check if data available or not */
	if (msg_len <= 0) {
		MCTP_CTRL_TRACE("\t--------------<empty>-------------\n");
	}

	for (int i = 0; i < msg_len; i++)
		MCTP_CTRL_TRACE("\tDATA[%d] \t\t: 0x%x\n", i,
				ep_discovery_resp->data[i]);
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
}

/* Tracing function to print request messages */
void mctp_print_req_msg(struct mctp_ctrl_req *ep_discovery_req, const char *msg,
			size_t msg_len)
{
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");

	/* Print only if message exist */
	if (msg) {
		MCTP_CTRL_TRACE("   %s\n", msg);
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");
	}

	MCTP_CTRL_TRACE("MCTP-REQ-HDR >> \n");
	MCTP_CTRL_TRACE("\tmsg_type \t: 0x%x\n",
			ep_discovery_req->hdr.ic_msg_type);
	MCTP_CTRL_TRACE("\trq_dgram_inst \t: 0x%x\n",
			ep_discovery_req->hdr.rq_dgram_inst);
	MCTP_CTRL_TRACE("\tcommand_code \t: 0x%x\n",
			ep_discovery_req->hdr.command_code);

	MCTP_CTRL_TRACE("MCTP-REQ-DATA >> \n");

	/* Check if data available or not */
	if (msg_len <= 0) {
		MCTP_CTRL_TRACE("\t--------------<empty>-------------\n");
	}

	for (size_t i = 0; i < msg_len; i++)
		MCTP_CTRL_TRACE("\tDATA[%zu] \t\t: 0x%x\n", i,
				ep_discovery_req->data[i]);
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
}

/* Tracing function to print Routing table entry */
void mctp_print_routing_table_entry(
	int routing_id, struct get_routing_table_entry *routing_table)
{
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
	MCTP_CTRL_TRACE("MCTP-ROUTING-TABLE-ENTRY [%d]\n", routing_id);

	/* Print only if message exist */
	if (routing_table) {
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");

		MCTP_CTRL_TRACE("\t\teid_range_size            :  0x%x\n",
				routing_table->eid_range_size);
		MCTP_CTRL_TRACE("\t\tstarting_eid              :  0x%x\n",
				routing_table->starting_eid);
		MCTP_CTRL_TRACE("\t\tentry_type                :  0x%x\n",
				routing_table->entry_type);
		MCTP_CTRL_TRACE("\t\tphys_transport_binding_id :  0x%x\n",
				routing_table->phys_transport_binding_id);
		MCTP_CTRL_TRACE("\t\tphys_media_type_id        :  0x%x\n",
				routing_table->phys_media_type_id);
		MCTP_CTRL_TRACE("\t\tphys_address_size         :  0x%x\n",
				routing_table->phys_address_size);
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");
	} else {
		MCTP_CTRL_TRACE(
			"-----------------< empty/invalid >------------------\n");
	}
}

/* Tracing function to print Messgae types */
static void
mctp_print_msg_types_table_entry(mctp_msg_type_table_t *msg_type_table)
{
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
	MCTP_CTRL_TRACE("MCTP-MSG-TYPE-TABLE-ENTRY\n");

	/* Print only if message exist */
	if (msg_type_table) {
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");

		MCTP_CTRL_TRACE("\t\tEID                       :  0x%x\n",
				msg_type_table->eid);
		MCTP_CTRL_TRACE("\t\tNumber of supported types :  0x%x\n",
				msg_type_table->data_len);
		MCTP_CTRL_TRACE("\t\tSupported Types           :  ");
		for (int i = 0; i < msg_type_table->data_len; i++) {
			MCTP_CTRL_TRACE("0x%x  ", msg_type_table->data[i]);
		}
		MCTP_CTRL_TRACE(
			"\n-----------------------------------------------\n");
	} else {
		MCTP_CTRL_TRACE(
			"-----------------< empty/invalid >------------------\n");
	}
}

/* Tracing function to print UUID */
static void mctp_print_uuid_table_entry(mctp_uuid_table_t *uuid_tbl)
{
	MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
	MCTP_CTRL_TRACE("MCTP-UUID-ENTRY-FOR-EID                 :  0x%x\n",
			uuid_tbl->eid);

	/* Print only if message exist */
	if (uuid_tbl) {
		MCTP_CTRL_TRACE(
			"-----------------------------------------------\n");

		MCTP_CTRL_TRACE("\t\tEID                             :  0x%x\n",
				uuid_tbl->eid);
		MCTP_CTRL_TRACE("\t\tUUID:(time-low)                 :  0x%x\n",
				uuid_tbl->uuid.canonical.data0);
		MCTP_CTRL_TRACE("\t\tUUID:(time-mid)                 :  0x%x\n",
				uuid_tbl->uuid.canonical.data1);
		MCTP_CTRL_TRACE("\t\tUUID:(time-high and version)    :  0x%x\n",
				uuid_tbl->uuid.canonical.data2);
		MCTP_CTRL_TRACE("\t\tUUID:(clk-seq and resvd)        :  0x%x\n",
				uuid_tbl->uuid.canonical.data3);
		MCTP_CTRL_TRACE(
			"\t\tUUID:(node)                     :  0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",
			uuid_tbl->uuid.canonical.data4[0],
			uuid_tbl->uuid.canonical.data4[1],
			uuid_tbl->uuid.canonical.data4[2],
			uuid_tbl->uuid.canonical.data4[3],
			uuid_tbl->uuid.canonical.data4[4],
			uuid_tbl->uuid.canonical.data4[5]);
		MCTP_CTRL_TRACE(
			"\n-----------------------------------------------\n");
	} else {
		MCTP_CTRL_TRACE(
			"-----------------< empty/invalid >------------------\n");
	}
}

void mctp_routing_entry_display(void)
{
	mctp_routing_table_t *display_entry;

	/* Get the start pointer */
	display_entry = g_routing_table_entries;

	while (display_entry != NULL) {
		mctp_print_routing_table_entry(display_entry->id,
					       &(display_entry->routing_table));
		display_entry = display_entry->next;
	}
}

/* To create a new routing entry and add to global routing table */
int mctp_routing_entry_add(struct get_routing_table_entry *routing_table_entry)
{
	mctp_routing_table_t *new_entry, *temp_entry;
	static int routing_id = 0;

	/* Create a new Routing table entry */
	new_entry =
		(mctp_routing_table_t *)malloc(sizeof(mctp_routing_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the contents */
	memcpy(&new_entry->routing_table, routing_table_entry,
	       sizeof(struct get_routing_table_entry));

	new_entry->valid = true;

	/* Check if any entry exist */
	if (g_routing_table_entries == NULL) {
		g_routing_table_entries = new_entry;
		new_entry->next = NULL;

		/* Rese the routing ID to zero */
		routing_id = 0;

		/* Update the routing ID */
		new_entry->id = routing_id++;

		return 0;
	}

	/* Traverse the routing table */
	temp_entry = g_routing_table_entries;
	while (temp_entry->next != NULL) {
		if (temp_entry->routing_table.starting_eid ==
		    new_entry->routing_table.starting_eid) {
			MCTP_CTRL_DEBUG(
				"%s: Routing table entry with EID: %d already exists, ignoring\n",
				__func__,
				temp_entry->routing_table.starting_eid);
			temp_entry->valid = true;
			free(new_entry);
			new_entry = NULL;
			return 0;
		}
		temp_entry = temp_entry->next;
	}

	if (temp_entry->routing_table.starting_eid ==
	    new_entry->routing_table.starting_eid) {
		MCTP_CTRL_DEBUG(
			"%s: Routing table entry with EID: %d already exists, ignoring\n",
			__func__, temp_entry->routing_table.starting_eid);
		temp_entry->valid = true;
		free(new_entry);
		new_entry = NULL;
		return 0;
	}

	/* Add at the last */
	temp_entry->next = new_entry;
	new_entry->next = NULL;

	/* Update the routing ID */
	new_entry->id = routing_id++;

	/* Increment the global counter */
	g_routing_table_length++;

	return 0;
}

/* To delete all the entris in global routing table */
void mctp_routing_entry_delete_all(void)
{
	mctp_routing_table_t *del_entry;

	// Check if entry exist
	while (g_routing_table_entries != NULL) {
		del_entry = g_routing_table_entries;
		g_routing_table_entries = del_entry->next;

		MCTP_CTRL_DEBUG("%s: Deleting Routing table: %d\n", __func__,
				del_entry->id);

		free(del_entry);
	}
}

void mctp_uuid_display(void)
{
	mctp_uuid_table_t *display_entry;

	/* Get the start pointer */
	display_entry = g_uuid_entries;

	while (display_entry != NULL) {
		mctp_print_uuid_table_entry(display_entry);
		display_entry = display_entry->next;
	}
}

/* To create a new UUID entry and add to global UUID table */
int mctp_uuid_entry_add(mctp_uuid_table_t *uuid_tbl)
{
	mctp_uuid_table_t *new_entry, *temp_entry;

	/* Create a new Message type entry */
	new_entry = (mctp_uuid_table_t *)malloc(sizeof(mctp_uuid_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the Message type contents */
	memcpy(new_entry, uuid_tbl, sizeof(mctp_uuid_table_t));

	/* Check if any entry exist */
	if (g_uuid_entries == NULL) {
		g_uuid_entries = new_entry;
		new_entry->next = NULL;

		return 0;
	}

	/* Traverse the message type table */
	temp_entry = g_uuid_entries;
	while (temp_entry->next != NULL)
		temp_entry = temp_entry->next;

	/* Add at the last */
	temp_entry->next = new_entry;
	new_entry->next = NULL;

	/* Increment the global counter */
	g_uuid_table_len++;

	return 0;
}

/** To remove single entry by UUID key */
int mctp_uuid_entry_remove(uint8_t eid)
{
	mctp_uuid_table_t *prev = NULL, *curr = NULL;
	for (curr = g_uuid_entries; curr; curr = curr->next) {
		if (curr->eid == eid) {
			if (prev)
				prev->next = curr->next;
			else
				g_uuid_entries = curr->next;
			free(curr);
			--g_uuid_table_len;
			return 0;
		}
		prev = curr;
	}
	return -1;
}

/* To delete all the UUID information */
void mctp_uuid_delete_all(void)
{
	mctp_uuid_table_t *del_entry;

	// Check if entry exist
	while (g_uuid_entries != NULL) {
		del_entry = g_uuid_entries;
		g_uuid_entries = del_entry->next;

		MCTP_CTRL_DEBUG("%s: Deleting UUID Entry: EID[%d]\n", __func__,
				del_entry->eid);

		free(del_entry);
	}
}

void mctp_msg_types_display(void)
{
	mctp_msg_type_table_t *display_entry;

	/* Get the start pointer */
	display_entry = g_msg_type_entries;

	while (display_entry != NULL) {
		mctp_print_msg_types_table_entry(display_entry);
		display_entry = display_entry->next;
	}
}

/* To create a new MCTP Message type and add to global message type */
int mctp_msg_type_entry_add(mctp_msg_type_table_t *msg_type_tbl)
{
	mctp_msg_type_table_t *new_entry, *temp_entry;

	/* Create a new Message type entry */
	new_entry =
		(mctp_msg_type_table_t *)malloc(sizeof(mctp_msg_type_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the Message type contents */
	memcpy(new_entry, msg_type_tbl, sizeof(mctp_msg_type_table_t));

	/* Check if any entry exist */
	if (g_msg_type_entries == NULL) {
		g_msg_type_entries = new_entry;
		new_entry->next = NULL;

		return 0;
	}

	/* Traverse the message type table */
	temp_entry = g_msg_type_entries;
	while (temp_entry->next != NULL) {
		if (temp_entry->eid == new_entry->eid) {
			MCTP_CTRL_DEBUG(
				"%s: EID %d already exists in message type list, ignoring.\n",
				__func__, temp_entry->eid);
			temp_entry->enabled = true;
			free(new_entry);
			return 0;
		}
		temp_entry = temp_entry->next;
	}

	if (temp_entry->eid == new_entry->eid) {
		MCTP_CTRL_DEBUG(
			"%s: EID %d already exists in message type list, ignoring.\n",
			__func__, temp_entry->eid);
		temp_entry->enabled = true;
		free(new_entry);
		return 0;
	}

	/* Add at the last */
	temp_entry->next = new_entry;
	new_entry->next = NULL;

	/* Increment the global counter */
	g_msg_type_table_len++;

	return 0;
}

/* To remove MCTP type entry by EID */
int mctp_msg_type_entry_remove(uint8_t eid)
{
	mctp_msg_type_table_t *prev = NULL, *curr = NULL;
	for (curr = g_msg_type_entries; curr; curr = curr->next) {
		if (curr->eid == eid) {
			if (prev)
				prev->next = curr->next;
			else
				g_msg_type_entries = curr->next;
			free(curr);
			--g_msg_type_table_len;
			return 0;
		}
		prev = curr;
	}
	return -1;
}

/* To delete all the Messgae types information */
void mctp_msg_types_delete_all(void)
{
	mctp_msg_type_table_t *del_entry;

	// Check if entry exist
	while (g_msg_type_entries != NULL) {
		del_entry = g_msg_type_entries;
		g_msg_type_entries = del_entry->next;

		MCTP_CTRL_DEBUG("%s: Deleting msg type entry: EID[%d]\n",
				__func__, del_entry->eid);

		free(del_entry);
	}
}
