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
#include "libmctp-smbus.h"

#include "mctp-discovery-i2c.h"
#include "mctp-discovery-common.h"

#include "mctp-ctrl.h"
#include "mctp-encode.h"
#include "mctp-ctrl-log.h"

extern uint8_t g_eid_pool_size;
extern uint8_t g_eid_pool_start;
extern mctp_routing_table_t *g_routing_table_entries;
extern const uint8_t MCTP_ROUTING_ENTRY_START;

/* The EIDs and pool start information would be obtaind from commandline */
static uint8_t g_i2c_bridge_eid, g_i2c_own_eid, g_i2c_bridge_pool_start;
static uint8_t g_i2c_bus, g_i2c_dest_slave_addr, g_i2c_src_slave_addr;

void set_g_val_for_pvt_binding(uint8_t bus_num, uint8_t dest_slave_addr, uint8_t src_slave_addr)
{
	g_i2c_bus = bus_num;
	g_i2c_dest_slave_addr = dest_slave_addr;
	g_i2c_src_slave_addr = src_slave_addr;
}

/* Send function for Get MCTP version support */
mctp_ret_codes_t mctp_i2c_get_mctp_ver_support_request(int sock_fd, uint8_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_mctp_ver_support get_mctp_ver_support;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;

	(void)eid;

	/* Set destination EID */
	dest_eid = 0;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Encode Get MCTP version support message */
	req_ret = mctp_encode_ctrl_cmd_get_ver_support(&get_mctp_ver_support, MCTP_MESSAGE_TYPE_MCTP_CTRL);

	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &get_mctp_ver_support, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_VERSION_SUPPORT_REQUEST", msg_len);

	/* TBD: ep request set eid issue */
	ep_req.data[0] = 0;

	/* Send the request message over socket */
	mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
								(const uint8_t *) &ep_req,
								sizeof(struct mctp_ctrl_cmd_set_eid),
								&bind_id, (void *) &pvt_binding,
								sizeof(pvt_binding));


	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}



/* Send function for Set Endpoint ID */
mctp_ret_codes_t mctp_i2c_set_eid_send_request(int sock_fd, mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_set_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;

	/* Set destination EID as NULL */
	dest_eid = MCTP_EID_NULL;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Encode Set Endpoint ID message */
	req_ret = mctp_encode_ctrl_cmd_set_eid(&set_eid_req, op, eid);

	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_set_eid) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req, sizeof(struct mctp_ctrl_cmd_set_eid));

	mctp_print_req_msg(&ep_req, "MCTP_SET_EP_REQUEST", msg_len);

	/* TBD: ep request set eid issue */
	ep_req.data[0] = 0;

	/* Send the request message over socket */
	mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
								(const uint8_t *) &ep_req,
								sizeof(struct mctp_ctrl_cmd_set_eid),
								&bind_id, (void *) &pvt_binding,
								sizeof(pvt_binding));


	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Set Endpoint ID */
int mctp_i2c_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
					uint8_t eid, uint8_t *eid_count)
{
	bool req_ret;
	struct mctp_ctrl_resp_set_eid *set_eid_resp;

	(void)eid;

	mctp_print_resp_msg(
		(struct mctp_ctrl_resp *)mctp_resp_msg, "MCTP_SET_EP_RESPONSE",
		resp_msg_len - sizeof(struct mctp_ctrl_cmd_msg_hdr));

	set_eid_resp = (struct mctp_ctrl_resp_set_eid *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_set_eid(set_eid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (set_eid_resp->completion_code ==
			MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_CTRL_DEBUG(
				"%s: Device [eid: %d] is not ready yet..\n",
				__func__, set_eid_resp->eid_set);
			return MCTP_RET_DEVICE_NOT_READY;
		}

		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check whether the EID is accepted by the device or not */
	if (set_eid_resp->status & MCTP_SETEID_ASSIGN_STATUS_REJECTED) {
		MCTP_CTRL_DEBUG(
			"%s: Set Endpoint id: 0x%x, Status:0x%x (Rejected by the device)\n",
			__func__, set_eid_resp->status, set_eid_resp->eid_set);

		/* Get the EID from the bridge (FPGA) */
		g_i2c_bridge_eid = set_eid_resp->eid_set;
	} else {
		MCTP_CTRL_DEBUG(
			"%s: Set Endpoint id: 0x%x (Accepted by the device)\n",
			__func__, set_eid_resp->eid_set);
	}

	/* Check whether the device requires EID pool allocation or not */
	if (set_eid_resp->status & MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ) {
		MCTP_CTRL_DEBUG(
			"%s: Endpoint require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* Get the EID pool size from response */
		g_eid_pool_size = set_eid_resp->eid_pool_size;

		/* update the eid_count pointer */
		*eid_count = set_eid_resp->eid_pool_size;

		MCTP_CTRL_DEBUG("%s: g_i2c_eid_pool_size: 0x%x\n", __func__,
				g_eid_pool_size);

	} else {
		MCTP_CTRL_DEBUG(
			"%s: Endpoint doesn't require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* Reset the EID pool size */
		g_eid_pool_size = 0;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Allocate Endpoint ID */
mctp_ret_codes_t mctp_i2c_alloc_eid_send_request(int sock_fd,
						mctp_eid_t assigned_eid,
						mctp_ctrl_cmd_set_eid_op op,
						uint8_t eid_count,
						uint8_t eid_start)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_alloc_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;

	/* Set destination EID as NULL */
	dest_eid = assigned_eid;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Allocate Endpoint ID's message */
	req_ret = mctp_encode_ctrl_cmd_alloc_eid(&set_eid_req,
			(mctp_ctrl_cmd_alloc_eid_op)op, eid_count, eid_start);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_alloc_eid) -
			sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req, sizeof(struct mctp_ctrl_cmd_alloc_eid));

	/* Force set to 0 */
	ep_req.data[0] = 0;

	mctp_print_req_msg(&ep_req, "MCTP_ALLOCATE_EP_ID_REQUEST", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_alloc_eid), &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Allocate Endpoint ID */
int mctp_i2c_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_alloc_eid *alloc_eid_resp;

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
				"MCTP_ALLOCATE_EP_ID_RESPONSE",
				resp_msg_len -
					sizeof(struct mctp_ctrl_cmd_msg_hdr));

	alloc_eid_resp = (struct mctp_ctrl_resp_alloc_eid *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_alloc_eid(alloc_eid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check whether allocation was accepted or not */
	if (alloc_eid_resp->alloc_status == MCTP_ALLOC_EID_REJECTED) {
		MCTP_CTRL_ERR(
			"%s: Alloc Endpoint ID rejected/already allocated by another bus owner\n",
			__func__);
	}

	/* Get EID pool size and the EID start */
	g_eid_pool_size = alloc_eid_resp->eid_pool_size;
	g_eid_pool_start = alloc_eid_resp->eid_start;

	MCTP_CTRL_DEBUG("%s: g_eid_pool_size: %d, eid_start: %d\n", __func__,
			g_eid_pool_size, g_eid_pool_start);

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get routing table */
mctp_ret_codes_t mctp_i2c_get_routing_table_send_request(int sock_fd,
							 mctp_eid_t eid,
							 uint8_t entry_handle)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_routing_table get_routing_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
	static int entry_count = 0;

	(void)eid;

	/* Set destination EID as NULL */
	dest_eid = MCTP_EID_NULL;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Get routing table request message */
	req_ret = mctp_encode_ctrl_cmd_get_routing_table(
		&get_routing_req, entry_handle + entry_count);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Increment the entry count */
	entry_count++;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_routing_table) -
			sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &get_routing_req,
			sizeof(struct mctp_ctrl_cmd_get_routing_table));

	mctp_print_req_msg(&ep_req, "MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST",
				msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_routing_table), &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get routing table */
int mctp_i2c_get_routing_table_get_response(int sock_fd, mctp_eid_t eid,
					uint8_t *mctp_resp_msg,
					size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_routing_table *routing_table;
	int ret;

	(void)sock_fd;
	(void)eid;

	MCTP_CTRL_TRACE("%s: Get EP reesponse\n", __func__);

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
				"MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE",
				resp_msg_len -
					sizeof(struct mctp_ctrl_cmd_msg_hdr));

	routing_table =
		(struct mctp_ctrl_resp_get_routing_table *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_get_routing_table(routing_table);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (routing_table->completion_code ==
			MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_CTRL_DEBUG("%s: Device is not ready yet..\n",
					__func__);
			return MCTP_RET_DEVICE_NOT_READY;
		}
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_CTRL_DEBUG("%s: Next entry handle: %d, Number of entries: %d\n",
			__func__, routing_table->next_entry_handle,
			routing_table->number_of_entries);

	/* Check if the routing table exist */
	if (routing_table->number_of_entries) {
		struct get_routing_table_entry routing_table_entry;

		/* Copy the routing table entries to local routing table */
		memcpy(&routing_table_entry,
				mctp_resp_msg +
				sizeof(struct mctp_ctrl_resp_get_routing_table),
				sizeof(struct get_routing_table_entry));

		/* Dont add the entry to the routing table if the EID is it's own */
		if (routing_table_entry.starting_eid == g_i2c_own_eid) {

			MCTP_CTRL_DEBUG(
				"%s: Found it's own eid: [%d] in the Routing table\n",
				__func__, routing_table_entry.starting_eid);
		} else {

			/* Add the entry to a linked list */
			ret = mctp_routing_entry_add(&routing_table_entry);

			if (ret < 0) {
				MCTP_CTRL_ERR(
					"%s: Failed to update global routing table..\n",
					__func__);
				return MCTP_RET_REQUEST_FAILED;
			}

			/* Print the routing table entry */
			mctp_print_routing_table_entry(
				g_routing_table_entries->id,
				&routing_table_entry);

			/* Length of the Routing table */
			MCTP_CTRL_DEBUG(
				"%s: EID: 0x%x, Routing table length: %d\n",
				__func__, routing_table_entry.starting_eid,
				g_eid_pool_size);
		}

		/* Check if the next routing table exist.. */
		if (routing_table->next_entry_handle != 0xFF) {
			MCTP_CTRL_DEBUG("%s: Next routing entry found %d\n",
					__func__,
					routing_table->next_entry_handle);

			return MCTP_RET_ROUTING_TABLE_FOUND;
		} else {
			MCTP_CTRL_DEBUG("%s: No more routing entries %d\n",
					__func__,
					routing_table->next_entry_handle);
		}
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get UUID */
mctp_ret_codes_t mctp_i2c_get_endpoint_uuid_send_request(int sock_fd,
							 mctp_eid_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_uuid uuid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;

	/* Set destination EID */
	dest_eid = eid;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_uuid(&uuid_req);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_uuid) -
			sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &uuid_req, sizeof(struct mctp_ctrl_cmd_get_uuid));

	mctp_print_req_msg(&ep_req, "MCTP_GET_EP_UUID_REQUEST", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_uuid), &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get UUID */
int mctp_i2c_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
					size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_uuid *uuid_resp;
	int ret;
	mctp_uuid_table_t uuid_table;

	/* Trace the Rx message */
	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
				"MCTP_GET_EP_UUID_RESPONSE",
				resp_msg_len -
					sizeof(struct mctp_ctrl_cmd_msg_hdr));

	uuid_resp = (struct mctp_ctrl_resp_get_uuid *)mctp_resp_msg;

	/* Parse the UUID response message */
	req_ret = mctp_decode_resp_get_uuid(uuid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Update UUID private params to export to upper layer */
	uuid_table.eid = eid;
	memcpy(&uuid_table.uuid.canonical, &uuid_resp->uuid.canonical,
			sizeof(guid_t));
	uuid_table.next = NULL;

	/* Create a new UUID entry and add to list */
	ret = mctp_uuid_entry_add(&uuid_table);
	if (ret < 0) {
		MCTP_CTRL_ERR("%s: Failed to update global UUID table..\n",
				__func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Messgae types */
mctp_ret_codes_t mctp_i2c_get_msg_type_request(int sock_fd, mctp_eid_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_msg_type_support msg_type_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;

	/* Set destination EID */
	dest_eid = eid;

	/* Set Bind ID as SMBus */
	bind_id = MCTP_BINDING_SMBUS;

	/* Set private binding */
	pvt_binding.i2c_bus = g_i2c_bus;
	pvt_binding.dest_slave_addr = g_i2c_dest_slave_addr;
	pvt_binding.src_slave_addr = g_i2c_src_slave_addr;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_msg_type_support(&msg_type_req);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_msg_type_support) -
			sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &msg_type_req,
			sizeof(struct mctp_ctrl_cmd_get_msg_type_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_MSG_TYPE_REQUEST", msg_len);

	/* Send the request message over socket */
	MCTP_CTRL_TRACE("%s: Sending EP request\n", __func__);
	mctp_ret = mctp_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_msg_type_support), &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get Messgae types */
int mctp_i2c_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
					size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_msg_type_support *msg_type_resp;
	int ret;
	mctp_msg_type_table_t msg_type_table;

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
				"MCTP_GET_MSG_TYPE_RESPONSE",
				resp_msg_len -
					sizeof(struct mctp_ctrl_cmd_msg_hdr));

	msg_type_resp =
		(struct mctp_ctrl_resp_get_msg_type_support *)mctp_resp_msg;

	/* Parse the Get message type buffer */
	req_ret = mctp_decode_ctrl_cmd_get_msg_type_support(msg_type_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_CTRL_DEBUG("%s: EID: %d, Number of supported message types %d\n",
			__func__, eid,
			((struct mctp_ctrl_resp *)mctp_resp_msg)->data[0]);

	/* Update Message type private params to export to upper layer */
	msg_type_table.eid = eid;
	msg_type_table.data_len = ((struct mctp_ctrl_resp *)mctp_resp_msg)
						->data[MCTP_MSG_TYPE_DATA_LEN_OFFSET];
	msg_type_table.next = NULL;
	memcpy(&msg_type_table.data,
			&((struct mctp_ctrl_resp *)mctp_resp_msg)
			->data[MCTP_MSG_TYPE_DATA_OFFSET],
			msg_type_table.data_len);

	/* Create a new Msg type entry and add to list */
	ret = mctp_msg_type_entry_add(&msg_type_table);
	if (ret < 0) {
		MCTP_CTRL_ERR("%s: Failed to update global routing table..\n",
				__func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* MCTP discovery response receive routine */
static mctp_ret_codes_t mctp_discover_response(mctp_discovery_mode mode,
			mctp_eid_t eid, int sock, uint8_t **mctp_resp_msg,
			size_t *mctp_resp_len)
{
	mctp_requester_rc_t mctp_ret;

	/* Ignore request commands */
	switch (mode)
	{
		case MCTP_SET_EP_REQUEST:
		case MCTP_ALLOCATE_EP_ID_REQUEST:
		case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:
		case MCTP_GET_EP_UUID_REQUEST:
		case MCTP_GET_MSG_TYPE_REQUEST:
			return MCTP_RET_REQUEST_SUCCESS;

		default:
			break;
	}

	switch (mode)
	{
		case MCTP_SET_EP_RESPONSE:
		case MCTP_ALLOCATE_EP_ID_RESPONSE:
		case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:
		case MCTP_GET_EP_UUID_RESPONSE:
		case MCTP_GET_MSG_TYPE_RESPONSE:

			/* Receive MCTP packets */
			mctp_ret = mctp_client_recv(eid, sock, mctp_resp_msg, mctp_resp_len);
			if (mctp_ret != MCTP_REQUESTER_SUCCESS)
			{
				MCTP_CTRL_ERR("%s: Failed to received message %d\n", __func__, mctp_ret);
				return MCTP_RET_REQUEST_FAILED;
			}

			break;

		default:
			MCTP_CTRL_DEBUG("%s: Unknown discovery mode: %d\n", __func__, mode);
			break;
	}


	return MCTP_RET_REQUEST_SUCCESS;
}

/* Routine to Discover the endpoint devices */
mctp_ret_codes_t mctp_i2c_discover_endpoints(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_SET_EP_REQUEST;
	mctp_ret_codes_t mctp_ret;
	mctp_ctrl_cmd_set_eid_op set_eid_op;
	mctp_ctrl_cmd_alloc_eid_op alloc_eid_op;
	uint8_t eid = 0, eid_count = 0, eid_start = 0;
	uint8_t entry_hdl = MCTP_ROUTING_ENTRY_START;
	uint8_t *mctp_resp_msg;
	mctp_eid_t local_eid = 11;      //8 - Host BMC-FPGA via PCIe | 10 - Host BMC-FPGA via i2c | 9 - HMC-FPGA via PCIe | 11 - HMC-i2c via i2c (MCTP Arch. & Desi. Spec. page 6)
	size_t resp_msg_len; 
	int timeout = 0;
	mctp_routing_table_t *routing_entry = NULL;

	/* Update the EID lists */
	g_i2c_own_eid = cmd->i2c.own_eid;
	g_i2c_bridge_eid = cmd->i2c.bridge_eid;
	g_i2c_bridge_pool_start = cmd->i2c.bridge_pool_start;

	MCTP_CTRL_INFO(
		"%s: i2c_own_eid: %d, i2c_bridge_eid: %d, i2c_bridge_pool_start: %d\n",
		__func__, g_i2c_own_eid, g_i2c_bridge_eid,
		g_i2c_bridge_pool_start);

	do {
		/* Wait for MCTP response */
		mctp_ret = mctp_discover_response(discovery_mode, local_eid,
						ctrl->sock, &mctp_resp_msg,
						&resp_msg_len);
		if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed to received message %d\n",
					__func__, mctp_ret);

			/*
			 * Dont return failure for Get EP UUID and Messgae types as it need to
			 * fetch the next data from the routing table entries.
			 * NOTE: In general it's very unlikely we hit this scenario. If such
			 * failure occurs, then it could be either a firmware issue or
			 * some Hardware issue.
			 */

			if ((discovery_mode != MCTP_GET_EP_UUID_RESPONSE) &&
				(discovery_mode != MCTP_GET_MSG_TYPE_RESPONSE)) {
				MCTP_CTRL_ERR(
					"%s: Unexpected failure %d, mode[%d]\n",
					__func__, mctp_ret, discovery_mode);
				return MCTP_RET_DISCOVERY_FAILED;
			}
		}
	   
		switch(discovery_mode) {

			case MCTP_SET_EP_REQUEST:

				/* Update the EID operation and EID number */
				set_eid_op = set_eid;
				eid = g_i2c_bridge_eid;

				/* Send the MCTP_SET_EP_REQUEST */
				mctp_ret = mctp_i2c_set_eid_send_request(ctrl->sock, set_eid_op, eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR("%s: Failed MCTP_I2C_SET_EP_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_SET_EP_RESPONSE;

				break;

			case MCTP_SET_EP_RESPONSE:
				/* Process the MCTP_SET_EP_RESPONSE */
				mctp_ret = mctp_i2c_set_eid_get_response(mctp_resp_msg, resp_msg_len,
							g_i2c_bridge_eid, &eid_count);
				/* Free Rx packet */
				free(mctp_resp_msg);

				/* Retry if the device is not ready */
				if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
					/* Make sure it's not timedout before continuing */
					if (timeout < MCTP_DEVICE_SET_EID_TIMEOUT) {
						/* Increment the timeout */
						timeout += MCTP_DEVICE_READY_DELAY;

						/* Set the discover mode as MCTP_SET_EP_REQUEST */
						discovery_mode = MCTP_SET_EP_REQUEST;

						/* Sleep for a while */
						sleep(MCTP_DEVICE_READY_DELAY);
						break;
					}

					MCTP_CTRL_ERR(
						"%s: Timedout[%d] MCTP_EP_DISCOVERY_RESPONSE\n",
						__func__, timeout);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Reset the timeout */
				timeout = 0;

				/* Next step is to Allocate endpoint IDs request */
				discovery_mode = MCTP_ALLOCATE_EP_ID_REQUEST;

				break;

			case MCTP_ALLOCATE_EP_ID_REQUEST:

				/* Update the Allocate EIDs operation, number of EIDs, Starting EID */
				eid = g_i2c_bridge_eid;
				alloc_eid_op = alloc_req_eid;

				/* Set the start of EID */
				eid_start = g_i2c_bridge_pool_start;

				/* Send the MCTP_ALLOCATE_EP_ID_REQUEST */
				mctp_ret = mctp_i2c_alloc_eid_send_request(
						ctrl->sock, eid,
						(mctp_ctrl_cmd_set_eid_op)alloc_eid_op,
						eid_count,
						eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_SET_EP_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_ALLOCATE_EP_ID_RESPONSE;

				break;

			case MCTP_ALLOCATE_EP_ID_RESPONSE:

				/* Process the MCTP_ALLOCATE_EP_ID_RESPONSE */
				mctp_ret = mctp_i2c_alloc_eid_get_response(mctp_resp_msg,
									resp_msg_len);

				/* Free Rx packet */
				free(mctp_resp_msg);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_ALLOCATE_EP_ID_RESPONSE\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Next step is to get UUID request */
				discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

				/*
					* Sleep for a while, since the device need to allocate EIDs
					* to downstream devices
					*/
				MCTP_CTRL_DEBUG(
					"%s: MCTP_ALLOCATE_EP_ID_RESPONSE (sleep %d secs)\n",
					__func__, MCTP_DEVICE_GET_ROUTING_DELAY);

				/*
					* Sleep for a while (this is needed for Bridge to prepare the
					* Routing table entries)
					*/
				sleep(MCTP_DEVICE_GET_ROUTING_DELAY);

				break;

			case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

				/* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
				mctp_ret = mctp_i2c_get_routing_table_send_request(
					ctrl->sock, eid, entry_hdl);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

			/* Wait for the endpoint response */
			discovery_mode =
				MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;

			break;

		case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:

			/* Process the MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE */
			mctp_ret = mctp_i2c_get_routing_table_get_response(
				ctrl->sock, eid, mctp_resp_msg, resp_msg_len);

			/* Free Rx packet */
			free(mctp_resp_msg);

			/* Retry if the device is not ready */
			if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
				/* Make sure it's not timedout before continuing */
				if (timeout < MCTP_DEVICE_GET_ROUTING_TIMEOUT) {
					/* Increment the timeout */
					timeout += MCTP_DEVICE_READY_DELAY;

					/* Set the discover mode as MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
					discovery_mode =
						MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

					/* Sleep for a while */
					sleep(MCTP_DEVICE_READY_DELAY);
					break;
				}

				MCTP_CTRL_ERR(
					"%s: Timedout[%d secs]  MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n",
					__func__, timeout);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Reset the timeout */
			timeout = 0;

			if (MCTP_RET_DISCOVERY_FAILED == mctp_ret) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n",
					__func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Check if next routing entry found and set discovery mode accordingly */
			if (MCTP_RET_ROUTING_TABLE_FOUND == mctp_ret) {
				MCTP_CTRL_DEBUG("%s: Next entry found..\n",
						__func__);
				discovery_mode =
					MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
				break;
			}

			/* Get the start of Routing entry */
			routing_entry = g_routing_table_entries;

			/* Next step is to Get Endpoint UUID request */
			discovery_mode = MCTP_GET_EP_UUID_REQUEST;

			break;

			case MCTP_GET_EP_UUID_REQUEST:

			/* Send the MCTP_GET_EP_UUID_REQUEST */
			if (routing_entry) {
				/* Set the Start of EID */
				eid_start = routing_entry->routing_table
							.starting_eid;

				MCTP_CTRL_DEBUG(
					"%s: Send UUID Request for EID: 0x%x\n",
					__func__, eid_start);

				mctp_ret = mctp_i2c_get_endpoint_uuid_send_request(
					ctrl->sock, eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_EP_UUID_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

			break;

		case MCTP_GET_EP_UUID_RESPONSE:

			if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
				MCTP_CTRL_ERR(
					"%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_GET_EP_UUID_RESPONSE */
				mctp_ret = mctp_i2c_get_endpoint_uuid_response(
					eid_start, mctp_resp_msg, resp_msg_len);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_EP_UUID_RESPONSE Failed\n",
						__func__);
				}
				/* Free Rx packet */
				free(mctp_resp_msg);
			}

			/* Increment the routing entry */
			if (routing_entry) {
				routing_entry = routing_entry->next;
			}

			/* Continue probing all UUID requests */
			if (routing_entry) {
				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_EP_UUID_REQUEST;
				break;
			}

			/* Get the start of Routing entry */
			routing_entry = g_routing_table_entries;

			discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;

			break;

		case MCTP_GET_MSG_TYPE_REQUEST:

			/* Send the MCTP_GET_EP_UUID_REQUEST */
			if (routing_entry) {
				/* Set the Start of EID */
				eid_start = routing_entry->routing_table
							.starting_eid;

				MCTP_CTRL_DEBUG(
					"%s: Send Get Msg type Request for EID: 0x%x\n",
					__func__, eid_start);

				mctp_ret = mctp_i2c_get_msg_type_request(ctrl->sock,
									 eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

			break;

		case MCTP_GET_MSG_TYPE_RESPONSE:

			if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
				MCTP_CTRL_ERR(
					"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
				mctp_ret = mctp_i2c_get_msg_type_response(
					eid_start, mctp_resp_msg, resp_msg_len);

				/* Free Rx packet */
				free(mctp_resp_msg);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n",
						__func__);
				}
			}

			/* Increment the routing entry */
			if (routing_entry) {
				routing_entry = routing_entry->next;
			}

			/* Continue probing all Msg type requests */
			if (routing_entry) {
				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
				break;
			}

			/* Finally update the global mctp_discovered_endpoints */
			MCTP_CTRL_DEBUG("%s: Completed discovery process..\n",
					__func__);
			discovery_mode = MCTP_FINISH_DISCOVERY;

			break;

			default:
				break;
		}

	} while (discovery_mode != MCTP_FINISH_DISCOVERY);

	/* Display all Routing table details */
	MCTP_CTRL_DEBUG("%s: Obtained Routing table entries\n", __func__);
	mctp_routing_entry_display();
 
	/* Display all UUID details */
	MCTP_CTRL_DEBUG("%s: Obtained UUID entries\n", __func__);
	mctp_uuid_display();

	/* Display all message type details */
	MCTP_CTRL_DEBUG("%s: Obtained Message type entries\n", __func__);
	mctp_msg_types_display();

	return MCTP_RET_DISCOVERY_SUCCESS;
}

/* Routine to Discover the endpoint devices */
mctp_ret_codes_t mctp_i2c_discover_static_pool_endpoint(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_SET_EP_REQUEST;
	mctp_ret_codes_t mctp_ret;
	mctp_ctrl_cmd_set_eid_op set_eid_op;
	uint8_t eid = 0, eid_count = 0;
	uint8_t *mctp_resp_msg;
	size_t resp_msg_len;
	int timeout = 0;
	uint8_t number_of_eid = 0;

	do {
		/* Wait for MCTP response */
		mctp_ret = mctp_discover_response(discovery_mode, cmd->i2c.own_eid,
						ctrl->sock, &mctp_resp_msg,
						&resp_msg_len);
		if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed to received message %d\n",
					__func__, mctp_ret);

			/* Try to repeat discovery for next endpoint from pool */
			if (cmd->dest_eid_tab_len > 1) {
				MCTP_CTRL_DEBUG("%s: Endpoint from pool doesn't response.\n", __func__);
				number_of_eid++;
				// Do procedure again if next EID is available
				if (number_of_eid < cmd->dest_eid_tab_len) {
					MCTP_CTRL_DEBUG("%s: Set EID for next endpoint from pool.\n", __func__);
					discovery_mode = MCTP_SET_EP_REQUEST;
				} else {
					MCTP_CTRL_DEBUG("%s: End of pool.\n", __func__);
					discovery_mode = MCTP_FINISH_DISCOVERY;
					break;
				}
			} else {
				if ((discovery_mode != MCTP_GET_EP_UUID_RESPONSE) &&
				    (discovery_mode != MCTP_GET_MSG_TYPE_RESPONSE)) {
					MCTP_CTRL_ERR(
						"%s: Unexpected failure %d, mode[%d]\n",
						__func__, mctp_ret, discovery_mode);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}
		}

		switch(discovery_mode) {

			case MCTP_SET_EP_REQUEST:
				/* Update the EID operation and EID number */
				set_eid_op = set_eid;
				eid = cmd->dest_eid_tab[number_of_eid];

				/* Send the MCTP_SET_EP_REQUEST */
				mctp_ret = mctp_i2c_set_eid_send_request(ctrl->sock, set_eid_op, eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR("%s: Failed MCTP_I2C_SET_EP_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_SET_EP_RESPONSE;

				break;

			case MCTP_SET_EP_RESPONSE:
				/* Process the MCTP_SET_EP_RESPONSE */
				mctp_ret = mctp_i2c_set_eid_get_response(mctp_resp_msg, resp_msg_len,
													eid, &eid_count);
				/* Free Rx packet */
				free(mctp_resp_msg);

				/* Retry if the device is not ready */
				if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
					/* Make sure it's not timedout before continuing */
					if (timeout < MCTP_DEVICE_SET_EID_TIMEOUT) {
						/* Increment the timeout */
						timeout += MCTP_DEVICE_READY_DELAY;

						/* Set the discover mode as MCTP_SET_EP_REQUEST */
						discovery_mode = MCTP_SET_EP_REQUEST;

						/* Sleep for a while */
						sleep(MCTP_DEVICE_READY_DELAY);
						break;
					}

					MCTP_CTRL_ERR(
						"%s: Timedout[%d] MCTP_EP_DISCOVERY_RESPONSE\n",
						__func__, timeout);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Reset the timeout */
				timeout = 0;

				discovery_mode = MCTP_GET_EP_UUID_REQUEST;

				break;

			case MCTP_GET_EP_UUID_REQUEST:
				/* Send the MCTP_GET_EP_UUID_REQUEST */

				MCTP_CTRL_DEBUG(
					"%s: Send UUID Request for EID: 0x%x\n",
					__func__, cmd->dest_eid_tab[number_of_eid]);

				mctp_ret = mctp_i2c_get_endpoint_uuid_send_request(
					ctrl->sock, cmd->dest_eid_tab[number_of_eid]);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_EP_UUID_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

				break;

			case MCTP_GET_EP_UUID_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n",
						__func__, cmd->dest_eid_tab[number_of_eid]);
				} else {
					/* Process the MCTP_GET_EP_UUID_RESPONSE */
					mctp_ret = mctp_i2c_get_endpoint_uuid_response(
						cmd->dest_eid_tab[number_of_eid], mctp_resp_msg, resp_msg_len);

					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_CTRL_ERR(
							"%s: MCTP_GET_EP_UUID_RESPONSE Failed\n",
							__func__);
					}
					/* Free Rx packet */
					free(mctp_resp_msg);
				}

				discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;

				break;

			case MCTP_GET_MSG_TYPE_REQUEST:

					MCTP_CTRL_DEBUG(
						"%s: Send Get Msg type Request for EID: 0x%x\n",
						__func__, cmd->dest_eid_tab[number_of_eid]);

					mctp_ret = mctp_i2c_get_msg_type_request(ctrl->sock,
								cmd->dest_eid_tab[number_of_eid]);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_CTRL_ERR(
							"%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n",
							__func__);
						return MCTP_RET_DISCOVERY_FAILED;
					}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

				break;

			case MCTP_GET_MSG_TYPE_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n",
						__func__, cmd->dest_eid_tab[number_of_eid]);
				} else {
					/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
					mctp_ret = mctp_i2c_get_msg_type_response(
						cmd->dest_eid_tab[number_of_eid], mctp_resp_msg, resp_msg_len);

					/* Free Rx packet */
					free(mctp_resp_msg);

					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_CTRL_ERR(
							"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n",
							__func__);
					}
				}

				/* Do procedure again if next EID is available */
				number_of_eid++;
				if (number_of_eid < cmd->dest_eid_tab_len) {
					MCTP_CTRL_DEBUG("%s: Set EID for next endpoint from pool.\n", __func__);
					discovery_mode = MCTP_SET_EP_REQUEST;
					break;
				}

				/* Finally update the global mctp_discovered_endpoints */
				MCTP_CTRL_DEBUG("%s: Completed discovery process..\n",
						__func__);
				discovery_mode = MCTP_FINISH_DISCOVERY;

				break;

			default:
				MCTP_CTRL_ERR("%s: Wrong discovery mode %d \n",
					      __func__, discovery_mode);
				// assert(0);
				break;
		}

	} while (discovery_mode != MCTP_FINISH_DISCOVERY);

	/* Display all UUID details */
	MCTP_CTRL_DEBUG("%s: Obtained UUID entries\n", __func__);
	mctp_uuid_display();

	/* Display all message type details */
	MCTP_CTRL_DEBUG("%s: Obtained Message type entries\n", __func__);
	mctp_msg_types_display();

	return MCTP_RET_DISCOVERY_SUCCESS;
}
