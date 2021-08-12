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
#include "libmctp-astpcie.h"
#include "mctp-encode.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-discovery.h"
#include "mctp-ctrl.h"
#include "mctp-ctrl-log.h"

static int mctp_discovered_endpoints = 0;
static int mctp_discovered_mode = 0;
static int mctp_routing_table_available = 0;
static int mctp_ep_uuids_available = 0;

/* Global defenitions */
int g_socket_fd = 0;
uint8_t g_eid_pool_size = 0;
mctp_routing_table_t    *g_routing_table_entries = NULL;
int                     g_routing_table_length = 0;

mctp_msg_type_table_t   *g_msg_type_entries = NULL;
int                     g_msg_type_table_len = 0;

mctp_uuid_table_t       *g_uuid_entries = NULL;
int                     g_uuid_table_len = 0;

const uint8_t MCTP_ROUTING_ENTRY_START = 0;
const uint8_t MCTP_FPGA_EID = 0x10;
const uint8_t MCTP_FPGA_EID_POOL[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20};
static int g_target_bdf = 0;

mctp_discovery_message_table_t	msg_tbl[] = {
	{MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST,     "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST"},
	{MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE,    "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE"},
	{MCTP_EP_DISCOVERY_REQUEST, 		        "MCTP_EP_DISCOVERY_REQUEST"},
	{MCTP_EP_DISCOVERY_RESPONSE, 		        "MCTP_EP_DISCOVERY_RESPONSE"},
	{MCTP_SET_EP_REQUEST, 			            "MCTP_SET_EP_REQUEST"},
	{MCTP_SET_EP_RESPONSE, 			            "MCTP_SET_EP_RESPONSE"},
	{MCTP_ALLOCATE_EP_ID_REQUEST, 		        "MCTP_ALLOCATE_EP_ID_REQUEST"},
	{MCTP_ALLOCATE_EP_ID_RESPONSE, 		        "MCTP_ALLOCATE_EP_ID_RESPONSE"},
	{MCTP_GET_MSG_TYPE_REQUEST, 			    "MCTP_GET_MSG_TYPE_REQUEST"},
	{MCTP_GET_MSG_TYPE_RESPONSE, 			    "MCTP_GET_MSG_TYPE_RESPONSE"},
};

/* Helper function to print respons messages */
static void mctp_print_resp_msg(struct mctp_ctrl_resp *ep_discovery_resp, const char *msg, int msg_len)
{

	printf("\n-----------------------------------------------\n");

	/* Print only if message exist */
	if (msg) {
		printf("   %s\n", msg);
		printf("-----------------------------------------------\n");
	}

	printf("MCTP-RESP-HDR >> \n");
	printf("\tmsg_type \t: 0x%x\n", ep_discovery_resp->hdr.ic_msg_type);
	printf("\trq_dgram_inst \t: 0x%x\n", ep_discovery_resp->hdr.rq_dgram_inst);
	printf("\tcommand_code \t: 0x%x\n", ep_discovery_resp->hdr.command_code);

	/* Print the compeltion code */
	if (msg_len >= 1)
		printf("\tcomp_code \t: 0x%x (%s)\n", ep_discovery_resp->completion_code,
		(ep_discovery_resp->completion_code == MCTP_CTRL_CC_SUCCESS)? "SUCCESS":"FAILURE");

	/* Decrement the length by one */
	msg_len--;

	if (ep_discovery_resp->data) {

		printf("MCTP-RESP-DATA >> \n");

		/* Check if data available or not */
		if (msg_len <= 0) {
			printf("\t--------------<empty>-------------\n");
		}

		for (int i = 0; i < msg_len; i++)
			printf("\tDATA[%d] \t\t: 0x%x\n", i, ep_discovery_resp->data[i]);
		printf("\n-----------------------------------------------\n");
	}
}


/* Helper function to print request messages */
static void mctp_print_req_msg(struct mctp_ctrl_req *ep_discovery_req, const char *msg, size_t msg_len)
{

	printf("\n-----------------------------------------------\n");

	/* Print only if message exist */
	if (msg) {
		printf("   %s\n", msg);
		printf("-----------------------------------------------\n");
	}

	printf("MCTP-REQ-HDR >> \n");
	printf("\tmsg_type \t: 0x%x\n", ep_discovery_req->hdr.ic_msg_type);
	printf("\trq_dgram_inst \t: 0x%x\n", ep_discovery_req->hdr.rq_dgram_inst);
	printf("\tcommand_code \t: 0x%x\n", ep_discovery_req->hdr.command_code);

	if (ep_discovery_req->data) {

		printf("MCTP-REQ-DATA >> \n");

		/* Check if data available or not */
		if (msg_len <= 0) {
			printf("\t--------------<empty>-------------\n");
		}

		for (int i = 0; i < msg_len; i++)
			printf("\tDATA[%d] \t\t: 0x%x\n", i, ep_discovery_req->data[i]);
		printf("\n-----------------------------------------------\n");
	}
}

static void mctp_print_routing_table_entry (int routing_id, struct get_routing_table_entry *routing_table)
{
	printf("\n-----------------------------------------------\n");
	printf("MCTP-ROUTING-TABLE-ENTRY [%d]\n", routing_id);

	/* Print only if message exist */
	if (routing_table) {
		printf("-----------------------------------------------\n");

		printf("\t\teid_range_size            :  0x%x\n", routing_table->eid_range_size);
		printf("\t\tstarting_eid              :  0x%x\n", routing_table->starting_eid);
		printf("\t\tentry_type                :  0x%x\n", routing_table->entry_type);
		printf("\t\tphys_transport_binding_id :  0x%x\n", routing_table->phys_transport_binding_id);
		printf("\t\tphys_media_type_id        :  0x%x\n", routing_table->phys_media_type_id);
		printf("\t\tphys_address_size         :  0x%x\n", routing_table->phys_address_size);
		printf("-----------------------------------------------\n");
	} else {
		printf("-----------------< empty/invalid >------------------\n");
	}
}

static void mctp_print_msg_types_table_entry (mctp_msg_type_table_t *msg_type_table)
{
	printf("\n-----------------------------------------------\n");
	printf("MCTP-MSG-TYPE-TABLE-ENTRY\n");

	/* Print only if message exist */
	if (msg_type_table) {
		printf("-----------------------------------------------\n");

		printf("\t\tEID                       :  0x%x\n", msg_type_table->eid);
		printf("\t\tNumber of supported types :  0x%x\n", msg_type_table->data_len);
		printf("\t\tSupported Types           :  ");
        for (int i=0; i < msg_type_table->data_len; i++) {
		    printf("0x%x  ", msg_type_table->data[i]);
        }
		printf("\n-----------------------------------------------\n");
	} else {
		printf("-----------------< empty/invalid >------------------\n");
	}
}

static void mctp_print_uuid_table_entry (mctp_uuid_table_t *uuid_tbl)
{
    printf("\n-----------------------------------------------\n");
    printf("MCTP-UUID-ENTRY-FOR-EID                 :  0x%x\n", uuid_tbl->eid);

    /* Print only if message exist */
    if (uuid_tbl) {
        printf("-----------------------------------------------\n");

        printf("\t\tEID                             :  0x%x\n", uuid_tbl->eid);
        printf("\t\tUUID:(time-low)                 :  0x%x\n", uuid_tbl->uuid.canonical.data0);
        printf("\t\tUUID:(time-mid)                 :  0x%x\n", uuid_tbl->uuid.canonical.data1);
        printf("\t\tUUID:(time-high and version)    :  0x%x\n", uuid_tbl->uuid.canonical.data2);
        printf("\t\tUUID:(clk-seq and resvd)        :  0x%x\n", uuid_tbl->uuid.canonical.data3);
        printf("\t\tUUID:(node)                     :  0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",
                                                                uuid_tbl->uuid.canonical.data4[0],
                                                                uuid_tbl->uuid.canonical.data4[1],
                                                                uuid_tbl->uuid.canonical.data4[2],
                                                                uuid_tbl->uuid.canonical.data4[3],
                                                                uuid_tbl->uuid.canonical.data4[4],
                                                                uuid_tbl->uuid.canonical.data4[5]);
    printf("\n-----------------------------------------------\n");
    } else {
        printf("-----------------< empty/invalid >------------------\n");
    }
}


void mctp_routing_entry_display(void)
{
	mctp_routing_table_t *display_entry;

	display_entry = g_routing_table_entries;

	while (display_entry != NULL) {
		mctp_print_routing_table_entry(display_entry->id, &(display_entry->routing_table));
		display_entry = display_entry->next;
	}
}

/* To create a new routing entry and add to global routing table */
int mctp_routing_entry_add(struct get_routing_table_entry *routing_table_entry)
{
	mctp_routing_table_t	*new_entry, *temp_entry;
	static int routing_id = 0;

	printf("VK: %s: Alloc memory and add the routing entry..\n", __func__);

	/* Create a new Routing table entry */
	new_entry = (mctp_routing_table_t *) malloc(sizeof(mctp_routing_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the contents */
	memcpy(&new_entry->routing_table, routing_table_entry, sizeof(struct get_routing_table_entry));

	/* Check if any entry exist */
	if (g_routing_table_entries == NULL) {
		printf("VK: %s: Adding first entry..\n", __func__);
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
	while (temp_entry->next != NULL)
		temp_entry = temp_entry->next;

	/* Add at the last */
	temp_entry->next = new_entry;
	new_entry->next = NULL;

	/* Update the routing ID */
	new_entry->id = routing_id++;

	/* Increment the global counter */
	printf("VK: %s: Incrementing global counter\n", __func__);
	g_routing_table_length++;

	return 0;
}

/* To delete all the entris in global routing table */
int mctp_routing_entry_delete_all(void)
{
	mctp_routing_table_t    *del_entry;
	printf("VK: %s: Deleting all routing entries..\n", __func__);

	// Check if entry exist
	while (g_routing_table_entries != NULL) {
		del_entry = g_routing_table_entries;
		g_routing_table_entries = del_entry->next;

		// free memory
		free(del_entry);
	}

	return 0;
}

void mctp_msg_types_display(void)
{
	mctp_msg_type_table_t *display_entry;

	display_entry = g_msg_type_entries;

	while (display_entry != NULL) {
		mctp_print_msg_types_table_entry(display_entry);
		display_entry = display_entry->next;
	}
}


/* To create a new MCTP Message type and add to global message type */
int mctp_msg_type_entry_add(mctp_msg_type_table_t *msg_type_tbl)
{
	mctp_msg_type_table_t	*new_entry, *temp_entry;
	static int routing_id = 0;

	printf("VK: %s: Alloc memory and add the routing entry..\n", __func__);

	/* Create a new Message type entry */
	new_entry = (mctp_msg_type_table_t *) malloc(sizeof(mctp_msg_type_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the Message type contents */
	memcpy(new_entry, msg_type_tbl, sizeof(mctp_msg_type_table_t));

	/* Check if any entry exist */
	if (g_msg_type_entries == NULL) {
		printf("VK: %s: Adding first entry..\n", __func__);
		g_msg_type_entries = new_entry;
		new_entry->next = NULL;

		return 0;
	}

	/* Traverse the message type table */
	temp_entry = g_msg_type_entries;
	while (temp_entry->next != NULL)
		temp_entry = temp_entry->next;

	/* Add at the last */
	temp_entry->next = new_entry;
	new_entry->next = NULL;

	/* Increment the global counter */
	printf("VK: %s: Incrementing global counter\n", __func__);
	g_msg_type_table_len++;

	return 0;
}

/* To delete all the Messgae types information */
int mctp_msg_types_delete_all(void)
{
	mctp_msg_type_table_t    *del_entry;
	printf("VK: %s: Deleting all Message type entries..\n", __func__);

	// Check if entry exist
	while (g_msg_type_entries != NULL) {
		del_entry = g_msg_type_entries;
		g_msg_type_entries = del_entry->next;

		// free memory
		free(del_entry);
	}

	return 0;
}

void mctp_uuid_display(void)
{
	mctp_uuid_table_t *display_entry;

	display_entry = g_uuid_entries;

	while (display_entry != NULL) {
		mctp_print_uuid_table_entry(display_entry);
		display_entry = display_entry->next;
	}
}


/* To create a new MCTP Message type and add to global message type */
int mctp_uuid_entry_add(mctp_uuid_table_t *uuid_tbl)
{
	mctp_uuid_table_t	*new_entry, *temp_entry;
	static int routing_id = 0;

	printf("VK: %s: Alloc memory and add the UUID entry..\n", __func__);

	/* Create a new Message type entry */
	new_entry = (mctp_uuid_table_t *) malloc(sizeof(mctp_uuid_table_t));
	if (new_entry == NULL)
		return -1;

	/* Copy the Message type contents */
	memcpy(new_entry, uuid_tbl, sizeof(mctp_uuid_table_t));

	/* Check if any entry exist */
	if (g_uuid_entries == NULL) {
		printf("VK: %s: Adding first entry..\n", __func__);
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
	printf("VK: %s: Incrementing uuid global counter\n", __func__);
	g_uuid_table_len++;

	return 0;
}

/* To delete all the Messgae types information */
int mctp_uuid_delete_all(void)
{
	mctp_uuid_table_t    *del_entry;
	printf("VK: %s: Cleanup all UUID entries..\n", __func__);

	// Check if entry exist
	while (g_uuid_entries != NULL) {
		del_entry = g_uuid_entries;
		g_uuid_entries = del_entry->next;

		// free memory
		free(del_entry);
	}

	return 0;
}


mctp_ret_codes_t mctp_prepare_ep_discovery_send_request(int sock_fd)
{
	bool req_ret;
	mctp_requester_rc_t	mctp_ret;
	struct mctp_ctrl_cmd_prepare_ep_discovery prep_ep_discovery;
	struct mctp_ctrl_req    ep_discovery_req;
	size_t msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID as broadcast */
    dest_eid = MCTP_EID_BROADCAST;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_BROADCAST_FROM_RC;
    pvt_binding.remote_id = g_target_bdf;

	/* Prepare the endpoint discovery message */
	req_ret = mctp_encode_ctrl_cmd_prepare_ep_discovery(&prep_ep_discovery);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_discovery_req, 0, sizeof(ep_discovery_req));

	/* Copy to Tx packet */
	memcpy(&ep_discovery_req, &prep_ep_discovery,
				sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery));

	mctp_print_req_msg(&ep_discovery_req, "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST", msg_len);

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_discovery_req,
				                sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_prepare_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp   ep_res;
	struct mctp_ctrl_resp_prepare_discovery prep_ep_discovery_resp;
	int msg_len;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&prep_ep_discovery_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_prepare_discovery));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_prepare_discovery) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_prepare_ep_discovery(&prep_ep_discovery_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_ep_discovery_send_request(int sock_fd)
{
	bool req_ret;
	mctp_requester_rc_t	mctp_ret;
	struct mctp_ctrl_cmd_ep_discovery ep_discovery;
	struct mctp_ctrl_req    ep_req;
	size_t msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID as broadcast */
    dest_eid = MCTP_EID_BROADCAST;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_BROADCAST_FROM_RC;
    pvt_binding.remote_id = g_target_bdf;

	/* Prepare the endpoint discovery message */
	req_ret = mctp_encode_ctrl_cmd_ep_discovery(&ep_discovery);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_ep_discovery) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &ep_discovery,
				sizeof(struct mctp_ctrl_cmd_ep_discovery));

	mctp_print_req_msg(&ep_req, "MCTP_EP_DISCOVERY_REQUEST", msg_len);

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_ep_discovery),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp   ep_res;
	struct mctp_ctrl_resp_endpoint_discovery ep_discovery_resp;
	int msg_len;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&ep_discovery_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_endpoint_discovery));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_endpoint_discovery) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_EP_DISCOVERY_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_ep_discovery(&ep_discovery_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_set_eid_send_request(int sock_fd, mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
	bool 				req_ret;
	mctp_requester_rc_t		mctp_ret;
	struct mctp_ctrl_cmd_set_eid 	set_eid_req;
	struct mctp_ctrl_req    	ep_req;
	size_t 				msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID as NULL */
    dest_eid = MCTP_EID_NULL;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

	/* Encode Set Endpoint ID message */
	req_ret = mctp_encode_ctrl_cmd_set_eid(&set_eid_req, op, eid);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_set_eid) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req,
				sizeof(struct mctp_ctrl_cmd_set_eid));

	mctp_print_req_msg(&ep_req, "MCTP_SET_EP_REQUEST", msg_len);

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_set_eid),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));


	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool 				req_ret;
	struct mctp_ctrl_resp   	ep_res;
	struct mctp_ctrl_resp_set_eid 	set_eid_resp;
	int 				msg_len;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&set_eid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_set_eid));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_set_eid) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_SET_EP_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_set_eid(&set_eid_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Allocate EID pools if required */
	/* TBD */
	g_eid_pool_size = set_eid_resp.eid_pool_size;
	printf("VK: %s: g_eid_pool_size: %d\n", __func__, g_eid_pool_size);

	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_alloc_eid_send_request(int sock_fd, mctp_eid_t assigned_eid,
                        mctp_ctrl_cmd_set_eid_op op, uint8_t eid_count, uint8_t eid_start)
{
	bool 				req_ret;
	mctp_requester_rc_t		mctp_ret;
	struct mctp_ctrl_cmd_alloc_eid 	set_eid_req;
	struct mctp_ctrl_req    	ep_req;
	size_t 				msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID as NULL */
    dest_eid = assigned_eid;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

	/* Prepare the endpoint discovery message */
	req_ret = mctp_encode_ctrl_cmd_alloc_eid(&set_eid_req, op, eid_count, eid_start);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_alloc_eid) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req,
				sizeof(struct mctp_ctrl_cmd_alloc_eid));

	mctp_print_req_msg(&ep_req, "MCTP_ALLOCATE_EP_ID_REQUEST", msg_len);

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_alloc_eid),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool 					req_ret;
	struct mctp_ctrl_resp   		ep_res;
	struct mctp_ctrl_resp_alloc_eid 	alloc_eid_resp;
	int 					msg_len;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	printf("VK: %s: sizeof mctp_ctrl_resp_alloc_eid: %ld\n", __func__, sizeof(struct mctp_ctrl_resp_alloc_eid));
	/* Copy the Rx packet header */
	memcpy(&alloc_eid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_alloc_eid));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_alloc_eid) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_ALLOCATE_EP_ID_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_alloc_eid(&alloc_eid_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Allocate EID pools if required */
	/* TBD */
	g_eid_pool_size = alloc_eid_resp.eid_pool_size;
	printf("VK: %s: g_eid_pool_size: %d\n", __func__, g_eid_pool_size);

	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_get_routing_table_send_request(int sock_fd, mctp_eid_t eid,
                                                                uint8_t entry_handle)
{
	bool 					req_ret;
	mctp_requester_rc_t			mctp_ret;
	struct mctp_ctrl_cmd_get_routing_table 	get_routing_req;
	struct mctp_ctrl_req    		ep_req;
	size_t 					msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID as NULL */
    dest_eid = MCTP_EID_NULL;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

	/* Get routing table request message */
	req_ret = mctp_encode_ctrl_cmd_get_routing_table(&get_routing_req, entry_handle);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_routing_table) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &get_routing_req,
				sizeof(struct mctp_ctrl_cmd_get_routing_table));

	mctp_print_req_msg(&ep_req, "MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST", msg_len);

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_get_routing_table),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_get_routing_table_get_response(int sock_fd, mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool 						req_ret;
	struct mctp_ctrl_resp   			ep_res;
	struct mctp_ctrl_resp_get_routing_table 	routing_table;
	int 						msg_len, ret;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&routing_table, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_get_routing_table));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_routing_table) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_get_routing_table(&routing_table);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check if the routing table exist */
	if (routing_table.number_of_entries) {
		struct get_routing_table_entry			routing_table_entry;

		/* Copy the routing table entries to local routing table */
		memcpy(&routing_table_entry, mctp_resp_msg + sizeof(struct mctp_ctrl_resp_get_routing_table),
						sizeof(struct get_routing_table_entry));

		/* Add the entry to a linked list */
		/* TBD */
		ret = mctp_routing_entry_add(&routing_table_entry);
		if (ret < 0) {
			printf("VK: %s: Failed to update global routing table..\n", __func__);
		}

		/* Print the routing table entry */
		mctp_print_routing_table_entry (g_routing_table_entries->id, &routing_table_entry);

		// Length of the Routing table
		printf("VK: %s: Routing table lenght: %d\n", __func__, g_eid_pool_size);

		/* Check if the next routing table exist.. */
		if (routing_table.next_entry_handle != 0xFF) {
			mctp_ret_codes_t mctp_ret;

			printf("VK: %s: Next routing entry found, probe for the next handle: %d\n", __func__, routing_table.next_entry_handle);

			/* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
			printf("VK: %s: MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST -----\n", __func__);
			mctp_ret = mctp_get_routing_table_send_request(sock_fd, eid, routing_table.next_entry_handle);
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				printf("VK: %s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n", __func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			return MCTP_RET_ROUTING_TABLE_FOUND;
		} else {
			printf("VK: %s: Next routing table entry not found, next handle: %d\n", __func__, routing_table.next_entry_handle);
		}
	}

	return MCTP_RET_REQUEST_SUCCESS;
}


mctp_ret_codes_t mctp_get_endpoint_uuid_send_request(int sock_fd, mctp_eid_t eid)
{
	bool 				req_ret;
	mctp_requester_rc_t		mctp_ret;
	struct mctp_ctrl_cmd_get_uuid 	uuid_req;
	struct mctp_ctrl_req    	ep_req;
	size_t 				msg_len;
    mctp_eid_t dest_eid;
    mctp_binding_ids_t bind_id;
    struct mctp_astpcie_pkt_private pvt_binding;

    /* Set destination EID */
    dest_eid = eid;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_uuid(&uuid_req);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_uuid) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &uuid_req,
				sizeof(struct mctp_ctrl_cmd_get_uuid));

	mctp_print_req_msg(&ep_req, "MCTP_GET_EP_UUID_REQUEST", msg_len);

	/* Check whether the eid is valid before sending request */
	//TBD

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_get_uuid),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool 				            req_ret;
	struct mctp_ctrl_resp   	    ep_res;
	struct mctp_ctrl_resp_get_uuid 	uuid_resp;
	int 				            msg_len, ret;
    mctp_uuid_table_t               uuid_table;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&uuid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_get_uuid));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_uuid) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_GET_EP_UUID_RESPONSE", msg_len);

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_get_uuid(&uuid_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

    uuid_table.eid = eid;
    memcpy(&uuid_table.uuid.canonical, &ep_res.data[1], sizeof(guid_t));

    /* Print the routing table entry */
    //mctp_print_uuid_table_entry(&uuid_table);

    /* Add the entry to a linked list */
    ret = mctp_uuid_entry_add(&uuid_table);
    if (ret < 0) {
        printf("VK: %s: Failed to update global UUID table..\n", __func__);
    }
	return MCTP_RET_REQUEST_SUCCESS;
}

mctp_ret_codes_t mctp_get_msg_type_request(int sock_fd, mctp_eid_t eid)
{
	bool 				                        req_ret;
	mctp_requester_rc_t		                    mctp_ret;
	struct mctp_ctrl_cmd_get_msg_type_support 	msg_type_req;
	struct mctp_ctrl_req    	                ep_req;
	size_t 				                        msg_len;
    mctp_eid_t                                  dest_eid;
    mctp_binding_ids_t                          bind_id;
    struct mctp_astpcie_pkt_private             pvt_binding;

    /* Set destination EID */
    dest_eid = eid;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_msg_type_support(&msg_type_req);
	if (req_ret == false) {
		printf("VK: %s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_msg_type_support) -
						sizeof(struct mctp_ctrl_cmd_msg_hdr);

	printf("VK: %s: message length: %ld\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &msg_type_req,
				sizeof(struct mctp_ctrl_cmd_get_msg_type_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_MSG_TYPE_REQUEST", msg_len);

	/* Check whether the eid is valid before sending request */
	//TBD

	/* Send the request message over socket */
	printf("VK: %s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
				                (const uint8_t *) &ep_req,
				                sizeof(struct mctp_ctrl_cmd_get_msg_type_support),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		printf("VK: %s: Failed to send message..\n", __func__);
	}
	printf("VK: %s: Successfully sent message..\n", __func__);

	return MCTP_RET_REQUEST_SUCCESS;
}

int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool 				                        req_ret;
	struct mctp_ctrl_resp   	                ep_res;
	struct mctp_ctrl_resp_get_msg_type_support 	msg_type_resp;
	int 				                        msg_len, ret;
    mctp_msg_type_table_t                       msg_type_table;

	printf("VK: %s: Get EP reesponse\n", __func__);

	/* Validate the packet */
	/* TBD */

	/* Copy the Rx packet header */
	memcpy(&msg_type_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_get_msg_type_support));

	/* Copy the Rx packet header */
	memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_msg_type_support) - sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Get the message length */
	printf("VK: %s: Response resp_msg_len: %ld, msg_len: %d", __func__, resp_msg_len, msg_len);
	mctp_print_resp_msg(&ep_res, "MCTP_GET_MSG_TYPE_RESPONSE", msg_len);

	/* Parse the Get message type buffer */
	req_ret = mctp_decode_ctrl_cmd_get_msg_type_support(&msg_type_resp);
	if (req_ret == false) {
		printf("VK: %s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

    msg_type_table.eid = eid;
    msg_type_table.data_len = ep_res.data[0];
    memcpy(&msg_type_table.data, &ep_res.data[1], msg_type_table.data_len);

	/* Print the routing table entry */
	//mctp_print_msg_types_table_entry(&msg_type_table);

	/* Add the entry to a linked list */
	ret = mctp_msg_type_entry_add(&msg_type_table);
	if (ret < 0) {
		printf("VK: %s: Failed to update global routing table..\n", __func__);
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

static mctp_ret_codes_t mctp_discover_response(mctp_discovery_mode mode,
                                                    mctp_eid_t eid, int sock,
                                                    uint8_t **mctp_resp_msg,
                                                    size_t *mctp_resp_len)
{
	mctp_ret_codes_t		mctp_ret;

    switch (mode) {
        case MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE:
        case MCTP_EP_DISCOVERY_RESPONSE:
        case MCTP_SET_EP_RESPONSE:
        case MCTP_ALLOCATE_EP_ID_RESPONSE:
        case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:
        case MCTP_GET_EP_UUID_RESPONSE:
        case MCTP_GET_MSG_TYPE_RESPONSE:

            /* Receive MCTP packets */
            mctp_ret = mctp_client_recv(eid, sock, mctp_resp_msg, mctp_resp_len);
            if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
                printf("VK: %s: Failed to received message %d\n", __func__, mctp_ret);
                return MCTP_RET_REQUEST_FAILED;
            }

            break;

        default:
            printf("VK: %s: Invalid discovery mode: %d\n", __func__, mode);
            break;
    }


    return MCTP_RET_REQUEST_SUCCESS;
}

/* Discover the endpoint devices */
mctp_ret_codes_t mctp_discover_endpoints(mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
	static int                  discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST;
	struct mctp_ctrl_req    	ep_discovery_req;
	struct mctp_ctrl_resp   	ep_discovery_res;
	mctp_ret_codes_t		    mctp_ret;
	mctp_ctrl_cmd_set_eid_op 	set_eid_op;
	mctp_ctrl_cmd_alloc_eid_op 	alloc_eid_op;
	uint8_t 			        eid, eid_count, eid_start;
	uint8_t				        entry_hdl = MCTP_ROUTING_ENTRY_START;
    size_t                      mctp_resp_len;
    uint8_t                     *mctp_resp_msg;
    mctp_eid_t                  local_eid = 8;
    size_t                      resp_msg_len;
    int                         uuid_req_count = 0;
    int                         msg_type_req_count = 0;

    /* Update Target BDF */
    g_target_bdf = mctp_ctrl_get_target_bdf (cmd);

    do {

        /* Wait for MCTP response */
        mctp_ret = mctp_discover_response (discovery_mode, local_eid,
                                        ctrl->sock, &mctp_resp_msg, &resp_msg_len);
        if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
            printf("VK: %s: Failed to received message %d\n", __func__, mctp_ret);
            break;
        }

        //printf("VK: %s: Successfully received message..\n", __func__);

		switch(discovery_mode) {
			case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:

				/* Send the prepare endpoint discovery message */
				printf("VK: %s: MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST -----\n", __func__);
				mctp_ret = mctp_prepare_ep_discovery_send_request(ctrl->sock);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint discovery response */
				discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE;

				break;

			case MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE:

				/* Process the prepare endpoint discovery message */
				printf("VK: %s: MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE -----\n", __func__);
				mctp_ret = mctp_prepare_ep_discovery_get_response(mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Next step is to send endpoint Discovery request */
				discovery_mode = MCTP_EP_DISCOVERY_REQUEST;

			case MCTP_EP_DISCOVERY_REQUEST:

				/* Send the prepare endpoint message */
				printf("VK: %s: MCTP_EP_DISCOVERY_REQUEST -----\n", __func__);
				mctp_ret = mctp_ep_discovery_send_request(ctrl->sock);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_EP_DISCOVERY_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_EP_DISCOVERY_RESPONSE;

				break;

			case MCTP_EP_DISCOVERY_RESPONSE:

				/* Process the endpoint discovery message */
				printf("VK: %s: MCTP_EP_DISCOVERY_RESPONSE -----\n", __func__);
				mctp_ret = mctp_ep_discovery_get_response(mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_EP_DISCOVERY_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Next step is to set endpoint ID request */
				discovery_mode = MCTP_SET_EP_REQUEST;
                break;

			case MCTP_SET_EP_REQUEST:

				/* Update the EID operation and EID number */
				set_eid_op = set_eid;
				eid = MCTP_FPGA_EID;

				/* Send the MCTP_SET_EP_REQUEST */
				printf("VK: %s: MCTP_SET_EP_REQUEST -----\n", __func__);
				mctp_ret = mctp_set_eid_send_request(ctrl->sock, set_eid_op, eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_SET_EP_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_SET_EP_RESPONSE;

				break;

			case MCTP_SET_EP_RESPONSE:

				/* Process the MCTP_SET_EP_RESPONSE */
				printf("VK: %s: MCTP_EP_DISCOVERY_RESPONSE -----\n", __func__);
				mctp_ret = mctp_set_eid_get_response(mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_EP_DISCOVERY_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Next step is to Allocate endpoint IDs request */
				discovery_mode = MCTP_ALLOCATE_EP_ID_REQUEST;

			case MCTP_ALLOCATE_EP_ID_REQUEST:

				/* Update the Allocate EIDs operation, number of EIDs, Starting EID */
				alloc_eid_op = alloc_eid_op;
				eid_count = sizeof(MCTP_FPGA_EID_POOL);
				eid_start = MCTP_FPGA_EID_POOL[0];

				/* Send the MCTP_ALLOCATE_EP_ID_REQUEST */
				printf("VK: %s: MCTP_SET_EP_REQUEST -----\n", __func__);
				mctp_ret = mctp_alloc_eid_send_request(ctrl->sock, eid,
                                                        alloc_eid_op, eid_count, eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_SET_EP_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_ALLOCATE_EP_ID_RESPONSE;

				break;

			case MCTP_ALLOCATE_EP_ID_RESPONSE:

				/* Process the MCTP_ALLOCATE_EP_ID_RESPONSE */
				printf("VK: %s: MCTP_ALLOCATE_EP_ID_RESPONSE -----\n", __func__);
				mctp_ret = mctp_alloc_eid_get_response(mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_ALLOCATE_EP_ID_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Next step is to get UUID request */
				discovery_mode = MCTP_GET_EP_UUID_REQUEST;
                break;

			case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

				/* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
				printf("VK: %s: MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST -----\n", __func__);
				mctp_ret = mctp_get_routing_table_send_request(ctrl->sock, eid, entry_hdl);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;

				break;

			case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:

				/* Process the MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE */
				printf("VK: %s: MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE -----\n", __func__);
				mctp_ret = mctp_get_routing_table_get_response(ctrl->sock, eid, mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Check if next routing entry found and set discovery mode accordingly */
				if (mctp_ret == MCTP_RET_ROUTING_TABLE_FOUND) {

					printf("VK: %s: Next entry found..\n", __func__);
					discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;
					break;
				}

				printf("VK: %s: print the entire routing table..\n", __func__);
				mctp_routing_entry_display();

				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_EP_UUID_REQUEST;
                break;

			case MCTP_GET_EP_UUID_REQUEST:

				eid_count = sizeof(MCTP_FPGA_EID_POOL);

				/* Send the MCTP_GET_EP_UUID_REQUEST */
				printf("VK: %s: MCTP_GET_EP_UUID_REQUEST -----\n", __func__);
                if (uuid_req_count < eid_count) {
				    eid_start = MCTP_FPGA_EID_POOL[uuid_req_count];
					mctp_ret = mctp_get_endpoint_uuid_send_request(ctrl->sock, eid_start);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						printf("VK: %s: Failed MCTP_GET_EP_UUID_REQUEST\n", __func__);
						return MCTP_RET_DISCOVERY_FAILED;
					}

                    /* Increment the UUID request count */
                    uuid_req_count++;
                }

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

				break;

			case MCTP_GET_EP_UUID_RESPONSE:

				/* Process the MCTP_GET_EP_UUID_RESPONSE */
				printf("VK: %s: MCTP_GET_EP_UUID_RESPONSE -----\n", __func__);
				mctp_ret = mctp_get_endpoint_uuid_response(eid_start, mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: MCTP_GET_EP_UUID_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

                /* Continue probing all UUID requests */
                if (uuid_req_count < eid_count) {
					printf("VK: %s: MCTP_GET_EP_UUID_RESPONSE: Probe for eid: %d\n",
                                                        __func__, MCTP_FPGA_EID_POOL[uuid_req_count]);
				    /* Next step is to Get Endpoint UUID request */
				    discovery_mode = MCTP_GET_EP_UUID_REQUEST;
                    break;
                }

				discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;

				break;


            case MCTP_GET_MSG_TYPE_REQUEST:

				/* Send the MCTP_GET_MSG_TYPE_REQUEST */
				printf("VK: %s: MCTP_GET_MSG_TYPE_REQUEST -----\n", __func__);
                if (msg_type_req_count < eid_count) {
				    eid_start = MCTP_FPGA_EID_POOL[msg_type_req_count];
					mctp_ret = mctp_get_msg_type_request(ctrl->sock, eid_start);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						printf("VK: %s: Failed MCTP_GET_MSG_TYPE_REQUEST\n", __func__);
						return MCTP_RET_DISCOVERY_FAILED;
					}

                    /* Increment the Msg type request count */
                    msg_type_req_count++;
                }

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

                break;

            case MCTP_GET_MSG_TYPE_RESPONSE:

				/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
				printf("VK: %s: MCTP_GET_MSG_TYPE_RESPONSE -----\n", __func__);
				mctp_ret = mctp_get_msg_type_response(eid_start, mctp_resp_msg, resp_msg_len);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					printf("VK: %s: MCTP_GET_MSG_TYPE_RESPONSE\n", __func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

                /* Continue probing for all EID's */
                if (msg_type_req_count < eid_count) {
					printf("VK: %s: MCTP_GET_MSG_TYPE_RESPONSE: Probe for eid: %d\n",
                                                        __func__, MCTP_FPGA_EID_POOL[msg_type_req_count]);
				    /* Next step is to Get Endpoint UUID request */
				    discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
                    break;
                }

				/* Finally update the global mctp_discovered_endpoints */
				printf("VK: %s: Completed discovery process..\n", __func__);
				discovery_mode = MCTP_FINISH_DISCOVERY;

                break;

			default:
				break;
		}

    } while (discovery_mode != MCTP_FINISH_DISCOVERY);

    /* Display all UUID details */
    mctp_uuid_display();
    mctp_uuid_delete_all();

    /* Display all message type details */
    mctp_msg_types_display();
    mctp_msg_types_delete_all();

	return MCTP_RET_DISCOVERY_SUCCESS;
}
