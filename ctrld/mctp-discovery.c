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

/* Global variable for MCTP discovery mode */
static int              mctp_discovered_endpoints = 0;
static int              mctp_discovered_mode = 0;

/* Structure for Getting MCTP response */
struct mctp_ctrl_resp {
        struct mctp_ctrl_cmd_msg_hdr hdr;
        uint8_t completion_code;
        uint8_t data[MCTP_BTU];
} resp;

/*
 * Global variable for user to check the Routing table 
 * and UUI availablity
 */
static int              mctp_routing_table_available = 0;
static int              mctp_ep_uuids_available = 0;

/* Global EID pool size and start position */
uint8_t                 g_eid_pool_size = 0;
uint8_t                 g_eid_pool_start = 0;

/* Global pointer for Routing table and its length */
mctp_routing_table_t    *g_routing_table_entries = NULL;
int                     g_routing_table_length = 0;

/* Global pointer for Message types and its length */
mctp_msg_type_table_t   *g_msg_type_entries = NULL;
int                     g_msg_type_table_len = 0;

/* Global pointer for UUID and its length */
mctp_uuid_table_t       *g_uuid_entries = NULL;
int                     g_uuid_table_len = 0;

/* Start point of Routing entry */
const uint8_t           MCTP_ROUTING_ENTRY_START = 0;

/* EID of the Endpoint to set */
const uint8_t           MCTP_FPGA_EID = 0xEE;

/* Default EID pools */
const uint8_t           MCTP_FPGA_EID_POOL[] = {
                                                0x20, 0x21, 0x22, 0x23,
                                                0x24, 0x25, 0x26, 0x27,
                                                0x28, 0x29, 0x2A, 0x2B,
                                                0x2C, 0x2D, 0x2E, 0x2F,
                                                0x30, 0x31, 0x32, 0x33,
                                                0x34, 0x35, 0x36, 0x37,
                                                0x38, 0x39, 0x3A, 0x3B,
                                                0x3C, 0x3D, 0x3E, 0x3F,
                                                };

/* PCIe target bdf */
static int              g_target_bdf = 0;

/* Map for Tracing ID and the message */
mctp_discovery_message_table_t  msg_tbl[] = {
    {MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST,     "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST"},
    {MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE,    "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE"},
    {MCTP_EP_DISCOVERY_REQUEST,                 "MCTP_EP_DISCOVERY_REQUEST"},
    {MCTP_EP_DISCOVERY_RESPONSE,                "MCTP_EP_DISCOVERY_RESPONSE"},
    {MCTP_SET_EP_REQUEST,                       "MCTP_SET_EP_REQUEST"},
    {MCTP_SET_EP_RESPONSE,                      "MCTP_SET_EP_RESPONSE"},
    {MCTP_ALLOCATE_EP_ID_REQUEST,               "MCTP_ALLOCATE_EP_ID_REQUEST"},
    {MCTP_ALLOCATE_EP_ID_RESPONSE,              "MCTP_ALLOCATE_EP_ID_RESPONSE"},
    {MCTP_GET_MSG_TYPE_REQUEST,                 "MCTP_GET_MSG_TYPE_REQUEST"},
    {MCTP_GET_MSG_TYPE_RESPONSE,                "MCTP_GET_MSG_TYPE_RESPONSE"},
};

/* Helper function to print respons messages */
static void mctp_print_resp_msg(struct mctp_ctrl_resp *ep_discovery_resp, const char *msg, int msg_len)
{

    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");

    /* Print only if message exist */
    if (msg) {
        MCTP_CTRL_TRACE("   %s\n", msg);
        MCTP_CTRL_TRACE("-----------------------------------------------\n");
    }

    MCTP_CTRL_TRACE("MCTP-RESP-HDR >> \n");
    MCTP_CTRL_TRACE("\tmsg_type \t: 0x%x\n", ep_discovery_resp->hdr.ic_msg_type);
    MCTP_CTRL_TRACE("\trq_dgram_inst \t: 0x%x\n", ep_discovery_resp->hdr.rq_dgram_inst);
    MCTP_CTRL_TRACE("\tcommand_code \t: 0x%x\n", ep_discovery_resp->hdr.command_code);

    /* Print the compeltion code */
    if (msg_len >= 1)
        MCTP_CTRL_TRACE("\tcomp_code \t: 0x%x (%s)\n", ep_discovery_resp->completion_code,
        (ep_discovery_resp->completion_code == MCTP_CTRL_CC_SUCCESS)? "SUCCESS":"FAILURE");

    /* Decrement the length by one */
    msg_len--;

    if (ep_discovery_resp->data) {

        MCTP_CTRL_TRACE("MCTP-RESP-DATA >> \n");

        /* Check if data available or not */
        if (msg_len <= 0) {
            MCTP_CTRL_TRACE("\t--------------<empty>-------------\n");
        }

        for (int i = 0; i < msg_len; i++)
            MCTP_CTRL_TRACE("\tDATA[%d] \t\t: 0x%x\n", i, ep_discovery_resp->data[i]);
        MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    }
}


/* Tracing function to print request messages */
static void mctp_print_req_msg(struct mctp_ctrl_req *ep_discovery_req, const char *msg, size_t msg_len)
{

    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");

    /* Print only if message exist */
    if (msg) {
        MCTP_CTRL_TRACE("   %s\n", msg);
        MCTP_CTRL_TRACE("-----------------------------------------------\n");
    }

    MCTP_CTRL_TRACE("MCTP-REQ-HDR >> \n");
    MCTP_CTRL_TRACE("\tmsg_type \t: 0x%x\n", ep_discovery_req->hdr.ic_msg_type);
    MCTP_CTRL_TRACE("\trq_dgram_inst \t: 0x%x\n", ep_discovery_req->hdr.rq_dgram_inst);
    MCTP_CTRL_TRACE("\tcommand_code \t: 0x%x\n", ep_discovery_req->hdr.command_code);

    if (ep_discovery_req->data) {

        MCTP_CTRL_TRACE("MCTP-REQ-DATA >> \n");

        /* Check if data available or not */
        if (msg_len <= 0) {
            MCTP_CTRL_TRACE("\t--------------<empty>-------------\n");
        }

        for (int i = 0; i < msg_len; i++)
            MCTP_CTRL_TRACE("\tDATA[%d] \t\t: 0x%x\n", i, ep_discovery_req->data[i]);
        MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    }
}

/* Tracing function to print Routing table entry */
static void mctp_print_routing_table_entry (int routing_id, struct get_routing_table_entry *routing_table)
{
    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    MCTP_CTRL_TRACE("MCTP-ROUTING-TABLE-ENTRY [%d]\n", routing_id);

    /* Print only if message exist */
    if (routing_table) {
        MCTP_CTRL_TRACE("-----------------------------------------------\n");

        MCTP_CTRL_TRACE("\t\teid_range_size            :  0x%x\n", routing_table->eid_range_size);
        MCTP_CTRL_TRACE("\t\tstarting_eid              :  0x%x\n", routing_table->starting_eid);
        MCTP_CTRL_TRACE("\t\tentry_type                :  0x%x\n", routing_table->entry_type);
        MCTP_CTRL_TRACE("\t\tphys_transport_binding_id :  0x%x\n", routing_table->phys_transport_binding_id);
        MCTP_CTRL_TRACE("\t\tphys_media_type_id        :  0x%x\n", routing_table->phys_media_type_id);
        MCTP_CTRL_TRACE("\t\tphys_address_size         :  0x%x\n", routing_table->phys_address_size);
        MCTP_CTRL_TRACE("-----------------------------------------------\n");
    } else {
        MCTP_CTRL_TRACE("-----------------< empty/invalid >------------------\n");
    }
}

/* Tracing function to print Messgae types */
static void mctp_print_msg_types_table_entry (mctp_msg_type_table_t *msg_type_table)
{
    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    MCTP_CTRL_TRACE("MCTP-MSG-TYPE-TABLE-ENTRY\n");

    /* Print only if message exist */
    if (msg_type_table) {
        MCTP_CTRL_TRACE("-----------------------------------------------\n");

        MCTP_CTRL_TRACE("\t\tEID                       :  0x%x\n", msg_type_table->eid);
        MCTP_CTRL_TRACE("\t\tNumber of supported types :  0x%x\n", msg_type_table->data_len);
        MCTP_CTRL_TRACE("\t\tSupported Types           :  ");
        for (int i=0; i < msg_type_table->data_len; i++) {
            MCTP_CTRL_TRACE("0x%x  ", msg_type_table->data[i]);
        }
        MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    } else {
        MCTP_CTRL_TRACE("-----------------< empty/invalid >------------------\n");
    }
}

/* Tracing function to print UUID */
static void mctp_print_uuid_table_entry (mctp_uuid_table_t *uuid_tbl)
{
    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    MCTP_CTRL_TRACE("MCTP-UUID-ENTRY-FOR-EID                 :  0x%x\n", uuid_tbl->eid);

    /* Print only if message exist */
    if (uuid_tbl) {
        MCTP_CTRL_TRACE("-----------------------------------------------\n");

        MCTP_CTRL_TRACE("\t\tEID                             :  0x%x\n", uuid_tbl->eid);
        MCTP_CTRL_TRACE("\t\tUUID:(time-low)                 :  0x%x\n", uuid_tbl->uuid.canonical.data0);
        MCTP_CTRL_TRACE("\t\tUUID:(time-mid)                 :  0x%x\n", uuid_tbl->uuid.canonical.data1);
        MCTP_CTRL_TRACE("\t\tUUID:(time-high and version)    :  0x%x\n", uuid_tbl->uuid.canonical.data2);
        MCTP_CTRL_TRACE("\t\tUUID:(clk-seq and resvd)        :  0x%x\n", uuid_tbl->uuid.canonical.data3);
        MCTP_CTRL_TRACE("\t\tUUID:(node)                     :  0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",
                                                                uuid_tbl->uuid.canonical.data4[0],
                                                                uuid_tbl->uuid.canonical.data4[1],
                                                                uuid_tbl->uuid.canonical.data4[2],
                                                                uuid_tbl->uuid.canonical.data4[3],
                                                                uuid_tbl->uuid.canonical.data4[4],
                                                                uuid_tbl->uuid.canonical.data4[5]);
    MCTP_CTRL_TRACE("\n-----------------------------------------------\n");
    } else {
        MCTP_CTRL_TRACE("-----------------< empty/invalid >------------------\n");
    }
}


void mctp_routing_entry_display(void)
{
    mctp_routing_table_t *display_entry;

    /* Get the start pointer */
    display_entry = g_routing_table_entries;

    while (display_entry != NULL) {
        mctp_print_routing_table_entry(display_entry->id, &(display_entry->routing_table));
        display_entry = display_entry->next;
    }
}

/* To create a new routing entry and add to global routing table */
int mctp_routing_entry_add(struct get_routing_table_entry *routing_table_entry)
{
    mctp_routing_table_t    *new_entry, *temp_entry;
    static int routing_id = 0;

    /* Create a new Routing table entry */
    new_entry = (mctp_routing_table_t *) malloc(sizeof(mctp_routing_table_t));
    if (new_entry == NULL)
        return -1;

    /* Copy the contents */
    memcpy(&new_entry->routing_table, routing_table_entry, sizeof(struct get_routing_table_entry));

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
    while (temp_entry->next != NULL)
        temp_entry = temp_entry->next;

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
int mctp_routing_entry_delete_all(void)
{
    mctp_routing_table_t    *del_entry;

    // Check if entry exist
    while (g_routing_table_entries != NULL) {
        del_entry = g_routing_table_entries;
        g_routing_table_entries = del_entry->next;

        MCTP_CTRL_DEBUG("%s: Deleting Routing table: %d\n",
                                            __func__, del_entry->id);

        // free memory
        free(del_entry);
    }

    return 0;
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
    mctp_msg_type_table_t   *new_entry, *temp_entry;
    static int routing_id = 0;

    /* Create a new Message type entry */
    new_entry = (mctp_msg_type_table_t *) malloc(sizeof(mctp_msg_type_table_t));
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
    while (temp_entry->next != NULL)
        temp_entry = temp_entry->next;

    /* Add at the last */
    temp_entry->next = new_entry;
    new_entry->next = NULL;

    /* Increment the global counter */
    g_msg_type_table_len++;

    return 0;
}

/* To delete all the Messgae types information */
int mctp_msg_types_delete_all(void)
{
    mctp_msg_type_table_t    *del_entry;

    // Check if entry exist
    while (g_msg_type_entries != NULL) {
        del_entry = g_msg_type_entries;
        g_msg_type_entries = del_entry->next;

        MCTP_CTRL_DEBUG("%s: Deleting msg type entry: EID[%d]\n",
                                            __func__, del_entry->eid);

        // free memory
        free(del_entry);
    }

    return 0;
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
    mctp_uuid_table_t   *new_entry, *temp_entry;
    static int routing_id = 0;

    /* Create a new Message type entry */
    new_entry = (mctp_uuid_table_t *) malloc(sizeof(mctp_uuid_table_t));
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

/* To delete all the UUID information */
int mctp_uuid_delete_all(void)
{
    mctp_uuid_table_t    *del_entry;

    // Check if entry exist
    while (g_uuid_entries != NULL) {
        del_entry = g_uuid_entries;
        g_uuid_entries = del_entry->next;

        MCTP_CTRL_DEBUG("%s: Deleting UUID Entry: EID[%d]\n",
                                            __func__, del_entry->eid);
        // free memory
        free(del_entry);
    }

    return 0;
}

/* Send function for Prepare for Endpoint discovery */
mctp_ret_codes_t mctp_prepare_ep_discovery_send_request(int sock_fd)
{
    bool                                        req_ret;
    mctp_requester_rc_t                         mctp_ret;
    struct mctp_ctrl_cmd_prepare_ep_discovery   prep_ep_discovery;
    struct mctp_ctrl_req                        ep_discovery_req;
    size_t                                      msg_len;
    mctp_eid_t                                  dest_eid;
    mctp_binding_ids_t                          bind_id;
    struct mctp_astpcie_pkt_private             pvt_binding;

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
        MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Get the message length */
    msg_len = sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery) -
                        sizeof(struct mctp_ctrl_cmd_msg_hdr);

    MCTP_CTRL_DEBUG("%s: message length: %ld\n", __func__, msg_len);

    /* Initialize the buffers */
    memset(&ep_discovery_req, 0, sizeof(ep_discovery_req));

    /* Copy to Tx packet */
    memcpy(&ep_discovery_req, &prep_ep_discovery,
                sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery));

    mctp_print_req_msg(&ep_discovery_req, "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST", msg_len);

    /* Send the request message over socket */
    MCTP_CTRL_DEBUG("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_discovery_req,
                                sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Prepare for Endpoint discovery */
mctp_ret_codes_t mctp_prepare_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
    bool                                        req_ret;
    struct mctp_ctrl_resp_prepare_discovery     prep_ep_discovery_resp;

    mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
                         "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE", resp_msg_len);

    /* Copy the Rx packet header */
    memcpy(&prep_ep_discovery_resp, mctp_resp_msg,
                    sizeof(struct mctp_ctrl_resp_prepare_discovery));

    /* Parse the endpoint discovery message */
    req_ret = mctp_decode_resp_prepare_ep_discovery(&prep_ep_discovery_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Endpoint discovery */
mctp_ret_codes_t mctp_ep_discovery_send_request(int sock_fd)
{
    bool                                req_ret;
    mctp_requester_rc_t                 mctp_ret;
    struct mctp_ctrl_cmd_ep_discovery   ep_discovery;
    struct mctp_ctrl_req                ep_req;
    size_t                              msg_len;
    mctp_eid_t                          dest_eid;
    mctp_binding_ids_t                  bind_id;
    struct mctp_astpcie_pkt_private     pvt_binding;

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
        MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Get the message length */
    msg_len = sizeof(struct mctp_ctrl_cmd_ep_discovery) -
                        sizeof(struct mctp_ctrl_cmd_msg_hdr);

    MCTP_CTRL_DEBUG("%s: message length: %ld\n", __func__, msg_len);

    /* Initialize the buffers */
    memset(&ep_req, 0, sizeof(ep_req));

    /* Copy to Tx packet */
    memcpy(&ep_req, &ep_discovery,
                sizeof(struct mctp_ctrl_cmd_ep_discovery));


    /* Send the request message over socket */
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_req,
                                sizeof(struct mctp_ctrl_cmd_ep_discovery),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Prepare for Endpoint discovery */
int mctp_ep_discovery_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
    bool                                        req_ret;
    struct mctp_ctrl_resp_endpoint_discovery    ep_discovery_resp;

    mctp_print_resp_msg((struct mctp_ctrl_resp *) mctp_resp_msg,
                         "MCTP_EP_DISCOVERY_RESPONSE", resp_msg_len);

    /* Copy the Rx packet header */
    memcpy(&ep_discovery_resp, mctp_resp_msg,
                    sizeof(struct mctp_ctrl_resp_endpoint_discovery));

    /* Parse the endpoint discovery message */
    req_ret = mctp_decode_resp_ep_discovery(&ep_discovery_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Set Endpoint ID */
mctp_ret_codes_t mctp_set_eid_send_request(int sock_fd, mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
    bool                                req_ret;
    mctp_requester_rc_t                 mctp_ret;
    struct mctp_ctrl_cmd_set_eid        set_eid_req;
    struct mctp_ctrl_req                ep_req;
    size_t                              msg_len;
    mctp_eid_t                          dest_eid;
    mctp_binding_ids_t                  bind_id;
    struct mctp_astpcie_pkt_private     pvt_binding;

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
        MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Get the message length */
    msg_len = sizeof(struct mctp_ctrl_cmd_set_eid) -
                        sizeof(struct mctp_ctrl_cmd_msg_hdr);

    /* Initialize the buffers */
    memset(&ep_req, 0, sizeof(ep_req));

    /* Copy to Tx packet */
    memcpy(&ep_req, &set_eid_req,
                sizeof(struct mctp_ctrl_cmd_set_eid));

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
int mctp_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
                                                uint8_t eid, uint8_t *eid_count)
{
    bool                                req_ret;
    struct mctp_ctrl_resp_set_eid       set_eid_resp;

    mctp_print_resp_msg((struct mctp_ctrl_resp*) mctp_resp_msg,
                         "MCTP_SET_EP_RESPONSE",
                         sizeof(struct mctp_ctrl_resp_set_eid) - sizeof(struct mctp_ctrl_cmd_msg_hdr));

    /* Copy the Rx packet header */
    memcpy(&set_eid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_set_eid));

    /* Parse the endpoint discovery message */
    req_ret = mctp_decode_resp_set_eid(&set_eid_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);

        /* Free Rx packet */
        free(mctp_resp_msg);

        return MCTP_RET_ENCODE_FAILED;
    }

    /* Check whether the EID is accepted by the device or not */
    if (set_eid_resp.eid_set != eid) {
        MCTP_CTRL_DEBUG("%s: Set Endpoint id: 0x%x (Rejected by the device)\n",
                                                            __func__, set_eid_resp.eid_set);

        /* Free Rx packet */
        free(mctp_resp_msg);

        return MCTP_RET_REQUEST_FAILED;
    } else {
        MCTP_CTRL_DEBUG("%s: Set Endpoint id: 0x%x (Accepted by the device)\n",
                                                            __func__, set_eid_resp.eid_set);
    }

    /* Check whether the device requires EID pool allocation or not */
    if (set_eid_resp.status & MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ) {
        MCTP_CTRL_DEBUG("%s: Endpoint require EID pool allocation: 0x%x (status)\n",
                                                            __func__, set_eid_resp.status);

        /* Get the EID pool size from response */
        g_eid_pool_size = set_eid_resp.eid_pool_size;


        /* Also, make sure the pool size is less than global pool buffer */
        if (set_eid_resp.eid_pool_size < sizeof(MCTP_FPGA_EID_POOL)) {
            /* update the eid_count pointer */
            *eid_count = set_eid_resp.eid_pool_size;
        } else {
            MCTP_CTRL_ERR("%s: pool size req %d is greater than global pool %lu\n",
                                                    __func__, g_eid_pool_size, sizeof(MCTP_FPGA_EID_POOL));
            /* Free Rx packet */
            free(mctp_resp_msg);

            return MCTP_RET_REQUEST_FAILED;
        }

        MCTP_CTRL_DEBUG("%s: g_eid_pool_size: 0x%x\n", __func__, g_eid_pool_size);

    } else {
        MCTP_CTRL_DEBUG("%s: Endpoint doesn't require EID pool allocation: 0x%x (status)\n",
                                            __func__, set_eid_resp.status);

        /* Reset the EID pool size */
        g_eid_pool_size = 0;
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Allocate Endpoint ID */
mctp_ret_codes_t mctp_alloc_eid_send_request(int sock_fd, mctp_eid_t assigned_eid,
                        mctp_ctrl_cmd_set_eid_op op, uint8_t eid_count, uint8_t eid_start)
{
    bool                                req_ret;
    mctp_requester_rc_t                 mctp_ret;
    struct mctp_ctrl_cmd_alloc_eid      set_eid_req;
    struct mctp_ctrl_req                ep_req;
    size_t                              msg_len;
    mctp_eid_t                          dest_eid;
    mctp_binding_ids_t                  bind_id;
    struct mctp_astpcie_pkt_private     pvt_binding;

    /* Set destination EID as NULL */
    dest_eid = assigned_eid;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

    /* Allocate Endpoint ID's message */
    req_ret = mctp_encode_ctrl_cmd_alloc_eid(&set_eid_req, op, eid_count, eid_start);
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
    memcpy(&ep_req, &set_eid_req,
                sizeof(struct mctp_ctrl_cmd_alloc_eid));

    /* Force set to 0 */
    ep_req.data[0] = 0;

    mctp_print_req_msg(&ep_req, "MCTP_ALLOCATE_EP_ID_REQUEST", msg_len);

    /* Send the request message over socket */
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_req,
                                sizeof(struct mctp_ctrl_cmd_alloc_eid),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Allocate Endpoint ID */
int mctp_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
    bool                                req_ret;
    struct mctp_ctrl_resp_alloc_eid     alloc_eid_resp;

    mctp_print_resp_msg((struct mctp_ctrl_resp*) mctp_resp_msg,
                        "MCTP_ALLOCATE_EP_ID_RESPONSE",
                        (sizeof(struct mctp_ctrl_resp_alloc_eid) - sizeof(struct mctp_ctrl_cmd_msg_hdr)));

    /* Copy the Rx packet header */
    memcpy(&alloc_eid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_alloc_eid));

    /* Parse the endpoint discovery message */
    req_ret = mctp_decode_resp_alloc_eid(&alloc_eid_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Check whether allocation was accepted or not */
    if (alloc_eid_resp.alloc_status == MCTP_ALLOC_EID_REJECTED) {
        MCTP_CTRL_ERR("%s: Alloc Endpoint ID rejected/already allocated by another bus owner\n", __func__);
    }

    /* Get EID pool size and the EID start */
    g_eid_pool_size = alloc_eid_resp.eid_pool_size;
    g_eid_pool_start = alloc_eid_resp.eid_start;

    MCTP_CTRL_DEBUG("%s: g_eid_pool_size: %d, eid_start: %d\n",
                                        __func__, g_eid_pool_size, g_eid_pool_start);

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get routing table */
mctp_ret_codes_t mctp_get_routing_table_send_request(int sock_fd, mctp_eid_t eid,
                                                                uint8_t entry_handle)
{
    bool                                        req_ret;
    mctp_requester_rc_t                         mctp_ret;
    struct mctp_ctrl_cmd_get_routing_table      get_routing_req;
    struct mctp_ctrl_req                        ep_req;
    size_t                                      msg_len;
    mctp_eid_t                                  dest_eid;
    mctp_binding_ids_t                          bind_id;
    struct mctp_astpcie_pkt_private             pvt_binding;
    static int                                  entry_count = 0;

    /* Set destination EID as NULL */
    dest_eid = MCTP_EID_NULL;

    /* Set Bind ID as PCIe */
    bind_id = MCTP_BINDING_PCIE;

    /* Set private binding */
    pvt_binding.routing = PCIE_ROUTE_BY_ID;
    pvt_binding.remote_id = g_target_bdf;

    /* Get routing table request message */
    req_ret = mctp_encode_ctrl_cmd_get_routing_table(&get_routing_req, entry_handle + entry_count);
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

    mctp_print_req_msg(&ep_req, "MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST", msg_len);

    /* Send the request message over socket */
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_req,
                                sizeof(struct mctp_ctrl_cmd_get_routing_table),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get routing table */
int mctp_get_routing_table_get_response(int sock_fd, mctp_eid_t eid,
                                uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
    bool                                        req_ret;
    struct mctp_ctrl_resp_get_routing_table     routing_table;
    int                                         ret;

    MCTP_CTRL_TRACE("%s: Get EP reesponse\n", __func__);

    mctp_print_resp_msg((struct mctp_ctrl_resp*) mctp_resp_msg,
                        "MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE", resp_msg_len);

    /* Copy the Rx packet header */
    memcpy(&routing_table, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_get_routing_table));

    /* Parse the endpoint discovery message */
    req_ret = mctp_decode_resp_get_routing_table(&routing_table);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    MCTP_CTRL_DEBUG("%s: Next entry handle: %d, Number of entries: %d\n", __func__,
                        routing_table.next_entry_handle, routing_table.number_of_entries);

    /* Check if the routing table exist */
    if (routing_table.number_of_entries) {
        struct get_routing_table_entry          routing_table_entry;

        /* Copy the routing table entries to local routing table */
        memcpy(&routing_table_entry,
               mctp_resp_msg + sizeof(struct mctp_ctrl_resp_get_routing_table),
               sizeof(struct get_routing_table_entry));

        /* Add the entry to a linked list */
        ret = mctp_routing_entry_add(&routing_table_entry);
        if (ret < 0) {
            MCTP_CTRL_ERR("%s: Failed to update global routing table..\n", __func__);
            return MCTP_RET_REQUEST_FAILED;
        }

        /* Print the routing table entry */
        mctp_print_routing_table_entry (g_routing_table_entries->id,
                                        &routing_table_entry);

        /* Length of the Routing table */
        MCTP_CTRL_DEBUG("%s: Routing table lenght: %d\n",
                                __func__, g_eid_pool_size);

        /* Check if the next routing table exist.. */
        if (routing_table.next_entry_handle != 0xFF) {
            MCTP_CTRL_DEBUG("%s: Next routing entry found %d\n",
                                __func__, routing_table.next_entry_handle);
            return MCTP_RET_ROUTING_TABLE_FOUND;
        } else {
            MCTP_CTRL_DEBUG("%s: No more routing entries %d\n",
                                __func__, routing_table.next_entry_handle);
        }
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}


/* Send function for Get UUID */
mctp_ret_codes_t mctp_get_endpoint_uuid_send_request(int sock_fd, mctp_eid_t eid)
{
    bool                                req_ret;
    mctp_requester_rc_t                 mctp_ret;
    struct mctp_ctrl_cmd_get_uuid       uuid_req;
    struct mctp_ctrl_req                ep_req;
    size_t                              msg_len;
    mctp_eid_t                          dest_eid;
    mctp_binding_ids_t                  bind_id;
    struct mctp_astpcie_pkt_private     pvt_binding;

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
        MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Get the message length */
    msg_len = sizeof(struct mctp_ctrl_cmd_get_uuid) -
                        sizeof(struct mctp_ctrl_cmd_msg_hdr);

    /* Initialize the buffers */
    memset(&ep_req, 0, sizeof(ep_req));

    /* Copy to Tx packet */
    memcpy(&ep_req, &uuid_req,
                sizeof(struct mctp_ctrl_cmd_get_uuid));

    mctp_print_req_msg(&ep_req, "MCTP_GET_EP_UUID_REQUEST", msg_len);

    /* Send the request message over socket */
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_req,
                                sizeof(struct mctp_ctrl_cmd_get_uuid),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get UUID */
int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
    bool                                req_ret;
    struct mctp_ctrl_resp_get_uuid      uuid_resp;
    int                                 ret;
    mctp_uuid_table_t                   uuid_table;

    /* Trace the Rx message */
    mctp_print_resp_msg((struct mctp_ctrl_resp *) mctp_resp_msg,
                        "MCTP_GET_EP_UUID_RESPONSE", resp_msg_len);

    /* Copy the Rx packet header */
    memcpy(&uuid_resp, mctp_resp_msg, sizeof(struct mctp_ctrl_resp_get_uuid));

    /* Parse the UUID response message */
    req_ret = mctp_decode_resp_get_uuid(&uuid_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    /* Update UUID private params to export to upper layer */
    uuid_table.eid = eid;
    memcpy(&uuid_table.uuid.canonical, &uuid_resp.uuid.canonical, sizeof(guid_t));

    /* Create a new UUID entry and add to list */
    ret = mctp_uuid_entry_add(&uuid_table);
    if (ret < 0) {
        MCTP_CTRL_ERR("%s: Failed to update global UUID table..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Messgae types */
mctp_ret_codes_t mctp_get_msg_type_request(int sock_fd, mctp_eid_t eid)
{
    bool                                        req_ret;
    mctp_requester_rc_t                         mctp_ret;
    struct mctp_ctrl_cmd_get_msg_type_support   msg_type_req;
    struct mctp_ctrl_req                        ep_req;
    size_t                                      msg_len;
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
    mctp_ret = mctp_client_with_binding_send(dest_eid, sock_fd,
                                (const uint8_t *) &ep_req,
                                sizeof(struct mctp_ctrl_cmd_get_msg_type_support),
                              &bind_id, (void *) &pvt_binding,
                              sizeof(pvt_binding));

    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get Messgae types */
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
                                                        size_t resp_msg_len)
{
    bool                                            req_ret;
    struct mctp_ctrl_resp                           ep_res;
    struct mctp_ctrl_resp_get_msg_type_support      msg_type_resp;
    int                                             ret;
    mctp_msg_type_table_t                           msg_type_table;

    mctp_print_resp_msg((struct mctp_ctrl_resp*) mctp_resp_msg,
                        "MCTP_GET_MSG_TYPE_RESPONSE", resp_msg_len);

    /* Copy the Rx packet header */
    memcpy(&msg_type_resp, mctp_resp_msg,
                sizeof(struct mctp_ctrl_resp_get_msg_type_support));

    /* Copy the Rx packet header */
    memcpy(&ep_res, mctp_resp_msg, resp_msg_len);

    /* Parse the Get message type buffer */
    req_ret = mctp_decode_ctrl_cmd_get_msg_type_support(&msg_type_resp);
    if (req_ret == false) {
        MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    MCTP_CTRL_DEBUG("%s: EID: %d, Number of supported message types %d\n", __func__,
        eid, ((struct mctp_ctrl_resp*) mctp_resp_msg)->data[0]);

    /* Update Message type private params to export to upper layer */
    msg_type_table.eid = eid;
    msg_type_table.data_len = ((struct mctp_ctrl_resp*)
                                mctp_resp_msg)->data[MCTP_MSG_TYPE_DATA_LEN_OFFSET];
    memcpy(&msg_type_table.data,
            &((struct mctp_ctrl_resp*) mctp_resp_msg)->data[MCTP_MSG_TYPE_DATA_OFFSET],
            msg_type_table.data_len);

    /* Create a new Msg type entry and add to list */
    ret = mctp_msg_type_entry_add(&msg_type_table);
    if (ret < 0) {
        MCTP_CTRL_ERR("%s: Failed to update global routing table..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    /* Free Rx packet */
    free(mctp_resp_msg);

    return MCTP_RET_REQUEST_SUCCESS;
}

/* MCTP discovery response receive routine */
static mctp_ret_codes_t mctp_discover_response(mctp_discovery_mode mode,
                                                    mctp_eid_t eid, int sock,
                                                    uint8_t **mctp_resp_msg,
                                                    size_t *mctp_resp_len)
{
    mctp_ret_codes_t        mctp_ret;

    /* Ignore request commands */
    switch (mode) {
        case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:
        case MCTP_EP_DISCOVERY_REQUEST:
        case MCTP_SET_EP_REQUEST:
        case MCTP_ALLOCATE_EP_ID_REQUEST:
        case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:
        case MCTP_GET_EP_UUID_REQUEST:
        case MCTP_GET_MSG_TYPE_REQUEST:
            return MCTP_RET_REQUEST_SUCCESS;

        default:
            break;
    }

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
mctp_ret_codes_t mctp_discover_endpoints(mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
    static int                  discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST;
    struct mctp_ctrl_req        ep_discovery_req;
    struct mctp_ctrl_resp       ep_discovery_res;
    mctp_ret_codes_t            mctp_ret;
    mctp_ctrl_cmd_set_eid_op    set_eid_op;
    mctp_ctrl_cmd_alloc_eid_op  alloc_eid_op;
    uint8_t                     eid, eid_count, eid_start;
    uint8_t                     entry_hdl = MCTP_ROUTING_ENTRY_START;
    size_t                      mctp_resp_len;
    uint8_t                     *mctp_resp_msg;
    mctp_eid_t                  local_eid = 8;
    size_t                      resp_msg_len; 
    int                         uuid_req_count = 0;
    int                         msg_type_req_count = 0;
    mctp_routing_table_t        *routing_entry;

    /* Update Target BDF */
    g_target_bdf = mctp_ctrl_get_target_bdf (cmd);

    do {

        /* Wait for MCTP response */
        mctp_ret = mctp_discover_response (discovery_mode, local_eid,
                                        ctrl->sock, &mctp_resp_msg, &resp_msg_len);
        if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
            MCTP_CTRL_ERR("%s: Failed to received message %d\n", __func__, mctp_ret);
            return MCTP_RET_DISCOVERY_FAILED;
        }
       
        switch(discovery_mode) {
            case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:
    
                /* Send the prepare endpoint discovery message */
                mctp_ret = mctp_prepare_ep_discovery_send_request(ctrl->sock);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Wait for the endpoint discovery response */
                discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE;

                break;

            case MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE:

                /* Process the prepare endpoint discovery message */
                mctp_ret = mctp_prepare_ep_discovery_get_response(mctp_resp_msg, resp_msg_len);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Next step is to send endpoint Discovery request */
                discovery_mode = MCTP_EP_DISCOVERY_REQUEST;
    
            case MCTP_EP_DISCOVERY_REQUEST:

                /* Send the prepare endpoint message */
                mctp_ret = mctp_ep_discovery_send_request(ctrl->sock);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_EP_DISCOVERY_REQUEST\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_EP_DISCOVERY_RESPONSE;

                break;

            case MCTP_EP_DISCOVERY_RESPONSE:

                /* Process the endpoint discovery message */
                mctp_ret = mctp_ep_discovery_get_response(mctp_resp_msg, resp_msg_len);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n", __func__);
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
                mctp_ret = mctp_set_eid_send_request(ctrl->sock, set_eid_op, eid);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SET_EP_REQUEST\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_SET_EP_RESPONSE;

                break;

            case MCTP_SET_EP_RESPONSE:

                /* Process the MCTP_SET_EP_RESPONSE */
                mctp_ret = mctp_set_eid_get_response(mctp_resp_msg, resp_msg_len,
                                                     MCTP_FPGA_EID, &eid_count);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Next step is to Allocate endpoint IDs request */
                discovery_mode = MCTP_ALLOCATE_EP_ID_REQUEST;

                break;

            case MCTP_ALLOCATE_EP_ID_REQUEST:

                /* Update the Allocate EIDs operation, number of EIDs, Starting EID */
                alloc_eid_op = alloc_req_eid;

                /* Set the start of EID */
                eid_start = MCTP_FPGA_EID_POOL[0];

                /* Send the MCTP_ALLOCATE_EP_ID_REQUEST */
                mctp_ret = mctp_alloc_eid_send_request(ctrl->sock, eid,
                                                        alloc_eid_op, eid_count, eid_start);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_SET_EP_REQUEST\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_ALLOCATE_EP_ID_RESPONSE;

                break;

            case MCTP_ALLOCATE_EP_ID_RESPONSE:

                /* Process the MCTP_ALLOCATE_EP_ID_RESPONSE */
                mctp_ret = mctp_alloc_eid_get_response(mctp_resp_msg, resp_msg_len);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_ALLOCATE_EP_ID_RESPONSE\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Next step is to get UUID request */
                discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

                /*
                 * Sleep for a while, since the device need to allocate EIDs
                 * to downstream devices
                 */
                MCTP_CTRL_DEBUG("%s: MCTP_ALLOCATE_EP_ID_RESPONSE (sleep for a while..)\n", __func__);
                sleep(2);

                break;

            case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

                /* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
                mctp_ret = mctp_get_routing_table_send_request(ctrl->sock, eid, entry_hdl);
                if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;

                break;

            case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:

                /* Process the MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE */
                mctp_ret = mctp_get_routing_table_get_response(ctrl->sock, eid, mctp_resp_msg, resp_msg_len);
                if (MCTP_RET_DISCOVERY_FAILED == mctp_ret) {
                    MCTP_CTRL_ERR("%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n", __func__);
                    return MCTP_RET_DISCOVERY_FAILED;
                }

                /* Check if next routing entry found and set discovery mode accordingly */
                if (MCTP_RET_ROUTING_TABLE_FOUND == mctp_ret) {
    
                    MCTP_CTRL_DEBUG("%s: Next entry found..\n", __func__);
                    discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
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
                    eid_start = routing_entry->routing_table.starting_eid;

                    MCTP_CTRL_DEBUG("%s: Send UUID Request for EID: 0x%x\n",
                                            __func__, eid_start);

                    mctp_ret = mctp_get_endpoint_uuid_send_request(ctrl->sock, eid_start);
                    if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                        MCTP_CTRL_ERR("%s: Failed MCTP_GET_EP_UUID_REQUEST\n", __func__);
                        return MCTP_RET_DISCOVERY_FAILED;
                    }
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

                break;

            case MCTP_GET_EP_UUID_RESPONSE:

                if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
                    MCTP_CTRL_ERR("%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n", __func__, eid_start);
                } else {
                    /* Process the MCTP_GET_EP_UUID_RESPONSE */
                    mctp_ret = mctp_get_endpoint_uuid_response(eid_start, mctp_resp_msg, resp_msg_len);
                    if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                        MCTP_CTRL_ERR("%s: MCTP_GET_EP_UUID_RESPONSE Failed\n", __func__);
                    }
                }

                /* Increment the routing entry */
                routing_entry = routing_entry->next;

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
                    eid_start = routing_entry->routing_table.starting_eid;

                    MCTP_CTRL_DEBUG("%s: Send Get Msg type Request for EID: 0x%x\n",
                                            __func__, eid_start);

                    mctp_ret = mctp_get_msg_type_request(ctrl->sock, eid_start);
                    if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                        MCTP_CTRL_ERR("%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n", __func__);
                        return MCTP_RET_DISCOVERY_FAILED;
                    }
                }

                /* Wait for the endpoint response */
                discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

                break;

            case MCTP_GET_MSG_TYPE_RESPONSE:

                if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
                    MCTP_CTRL_ERR("%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n", __func__, eid_start);
                } else {
                    /* Process the MCTP_GET_MSG_TYPE_RESPONSE */
                    mctp_ret = mctp_get_msg_type_response(eid_start, mctp_resp_msg, resp_msg_len);
                    if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
                        MCTP_CTRL_ERR("%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n", __func__);
                    }
                }

                /* Increment the routing entry */
                routing_entry = routing_entry->next;

                /* Continue probing all Msg type requests */
                if (routing_entry) {

                    /* Next step is to Get Endpoint UUID request */
                    discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
                    break;
                }

                /* Finally update the global mctp_discovered_endpoints */
                MCTP_CTRL_DEBUG("%s: Completed discovery process..\n", __func__);
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

