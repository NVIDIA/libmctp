/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _MCTP_ENCODE_H
#define _MCTP_ENCODE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "mctp-ctrl-cmds.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */

/* Prepare endpoint discovery request */
bool mctp_encode_ctrl_cmd_prepare_ep_discovery(
        struct mctp_ctrl_cmd_prepare_ep_discovery *prep_ep_discovery);

/* Prepare endpoint discovery response */
bool mctp_decode_resp_prepare_ep_discovery(
        struct mctp_ctrl_resp_prepare_discovery *prep_ep_discovery);

/* Endpoint discovery request */
bool mctp_encode_ctrl_cmd_ep_discovery(
        struct mctp_ctrl_cmd_ep_discovery *ep_discovery);

/* Endpoint discovery response */
bool mctp_decode_resp_ep_discovery(
        struct mctp_ctrl_resp_endpoint_discovery *ep_discovery);

/* Set Endpoint ID request */
bool mctp_encode_ctrl_cmd_set_eid(
        struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
        mctp_ctrl_cmd_set_eid_op op, uint8_t eid);

/* Set Endpoint ID response */
bool mctp_decode_resp_set_eid(
        struct mctp_ctrl_resp_set_eid *set_eid);


/* Allocate Endpoint ID request */
bool mctp_encode_ctrl_cmd_alloc_eid(
        struct mctp_ctrl_cmd_alloc_eid *alloc_eid_cmd,
        mctp_ctrl_cmd_alloc_eid_op op,
        uint8_t pool_size,
        uint8_t start);

/* Allocate Endpoint ID response */
bool mctp_decode_resp_alloc_eid(struct mctp_ctrl_resp_alloc_eid *alloc_eid);

/* Get Routing table request */
bool mctp_encode_ctrl_cmd_get_routing_table(
    struct mctp_ctrl_cmd_get_routing_table *get_routing_table_cmd,
    uint8_t entry_handle);

/* Get Routing table response */
bool mctp_decode_resp_get_routing_table(struct mctp_ctrl_resp_get_routing_table *routing_table);

/* Get Enodpoint ID request */
bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd);


/* Get UUID request */
bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd);

/* Get UUID response */
bool mctp_decode_resp_get_uuid(struct mctp_ctrl_resp_get_uuid *get_uuid_resp);

/* Get MCTP version request */
bool mctp_encode_ctrl_cmd_get_ver_support(
    struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
    uint8_t msg_type_number);

/* Get Message type request */
bool mctp_encode_ctrl_cmd_get_msg_type_support(
    struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd);

bool mctp_decode_ctrl_cmd_get_msg_type_support(
    struct mctp_ctrl_resp_get_msg_type_support *msg_type_support_cmd);

/* Get VDM support request */
bool mctp_encode_ctrl_cmd_get_vdm_support(
    struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd,
    uint8_t v_id_set_selector);

/* Get Discovery notify request */
bool mctp_encode_ctrl_cmd_discovery_notify(
    struct mctp_ctrl_cmd_discovery_notify *discovery_notify_cmd);

#ifdef __cplusplus
}
#endif

#endif /* _MCTP_ENCODE_H */
