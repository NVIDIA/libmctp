/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_CTRL_CMDS_H__
#define __MCTP_CTRL_CMDS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t mctp_eid_t;

/* Special Endpoint ID values */
#define MCTP_EID_NULL                                       0
#define MCTP_EID_BROADCAST                                  0xff

/* Baseline Transmission Unit and packet size */
#define MCTP_BTU                                            64

#define MCTP_PACKET_SIZE(unit)                              \
                ((unit) + sizeof(struct mctp_hdr))
#define MCTP_BODY_SIZE(unit)                                \
                ((unit) - sizeof(struct mctp_hdr))

#define MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE 0x80

/* MCTP Set Endpoint ID response fields
 * See DSP0236 v1.3.0 Table 14.
 */

#define MCTP_EID_ASSIGNMENT_STATUS_SHIFT                    0x4
#define MCTP_EID_ASSIGNMENT_STATUS_MASK                     0x3

#define SET_MCTP_EID_ASSIGNMENT_STATUS(field, status)       \
    ((field) |= (((status)&MCTP_EID_ASSIGNMENT_STATUS_MASK) \
             << MCTP_EID_ASSIGNMENT_STATUS_SHIFT))

#define MCTP_SET_EID_ACCEPTED                               0x0
#define MCTP_SET_EID_REJECTED                               0x1

/* MCTP Physical Transport Binding identifiers
 * See DSP0239 v1.7.0 Table 3.
 */
#define MCTP_BINDING_RESERVED                               0x00
#define MCTP_BINDING_SMBUS                                  0x01
#define MCTP_BINDING_PCIE                                   0x02
#define MCTP_BINDING_USB                                    0x03
#define MCTP_BINDING_KCS                                    0x04
#define MCTP_BINDING_SERIAL                                 0x05
#define MCTP_BINDING_VEDNOR                                 0x06

#define MCTP_GET_VDM_SUPPORT_PCIE_FORMAT_ID                 0x00
#define MCTP_GET_VDM_SUPPORT_IANA_FORMAT_ID                 0x01
#define MCTP_GET_VDM_SUPPORT_NO_MORE_CAP_SET                0xFF


#define MCTP_ENDPOINT_TYPE_SHIFT                            4
#define MCTP_ENDPOINT_TYPE_MASK                             0x3
#define MCTP_SIMPLE_ENDPOINT                                0
#define MCTP_BUS_OWNER_BRIDGE                               1

#define SET_ENDPOINT_TYPE(field, type)                      \
    ((field) |=                                             \
     (((type)&MCTP_ENDPOINT_TYPE_MASK) << MCTP_ENDPOINT_TYPE_SHIFT))

#define MCTP_ENDPOINT_ID_TYPE_SHIFT                         0
#define MCTP_ENDPOINT_ID_TYPE_MASK                          0x3
#define MCTP_DYNAMIC_EID                                    0
#define MCTP_STATIC_EID                                     1

#define SET_ENDPOINT_ID_TYPE(field, type)                   \
    ((field) |=                                             \
     (((type)&MCTP_ENDPOINT_ID_TYPE_MASK) << MCTP_ENDPOINT_ID_TYPE_SHIFT))

/* MCTP Routing Table entry types
 * See DSP0236 v1.3.0 Table 27.
 */
#define MCTP_ROUTING_ENTRY_PORT_SHIFT                       0
#define MCTP_ROUTING_ENTRY_PORT_MASK                        0x1F

#define SET_ROUTING_ENTRY_PORT(field, port)                 \
    ((field) |= (((port)&MCTP_ROUTING_ENTRY_PORT_MASK)      \
             << MCTP_ROUTING_ENTRY_PORT_SHIFT))

#define GET_ROUTING_ENTRY_PORT(field)                       \
    (((field) >> MCTP_ROUTING_ENTRY_PORT_SHIFT) &           \
     MCTP_ROUTING_ENTRY_PORT_MASK)

#define MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT            5
#define MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK             0x1
#define MCTP_DYNAMIC_ASSIGNMENT                             0
#define MCTP_STATIC_ASSIGNMENT                              1

#define SET_ROUTING_ENTRY_ASSIGNMENT_TYPE(field, type)                     \
    ((field) |= (((type)&MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK)          \
             << MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT))

#define GET_ROUTING_ENTRY_ASSIGNMENT_TYPE(field)                           \
    (((field) >> MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT) &               \
     MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK)

#define MCTP_ROUTING_ENTRY_TYPE_SHIFT                       6
#define MCTP_ROUTING_ENTRY_TYPE_MASK                        0x3
#define MCTP_ROUTING_ENTRY_ENDPOINT                         0x00
#define MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS             0x01
#define MCTP_ROUTING_ENTRY_BRIDGE                           0x02
#define MCTP_ROUTING_ENTRY_ENDPOINTS                        0x03

#define SET_ROUTING_ENTRY_TYPE(field, type)                 \
    ((field) |= (((type)&MCTP_ROUTING_ENTRY_TYPE_MASK)      \
             << MCTP_ROUTING_ENTRY_TYPE_SHIFT))

#define GET_ROUTING_ENTRY_TYPE(field)                       \
    (((field) >> MCTP_ROUTING_ENTRY_TYPE_SHIFT) &           \
     MCTP_ROUTING_ENTRY_TYPE_MASK)

#define MCTP_GET_VERSION_SUPPORT_BASE_INFO                  0xFF

/* For Set Endpoint ID response param validation (as per DSP0236 Version 1.3.1) */
#define MCTP_SETEID_ALLOC_STATUS_EID_POOL_NOT_REQ           0
#define MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ               1
#define MCTP_SETEID_ALLOC_STATUS_EID_POOL_ASSIGNED          2
#define MCTP_SETEID_ALLOC_STATUS_EID_POOL_RESVD             3

#define MCTP_SETEID_ASSIGN_STATUS_ACCEPTED                  0
#define MCTP_SETEID_ASSIGN_STATUS_REJECTED                  (1<<4)
#define MCTP_SETEID_ASSIGN_STATUS_RESVD                     (2<<4)
#define MCTP_SETEID_ASSIGN_STATUS_RESVD1                    (3<<4)

/* For Allocate Endpoint IDs response param validation (as per DSP0236 Version 1.3.1) */
#define MCTP_ALLOC_EID_ACCEPTED                             0
#define MCTP_ALLOC_EID_REJECTED                             1


/* MCTP core */
struct mctp;
struct mctp_bus;

struct mctp_ctrl_cmd_msg_hdr {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
} __attribute__((__packed__));

typedef enum {
    set_eid,
    force_eid,
    reset_eid,
    set_discovered_flag
} mctp_ctrl_cmd_set_eid_op;

typedef enum {
    alloc_req_eid,
    alloc_req_force_eid,
    alloc_req_get_info,
    alloc_req_resvd
} mctp_ctrl_cmd_alloc_eid_op;

typedef enum {
    alloc_resp_accepted,
    alloc_resp_rejected,
    alloc_resp_resvd,
} mctp_ctrl_resp_alloc_eid_op;

struct mctp_ctrl_cmd_prepare_ep_discovery {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_ep_discovery {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_set_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
    mctp_ctrl_cmd_set_eid_op operation : 2;
    uint8_t : 6;
    uint8_t eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_alloc_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
    mctp_ctrl_cmd_alloc_eid_op operation : 2;
    uint8_t : 6;
    uint8_t eid_pool_size;
    uint8_t eid_start;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_uuid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_mctp_ver_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
    uint8_t msg_type_number;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_msg_type_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_vdm_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
    uint8_t vendor_id_set_selector;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_discovery_notify {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_routing_table {
    struct mctp_ctrl_cmd_msg_hdr ctrl_msg_hdr;
    uint8_t entry_handle;
} __attribute__((__packed__));

typedef union {
    struct {
        uint32_t data0;
        uint16_t data1;
        uint16_t data2;
        uint16_t data3;
        uint8_t data4[6];
    } __attribute__((__packed__)) canonical;
    uint8_t raw[16];
} guid_t;

struct mctp_ctrl_resp_get_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    mctp_eid_t eid;
    uint8_t eid_type;
    uint8_t medium_data;

} __attribute__((__packed__));

struct mctp_ctrl_resp_get_uuid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    guid_t uuid;
} __attribute__((__packed__));

struct mctp_ctrl_resp_set_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t status;
    mctp_eid_t eid_set;
    uint8_t eid_pool_size;
} __attribute__((__packed__));

struct mctp_ctrl_resp_alloc_eid {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    mctp_ctrl_resp_alloc_eid_op alloc_status: 2;
    uint8_t : 6;
    uint8_t eid_pool_size;
    uint8_t eid_start;
} __attribute__((__packed__));

struct mctp_ctrl_resp_discovery_notify {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_resp_prepare_discovery {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_resp_endpoint_discovery {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_routing_table {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t next_entry_handle;
    uint8_t number_of_entries;
} __attribute__((__packed__));

struct get_routing_table_entry {
    uint8_t eid_range_size;
    uint8_t starting_eid;
    uint8_t entry_type;
    uint8_t phys_transport_binding_id;
    uint8_t phys_media_type_id;
    uint8_t phys_address_size;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_vdm_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t vendor_id_set_selector;
    uint8_t vendor_id_format;
    union {
        uint16_t vendor_id_data_pcie;
        uint32_t vendor_id_data_iana;
    };
    /* following bytes are dependent on vendor id format
     * and shall be interpreted by appropriate binding handler */
} __attribute__((__packed__));

struct mctp_pci_ctrl_resp_get_vdm_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t vendor_id_set_selector;
    uint8_t vendor_id_format;
    uint16_t vendor_id_data;
    uint16_t command_set_type;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_msg_type_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t msg_type_count;
} __attribute__((__packed__));

struct msg_type_entry {
    uint8_t msg_type_no;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_mctp_ver_support {
    struct mctp_ctrl_cmd_msg_hdr ctrl_hdr;
    uint8_t completion_code;
    uint8_t number_of_entries;
} __attribute__((__packed__));

struct version_entry {
    uint8_t major;
    uint8_t minor;
    uint8_t update;
    uint8_t alpha;
} __attribute__((__packed__));


/* Function prototypes */
bool mctp_ctrl_handle_msg(struct mctp *mctp, struct mctp_bus *bus,
              mctp_eid_t src, mctp_eid_t dest, void *buffer,
              size_t length, bool tag_owner, uint8_t tag,
              void *msg_binding_private);

bool mctp_encode_ctrl_cmd_set_eid(struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
                  mctp_ctrl_cmd_set_eid_op op, uint8_t eid);

bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd);

bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd);

bool mctp_encode_ctrl_cmd_get_ver_support(
    struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
    uint8_t msg_type_number);

bool mctp_encode_ctrl_cmd_get_msg_type_support(
    struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd);

bool mctp_encode_ctrl_cmd_get_vdm_support(
    struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd, uint8_t v_id_set_selector);

bool mctp_encode_ctrl_cmd_discovery_notify(
    struct mctp_ctrl_cmd_discovery_notify *discovery_notify_cmd);

bool mctp_encode_ctrl_cmd_get_routing_table(
    struct mctp_ctrl_cmd_get_routing_table *get_routing_table_cmd,
    uint8_t entry_handle);

void mctp_set_uuid(struct mctp *mctp, guid_t uuid);

bool mctp_is_mctp_ctrl_msg(void *buf, size_t len);

bool mctp_ctrl_msg_is_req(void *buf, size_t len);

int mctp_ctrl_cmd_set_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
                  struct mctp_ctrl_cmd_set_eid *request,
                  struct mctp_ctrl_resp_set_eid *response);

int mctp_ctrl_cmd_get_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
                  bool bus_owner,
                  struct mctp_ctrl_resp_get_eid *response);

int mctp_ctrl_cmd_get_vdm_support(
    struct mctp *mctp, mctp_eid_t src_eid,
    struct mctp_ctrl_resp_get_vdm_support *response);


#ifdef __cplusplus
}
#endif

#endif /* __MCTP_CTRL_CMDS_H__ */
