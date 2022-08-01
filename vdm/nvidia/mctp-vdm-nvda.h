#ifndef __VDM_NVDA_H__
#define __VDM_NVDA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>


/* Default interface */
#define MCTP_DEFAULUT_INTF              "mctp-mux"

/* VDM command name size from commandline option */
#define MCTP_VDM_COMMAND_NAME_SIZE      128

/* Download log buffer length */
#define MCTP_VDM_DOWNLOAD_LOG_BUFFER_SIZE 52

/* Download log buffer length */
#define MCTP_VDM_VENDOR_IANA_SIZE       4

/* MCTP VDM command operation */
#define MCTP_VDM_CMD_OP_SUCCESS        0xff

/* Boot complete command slot numbers */
#define MCTP_VDM_BOOT_COMPLETE_SLOT0    0
#define MCTP_VDM_BOOT_COMPLETE_SLOT1    1

/* Boot complete command for valid field */
#define MCTP_VDM_BOOT_COMPLETE_VALID    1

/* Heartbeat command enable/disable macros */
#define MCTP_VDM_HEARTBEAT_ENABLE       1
#define MCTP_VDM_HEARTBEAT_DISABLE      0

/* Background copy operation macros */
#define MCTP_VDM_BACKGROUND_COPY_DISABLE                    0x00
#define MCTP_VDM_BACKGROUND_COPY_ENABLE                     0x01
#define MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT           0x02
#define MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT            0x03
#define MCTP_VDM_BACKGROUND_COPY_INIT                       0x04
#define MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS               0x05
#define MCTP_VDM_BACKGROUND_COPY_PROGRESS                   0x06

/* Download log session ID for first request */
#define MCTP_VDM_DOWNLOAD_LOG_SESSION_ID_START              0xff

/* MCTP-VDM Header size */
#define MCTP_VDM_SEND_HDR_LENGTH        2

/* MCTP Tx/Rx waittime in milli-seconds */
#define MCTP_VDM_CMD_WAIT_SECONDS               (1 * 1000)
#define MCTP_VDM_CMD_WAIT_TIME                  (5 * MCTP_VDM_CMD_WAIT_SECONDS)
#define MCTP_VDM_CMD_THRESHOLD                  2

/* MCTP-VDM IO vectors */
typedef enum {
    MCTP_VDM_IO_VECTOR_0,
    MCTP_VDM_IO_VECTOR_1,
    MCTP_VDM_IO_VECTOR_MAX
} mctp_vdm_io_vectors_t;

typedef uint8_t mctp_eid_t;

/* MCTP-VDM Download log response structure */
typedef struct {
    uint8_t iana[MCTP_VDM_VENDOR_IANA_SIZE];
    uint8_t rq_dgram_inst;
    uint8_t msg_type;
    uint8_t cmd;
    uint8_t version;
    uint8_t cc;
    uint8_t session;
    uint8_t length;
    uint8_t data[MCTP_VDM_DOWNLOAD_LOG_BUFFER_SIZE];
} mctp_vdm_log_rep_hdr_t;


/**
 * @brief Open the MCTp-VDM socket interface, return success only if
 *        Socket is opened and Register with the message type.
 *
 * @param[in] *intf - Socket interface name
 * @param[in] msgtype - MCTP Message type
 *
 * @returns socket fd on successfull, errno on failure.
 */
int mctp_vdm_socket_init(const char *intf, uint8_t msgtype);

/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a MCTP message.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[out] mctp_resp_msg - *mctp_resp_msg will point to MCTP msg,
 *             this function allocates memory, caller to free(*mctp_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the MCTP msg.
 *
 * @return int (errno may be set). failure is returned even
 *         when data was read, but wasn't a MCTP response message
 */

int  mctp_vdm_recv(mctp_eid_t eid, int mctp_fd, uint8_t msgtype,
                              uint8_t **mctp_resp_msg,
                              size_t *resp_msg_len);

#ifdef __cplusplus
}
#endif

#endif /* __VDM_NVDA_H__ */
