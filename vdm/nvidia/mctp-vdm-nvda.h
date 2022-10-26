#ifndef __VDM_NVDA_H__
#define __VDM_NVDA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Default interface */
#define MCTP_DEFAULUT_INTF "mctp-mux"

/* VDM command name size from commandline option */
#define MCTP_VDM_COMMAND_NAME_SIZE 128

/* MCTP VDM message size */
#define MCTP_VDM_MESSAGE_SIZE MCTP_CERTIFICATE_CHAIN_SIZE

/* MCTP VDM command operation */
#define MCTP_VDM_CMD_OP_SUCCESS 0xff

/* Boot complete command slot numbers */
#define MCTP_VDM_BOOT_COMPLETE_SLOT0 0
#define MCTP_VDM_BOOT_COMPLETE_SLOT1 1

/* Boot complete command for valid field */
#define MCTP_VDM_BOOT_COMPLETE_VALID 1

/* Heartbeat command enable/disable macros */
#define MCTP_VDM_HEARTBEAT_ENABLE 1
#define MCTP_VDM_HEARTBEAT_DISABLE 0

/* In-Band command enable/disable macros */
#define MCTP_VDM_IN_BAND_DISABLE        0
#define MCTP_VDM_IN_BAND_ENABLE         1
#define MCTP_VDM_IN_BAND_QUERY_STATUS   2

/* Background copy operation macros */
#define MCTP_VDM_BACKGROUND_COPY_DISABLE 0x00
#define MCTP_VDM_BACKGROUND_COPY_ENABLE 0x01
#define MCTP_VDM_BACKGROUND_COPY_DISABLE_ONE_BOOT 0x02
#define MCTP_VDM_BACKGROUND_COPY_ENABLE_ONE_BOOT 0x03
#define MCTP_VDM_BACKGROUND_COPY_INIT 0x04
#define MCTP_VDM_BACKGROUND_COPY_QUERY_STATUS 0x05
#define MCTP_VDM_BACKGROUND_COPY_PROGRESS 0x06
#define MCTP_VDM_BACKGROUND_COPY_PENDING 0x07

/* Download log session ID for first request */
#define MCTP_VDM_DOWNLOAD_LOG_SESSION_ID_START 0xff

/* MCTP-VDM Header size */
#define MCTP_VDM_SEND_HDR_LENGTH 2

/* MCTP Tx/Rx waittime in milli-seconds */
#define MCTP_VDM_CMD_WAIT_SECONDS (1 * 1000)
#define MCTP_VDM_CMD_WAIT_TIME (5 * MCTP_VDM_CMD_WAIT_SECONDS)
#define MCTP_VDM_CMD_THRESHOLD 2

/* MCTP-VDM IO vectors */
typedef enum {
	MCTP_VDM_IO_VECTOR_0,
	MCTP_VDM_IO_VECTOR_1,
	MCTP_VDM_IO_VECTOR_MAX
} mctp_vdm_io_vectors_t;

typedef uint8_t mctp_eid_t;

#ifdef __cplusplus
}
#endif

#endif /* __VDM_NVDA_H__ */
