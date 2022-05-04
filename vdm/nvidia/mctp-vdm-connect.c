/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <libmctp.h>
#include <libmctp-cmds.h>

#include "mctp-vdm-nvda.h"
#include "libmctp-vdm-cmds.h"

/* MCTP Tx/Rx timeouts */
#define MCTP_VDM_TXRX_TIMEOUT_SECS         5
#define MCTP_VDM_TXRX_TIMEOUT_MICRO_SECS   0

/*
 * MCTP User defined error codes starting the user defined errors from 200
 * and can be extended till 255
 * NOTE: The standard errno range from 1 to 133
 */
#define MCTP_ERR_INVALID_LEN            200

/* MCTP Response hdr */
#define MCTP_VDM_RESP_HDR_SIZE             4

/* MCTP socket name suffix byte */
#define MCTP_VDM_SOCKET_SUFFIX_BYTE        1

/**
 * @brief Open the MCTp-VDM socket interface, return success only if
 *        Socket is opened and Register with the message type.
 *
 * @param[in] *intf - Socket interface name
 * @param[in] msgtype - MCTP Message type 
 *
 * @returns socket fd on successfull, errno on failure.
 */

int mctp_vdm_socket_init(const char *intf, uint8_t msgtype)
{
    int                 fd = -1;
    int                 rc = -1;
    int                 namelen = 0;
    struct timeval      timeout = {0};
    struct sockaddr_un  addr = {0};

    /* Set timeout as 5 seconds */
    timeout.tv_sec = MCTP_VDM_TXRX_TIMEOUT_SECS;
    timeout.tv_usec = MCTP_VDM_TXRX_TIMEOUT_MICRO_SECS;

    /* Get the socket file descriptor */
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        fprintf(stderr, "%s: [err: %d] socket[%d] open failed\n",
                                                        __func__, errno, fd);
        return errno;
    }

    /* Register socket operations for send timeouts */ 
    if (setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0) {
        fprintf(stderr, "%s: [err: %d] setsockopt failed\n",
                                            __func__, errno);
        return errno;
    }

    /* Register socket operations for recv timeouts */ 
    if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0) {
        fprintf(stderr, "%s: [err: %d] setsockopt failed\n",
                                            __func__, errno);
        return errno;
    }

    /* Update socket params */
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';

    /* Update the socket name */
    sprintf(addr.sun_path+1, "%s", intf);

    /* update the socket length */
    namelen = strlen(addr.sun_path + 1) + MCTP_VDM_SOCKET_SUFFIX_BYTE;

    /* Establish the connection */
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr.sun_family) + namelen);
    if (rc < 0) {
        fprintf(stderr, "%s: [err: %d] Socket connect failed\n",
                                                    __func__, errno, fd);
        return errno;
    }

    /* Register the message type */
    rc = write(fd, &msgtype, sizeof(msgtype));
    if (rc < 0) {
        fprintf(stderr, "%s: [err: %d] Socket write failed\n",
                                                    __func__, errno, fd);
        return errno;
    }

    return fd;
}


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
int mctp_vdm_recv(mctp_eid_t eid, int mctp_fd, uint8_t msgtype,
                                uint8_t **mctp_resp_msg, size_t *resp_msg_len)
{
    ssize_t min_len = sizeof(eid) + sizeof(msgtype) + MCTP_VDM_RESP_HDR_SIZE;
    ssize_t length = 0;

    /* Receive the MCTP-VDM packet length */
    length = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

    /* Return if it's timedout or the length is invalid */
    if (errno == EAGAIN) {
        fprintf(stderr, "%s: [err: %d] Timedout [%d secs]\n",
                                            __func__, errno, MCTP_VDM_TXRX_TIMEOUT_SECS);
        return errno;
    } else if (length < min_len) {
        fprintf(stderr, "%s: [err: %d] Invalid length [%d]\n",
                                            __func__, errno, length);
        return MCTP_ERR_INVALID_LEN;
    } else {
        struct iovec        iov[MCTP_VDM_IO_VECTOR_MAX];
        size_t              mctp_prefix_len = (msgtype == 0) ? sizeof(eid) :
                                                sizeof(eid) + sizeof(msgtype);
        uint8_t             mctp_prefix[mctp_prefix_len];
        size_t              mctp_len = length - mctp_prefix_len;
        struct msghdr       msg = {0};
        ssize_t             bytes = 0;

        /* Update the prefix vectors */
        iov[MCTP_VDM_IO_VECTOR_0].iov_len = mctp_prefix_len;
        iov[MCTP_VDM_IO_VECTOR_0].iov_base = mctp_prefix;

        /* Allocate response buffer */
        *mctp_resp_msg = malloc(mctp_len);

        /* Update the response vectors */
        iov[MCTP_VDM_IO_VECTOR_1].iov_len = mctp_len;
        iov[MCTP_VDM_IO_VECTOR_1].iov_base = *mctp_resp_msg;

        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

        /* Receive the message */
        bytes = recvmsg(mctp_fd, &msg, 0);

        /* Make sure the length matches */
        if (length != bytes) {
            fprintf(stderr, "%s: [err: %d] Recvd message with invalid length: %d\n",
                                                  __func__, errno, length);

            /* Free Response buffer */
            free(*mctp_resp_msg);
            *mctp_resp_msg = NULL;
            return errno;
        }

        /* Make sure the EID and messgae type are matching as expected */
        if ((mctp_prefix[MCTP_VDM_IO_VECTOR_0] != eid) ||
                (msgtype && (mctp_prefix[MCTP_VDM_IO_VECTOR_1] != msgtype))) {
 
            fprintf(stderr, "%s: [err: %d] Invalid data: EID: 0x%x, msgtype: 0x%x\n",
                                    __func__, errno, eid, msgtype);
            /* Free Response buffer */
            free(*mctp_resp_msg);
            *mctp_resp_msg = NULL;
            return errno;
        }

        /* update the message lenght */
        *resp_msg_len = mctp_len;
    }

    return 0;
}

/**
 * @brief Send MCTP VDM messages
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] mctp_req_msg - *mctp_req_msg will point to MCTP msg,
 * @param[in] resp_msg_len - length of the message 
 *
 * @return int (errno may be set)
 */

int mctp_vdm_send(mctp_eid_t eid, int mctp_fd, uint8_t msgtype,
			      const uint8_t *mctp_req_msg, size_t req_msg_len)
{
    uint8_t         hdr[MCTP_VDM_SEND_HDR_LENGTH] = {eid, msgtype};
    struct iovec    iov[MCTP_VDM_IO_VECTOR_MAX];
    struct msghdr   msg = {0};
    ssize_t         rc = -1;

    /* Update the VDM header vectors */
    iov[MCTP_VDM_IO_VECTOR_0].iov_base = hdr;
    iov[MCTP_VDM_IO_VECTOR_0].iov_len = sizeof(hdr);

    /* Update the VDM request messgae vectors */
    iov[MCTP_VDM_IO_VECTOR_1].iov_base = (uint8_t *)mctp_req_msg;
    iov[MCTP_VDM_IO_VECTOR_1].iov_len = req_msg_len;

    /* Update the send message structure */
    msg.msg_iov = iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

    /* Send the message */
    rc = sendmsg(mctp_fd, &msg, 0);
    if (rc < 0) {
        fprintf(stderr, "%s: [err: %d] sendmsg failed\n",
                                            __func__, errno);
        return errno;
    }

    return 0;
}
