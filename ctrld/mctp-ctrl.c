/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libmctp.h"
#include "libmctp-serial.h"
#include "libmctp-astlpc.h"
#include "libmctp-astpcie.h"

#include "libmctp-cmds.h"

#include "mctp-ctrl-log.h"
#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-encode.h"
#include "mctp-sdbus.h"


#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__((unused))

/* Default socket path */
#define MCTP_SOCK_PATH "\0mctp-mux";

/* Global definitions */
uint8_t g_verbose_level = 0;

/* Set MCTP message Type */
const uint8_t MCTP_MSG_TYPE_HDR = 0;
const uint8_t MCTP_CTRL_MSG_TYPE = 0;

static int g_socket_fd = -1;


void mctp_ctrl_clean_up(void)
{
    /* Close the socket connection */
    close(g_socket_fd);

    /* Delete Routing table entries */
    mctp_routing_entry_delete_all();

    /* Delete UUID entries */
    mctp_uuid_delete_all();

    /* Delete Msg type entries */
    mctp_msg_types_delete_all();
}

/* Signal handler for MCTP client app - can be called asynchronously */
void mctp_signal_handler(int signum)
{

    mctp_ctrl_clean_up();
    exit(0);
}

void mctp_ctrl_print_buffer(const char *str, const uint8_t *buffer, int size)
{
    MCTP_CTRL_TRACE("%s: ", str);
    for (int i = 0; i < size; i++)
        MCTP_CTRL_TRACE("0x%x ", buffer[i]);
    MCTP_CTRL_TRACE("\n");
}

mctp_requester_rc_t mctp_usr_socket_init(mctp_ctrl_t *mctp_ctrl)
{
    int                     fd = -1;
    int                     rc = -1;
    const char              path[] = MCTP_SOCK_PATH;
    struct sockaddr_un      addr;
 
 
    /* Create a socket connection */
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (-1 == fd) {
        return fd;
    }
 
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, sizeof(path) - 1);
 
    /* Send a connect request to ther server */
    rc = connect(fd, (struct sockaddr *)&addr,
                 sizeof(path) + sizeof(addr.sun_family) - 1);
    if (-1 == rc) {
        return MCTP_REQUESTER_OPEN_FAIL;
    }
 
    /* Update the MCTP socket descriptor */
    mctp_ctrl->sock = fd;
 
    /* Register the type with the server */
    rc = write(fd, &MCTP_CTRL_MSG_TYPE, sizeof(MCTP_CTRL_MSG_TYPE));
    if (-1 == rc) {
        return MCTP_REQUESTER_OPEN_FAIL;
    }
 
    return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t mctp_client_send(mctp_eid_t dest_eid, int mctp_fd,
                              const uint8_t *mctp_req_msg, size_t req_msg_len)
{
    uint8_t hdr[2] = {dest_eid, MCTP_MSG_TYPE_HDR};

    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = (uint8_t *)mctp_req_msg;
    iov[1].iov_len = req_msg_len;

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

    mctp_ctrl_print_buffer("mctp_req_msg >> ", mctp_req_msg, req_msg_len);
    ssize_t rc = sendmsg(mctp_fd, &msg, 0);
    if (rc == -1) {
            return MCTP_REQUESTER_SEND_FAIL;
    }
    return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t mctp_client_with_binding_send(mctp_eid_t dest_eid, int mctp_fd,
                              const uint8_t *mctp_req_msg, size_t req_msg_len,
                              mctp_binding_ids_t *bind_id, void *mctp_binding_info,
                              size_t mctp_binding_len)
{
    uint8_t         hdr[2] = {dest_eid, MCTP_MSG_TYPE_HDR};
    struct iovec    iov[4];

    if (mctp_req_msg[0] != MCTP_MSG_TYPE_HDR) {
        MCTP_CTRL_INFO("%s: unsupported Msg type: %d\n", __func__, mctp_req_msg[0]);
        return MCTP_REQUESTER_SEND_FAIL;
    }

    /* Binding ID and information */
    iov[0].iov_base = (uint8_t *) bind_id;
    iov[0].iov_len = sizeof (uint8_t);
    iov[1].iov_base = (uint8_t *)mctp_binding_info;
    iov[1].iov_len = mctp_binding_len;

    /* MCTP header and payload */
    iov[2].iov_base = hdr;
    iov[2].iov_len = sizeof(hdr);
    iov[3].iov_base = (uint8_t *)(mctp_req_msg + 1);
    iov[3].iov_len = req_msg_len;

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

    mctp_ctrl_print_buffer("mctp_bind_id  >> ", (uint8_t *) bind_id, sizeof(uint8_t));
    mctp_ctrl_print_buffer("mctp_pvt_data >> ", mctp_binding_info, mctp_binding_len);
    mctp_ctrl_print_buffer("mctp_req_hdr  >> ", hdr, sizeof(hdr));
    mctp_ctrl_print_buffer("mctp_req_msg  >> ", mctp_req_msg, req_msg_len);

    ssize_t rc = sendmsg(mctp_fd, &msg, 0);
    if (rc == -1) {
            return MCTP_REQUESTER_SEND_FAIL;
    }

    return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t mctp_client_recv(mctp_eid_t eid, int mctp_fd,
                                     uint8_t **mctp_resp_msg,
                                     size_t *resp_msg_len)
{
    size_t min_len = sizeof(eid) + sizeof(MCTP_MSG_TYPE_HDR) +
                                        sizeof(struct mctp_ctrl_cmd_msg_hdr);

    size_t length = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

    if (length <= 0) {
            MCTP_CTRL_INFO("%s: length: %ld\n", __func__, length);
            return MCTP_REQUESTER_RECV_FAIL;
    } else if (length < min_len) {
        /* read and discard */
        uint8_t buf[length];
        recv(mctp_fd, buf, length, 0);
        mctp_ctrl_print_buffer("mctp_recv_msg_invalid_len", buf, length);
        return MCTP_REQUESTER_INVALID_RECV_LEN;
    } else {
        struct iovec iov[2];

        //size_t mctp_prefix_len = sizeof(eid) + sizeof(MCTP_MSG_TYPE_HDR);
        size_t mctp_prefix_len = sizeof(eid);

        uint8_t mctp_prefix[mctp_prefix_len];
        size_t mctp_len;

        mctp_len = length - mctp_prefix_len;

        iov[0].iov_len = mctp_prefix_len;
        iov[0].iov_base = mctp_prefix;

        *mctp_resp_msg = malloc(mctp_len);

        iov[1].iov_len = mctp_len;
        iov[1].iov_base = *mctp_resp_msg;

        struct msghdr msg = {0};
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
        ssize_t bytes = recvmsg(mctp_fd, &msg, 0);

        mctp_ctrl_print_buffer("mctp_prefix_msg", mctp_prefix, mctp_prefix_len);
        mctp_ctrl_print_buffer("mctp_resp_msg", *mctp_resp_msg, mctp_len);

        if (length != bytes) {
                MCTP_CTRL_ERR("%s: free mctp_resp_msg MCTP_REQUESTER_INVALID_RECV_LEN\n", __func__);
                free(*mctp_resp_msg);
                return MCTP_REQUESTER_INVALID_RECV_LEN;
        }

        /* Update the response length */
        *resp_msg_len = mctp_len;

        MCTP_CTRL_DEBUG("%s: resp_msg_len: %zu, mctp_len: %zu\n",
                                    __func__, *resp_msg_len, mctp_len);
        return MCTP_REQUESTER_SUCCESS;
    }

    return MCTP_REQUESTER_SUCCESS;

}

static const struct option g_options[] = {
    { "verbose",    no_argument,        0, 'v' },
    { "eid",        required_argument,  0, 'e' },
    { "mode",       required_argument,  0, 'm' },
    { "type",       required_argument,  0, 't' },
    { "tx",         required_argument,  0, 's' },
    { "rx",         required_argument,  0, 'r' },
    { "bindinfo",   required_argument,  0, 'b' },
    { "help",       no_argument,        0, 'h' },
    { 0 },
};

const char * const short_options = "v:e:m:t:s:b:r:h";

static int64_t mctp_millis()
{
    struct timespec now;
    timespec_get(&now, TIME_UTC);
    return ((int64_t) now.tv_sec) * 1000 + ((int64_t) now.tv_nsec) / 1000000;
}

int mctp_cmdline_exec (mctp_cmdline_args_t  *cmd, int sock_fd)
{
    mctp_requester_rc_t             mctp_ret;
    size_t                          resp_msg_len;
    uint8_t                         *mctp_resp_msg;
    struct mctp_astpcie_pkt_private pvt_binding;
    time_t                          now;
    int64_t                         t_start, t_end;

    assert(cmd);

    /* Start time */
    t_start = mctp_millis();

    switch (cmd->ops) {
        case MCTP_CMDLINE_OP_WRITE_DATA:
            /* Send the request message over socket */
            MCTP_CTRL_INFO("%s: Sending EP request\n", __func__);
            mctp_ret = mctp_client_send(cmd->dest_eid, sock_fd,
                        (const uint8_t *) cmd->tx_data, cmd->tx_len);
  
            if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
                MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
            }

            break;

        case MCTP_CMDLINE_OP_READ_DATA:

            /* Receive the MCTP packet */
            mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd, &mctp_resp_msg, &resp_msg_len);
            if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Failed to received message %d\n", __func__, mctp_ret);
            }

            break;

        case MCTP_CMDLINE_OP_BIND_WRITE_DATA:

            // Get binding information
            if (cmd->binding_type == MCTP_BINDING_PCIE) {
                memcpy(&pvt_binding, &cmd->bind_info, sizeof(struct mctp_astpcie_pkt_private));
            } else {
                MCTP_CTRL_ERR("%s: Invalid binding type: %d\n", __func__, cmd->binding_type);
                return MCTP_CMD_FAILED; 
            }

            /* Send the request message over socket */
            MCTP_CTRL_DEBUG("%s: Pvt bind data: Routing: 0x%x, Remote ID: 0x%x\n",
                            __func__, pvt_binding.routing, pvt_binding.remote_id);

            mctp_ret = mctp_client_with_binding_send(cmd->dest_eid, sock_fd,
                        (const uint8_t *) cmd->tx_data, cmd->tx_len, &cmd->binding_type,
                        (void *) &pvt_binding, sizeof(pvt_binding));

            if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
                MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
            }

            break;

        case MCTP_CMDLINE_OP_LIST_SUPPORTED_DEV:
            MCTP_CTRL_INFO("%s: Supported bindigs: PCIe\n", __func__);
            break;

        default:
            break;
    }

    /* Receive the MCTP packet */
    mctp_ret = mctp_client_recv(cmd->dest_eid, sock_fd, &mctp_resp_msg, &resp_msg_len);
    if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
        MCTP_CTRL_ERR("%s: Failed to received message %d\n", __func__, mctp_ret);
        return MCTP_CMD_FAILED;
    }

    /* Timestamp Day and Date */
    time(&now);

    /* End time */
    t_end = mctp_millis();

    printf("%s: Successfully received message\n", __func__);
    printf("Command Done in [%d] ms\n", (t_end - t_start));

    return MCTP_CMD_SUCCESS;
}

uint16_t mctp_ctrl_get_target_bdf (mctp_cmdline_args_t  *cmd)
{
    struct mctp_astpcie_pkt_private pvt_binding;

    // Get binding information
    if (cmd->binding_type == MCTP_BINDING_PCIE) {
        memcpy(&pvt_binding, &cmd->bind_info, sizeof(struct mctp_astpcie_pkt_private));
    } else {
        MCTP_CTRL_INFO("%s: Invalid binding type: %d\n", __func__, cmd->binding_type);
        return 0; 
    }

    /* Update the target EID */
    MCTP_CTRL_INFO("%s: Target BDF: 0x%x\n", __func__, pvt_binding.remote_id);
    return (pvt_binding.remote_id);
}


int mctp_cmdline_copy_tx_buff(uint8_t src[], uint8_t *dest, int len)
{
    int i = 0, buff_len = 0;

    while(i < len) {
        dest[buff_len++] = (unsigned char) strtol(&src[i], NULL, 16);
        i = i + MCTP_CMDLINE_WRBUFF_WIDTH;
    }

    return buff_len;
}

int mctp_event_monitor (mctp_ctrl_t *mctp_evt)
{
    mctp_requester_rc_t     mctp_ret;
    uint8_t                 *mctp_resp_msg;
    size_t                  resp_msg_len;

    MCTP_CTRL_DEBUG("%s: Target eid: %d\n", __func__, mctp_evt->eid);

    /* Receive the MCTP packet */
    mctp_ret = mctp_client_recv(mctp_evt->eid, mctp_evt->sock, &mctp_resp_msg, &resp_msg_len);
    if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
        MCTP_CTRL_ERR("%s: Failed to received message %d\n", __func__, mctp_ret);
        return MCTP_REQUESTER_RECV_FAIL;
    }

    MCTP_CTRL_DEBUG("%s: Successfully received message..\n", __func__);

    /* Free the Rx buffer */
    free(mctp_resp_msg);

    return MCTP_REQUESTER_SUCCESS;
}

static int mctp_start_daemon (mctp_ctrl_t *ctrl)
{
    int rc;

    MCTP_CTRL_DEBUG("%s: Daemon starting....\n", __func__);
    ctrl->pollfds = malloc(MCTP_CTRL_FD_NR * sizeof(struct pollfd));

    ctrl->pollfds[MCTP_CTRL_FD_SOCKET].fd = ctrl->sock;
    ctrl->pollfds[MCTP_CTRL_FD_SOCKET].events = POLLIN;

    for(;;) {

        rc = poll(ctrl->pollfds, MCTP_CTRL_FD_NR, -1);
        if (rc < 0) {
            warn("poll failed");
            break;
        }

        if (!rc)
            continue;

        if (ctrl->pollfds[MCTP_CTRL_FD_SOCKET].revents) {
            MCTP_CTRL_DEBUG("%s: Rx socket event...\n", __func__);

            /* Read the Socket */
            rc = mctp_event_monitor (ctrl);
            if (rc != MCTP_REQUESTER_SUCCESS) {
                MCTP_CTRL_ERR("%s: Invalid data..\n", __func__);
            }

        } else {
            MCTP_CTRL_INFO("%s: Rx Timeout\n", __func__);
        }
    }

    free(ctrl->pollfds);
    return rc;

}

int main (int argc, char * const *argv)
{

    int                     length;
    char                    buffer[50];
    char                    *string = "Hello from client";
    int                     fd;
    uint8_t                 requestMsg[32];
    size_t                  req_msg_len;
    uint8_t                 mctp_eid = 8;
    uint8_t                 *tx_buff, *rx_buff;
    int                     rc;
    mctp_ctrl_t             *mctp_ctrl, _mctp_ctrl;
    mctp_requester_rc_t     mctp_ret;

    mctp_cmdline_args_t     cmdline;

    /* Initialize MCTP ctrl structure */
    mctp_ctrl = &_mctp_ctrl;
    mctp_ctrl->type = MCTP_MSG_TYPE_HDR;

    /* Initialize the cmdline structure */
    memset(&cmdline, 0, sizeof(cmdline));

    /* Register signals */
    signal(SIGINT, mctp_signal_handler);

    /* Update the cmdline sturcture with default values */
    const char * const mctp_ctrl_name = argv[0];
    strncpy (cmdline.name, mctp_ctrl_name, sizeof(mctp_ctrl_name)-1);

    cmdline.device_id       = -1;
    cmdline.verbose         = false;
    cmdline.binding_type    = MCTP_BINDING_RESERVED;
    cmdline.read            = 0;
    cmdline.write           = 0;
    cmdline.use_socket      = 0;
    cmdline.list_device_op  = 0;
    cmdline.ops             = MCTP_CMDLINE_OP_NONE;
 
    memset(&cmdline.tx_data, 0, MCTP_WRITE_DATA_BUFF_SIZE);
    memset(&cmdline.rx_data, 0, MCTP_READ_DATA_BUFF_SIZE);

    for (;;) {
        rc = getopt_long(argc, argv, short_options, g_options, NULL);
        if (rc == -1)
            break;

        switch (rc) {
            case 'v':
                cmdline.verbose = true;
                MCTP_CTRL_DEBUG("%s: Verbose level:%d", __func__, cmdline.verbose);
                g_verbose_level = cmdline.verbose;
                break;
            case 'e':
                cmdline.dest_eid = (uint8_t) atoi(optarg);;
                mctp_ctrl->eid = cmdline.dest_eid;
                break;
            case 'm':
                cmdline.mode = (uint8_t) atoi(optarg);;
                MCTP_CTRL_DEBUG("%s: Mode :%s", __func__,
                                            cmdline.mode? "Daemon mode":"Command line mode");
                break;
            case 't':
                cmdline.binding_type = (uint8_t) atoi(optarg);
                break;
            case 'b':
                cmdline.bind_len = mctp_cmdline_copy_tx_buff(optarg,
                                            cmdline.bind_info, strlen(optarg));
                cmdline.ops = MCTP_CMDLINE_OP_BIND_WRITE_DATA;
                break;
            case 's':
                cmdline.tx_len = mctp_cmdline_copy_tx_buff(optarg,
                                            cmdline.tx_data, strlen(optarg));
                break;
            case 'h':
                MCTP_CTRL_INFO("Various command line options mentioned below\n"
                                "\t-v\tVerbose level\n"
                                "\t-e\tTarget Endpoint Id\n"
                                "\t-m\tMode: (0 - Commandline mode, 1 - daemon mode)\n"
                                "\t-t\tBinding Type (0 - Resvd, 2 - PCIe)\n"
                                "\t-b\tBinding data (pvt)\n"
                                "\t-s\tTx data (MCTP packet payload: [Req-dgram]-[cmd-code]--)\n"
                                "\t-h\tPrints this message\n"
                                "Eg: To send MCTP message of PCIe type:\n"
                                "\tmctp-ctrl -s \"80 0b\" -t 2 -b \"03 00 00 00 01 12\" -e 255 -m 0");
                return EXIT_SUCCESS;
            default:
                MCTP_CTRL_ERR("Invalid argument\n");
                return EXIT_FAILURE;
        }
    }

    /* Open the user socket file-descriptor */
    rc = mctp_usr_socket_init(mctp_ctrl);
    if (MCTP_REQUESTER_OPEN_FAIL == rc) {
        MCTP_CTRL_ERR("Failed to open mctp socket\n");
        return EXIT_FAILURE;
    }

    /* Update global socket pointer */
    g_socket_fd = mctp_ctrl->sock;

    /* Run this application only if set as daemon mode */
    if (!cmdline.mode) {
        mctp_cmdline_exec(&cmdline, mctp_ctrl->sock);
    } else {
        mctp_ret_codes_t mctp_err_ret;

        /* Discover endpoints */
        mctp_err_ret = mctp_discover_endpoints(&cmdline, mctp_ctrl);
        if (mctp_err_ret != MCTP_RET_DISCOVERY_SUCCESS) {
            MCTP_CTRL_ERR("MCTP-Ctrl discovery unsuccessful\n");
        }

        /* Start sdbus initialization and monitoring */
        mctp_ctrl_sdbus_init();

        /* Start MCTP control daemon */
        MCTP_CTRL_INFO("%s: Start MCTP-CTRL daemon....", __func__);
        mctp_start_daemon(mctp_ctrl);
    }

    /* Close the socket connection */
    close(mctp_ctrl->sock);

    /* Delete Routing table entries */
    mctp_routing_entry_delete_all();

    /* Delete UUID entries */
    mctp_uuid_delete_all();

    /* Delete Msg type entries */
    mctp_msg_types_delete_all();

    return EXIT_SUCCESS;
}
